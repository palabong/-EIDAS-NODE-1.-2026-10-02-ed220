/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import fs from 'fs/promises';
import { webcrypto } from 'crypto';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';

dotenv.config();

import { verifyProof } from '../lib/crypto/zkp/nizkp.ts';
import { 
  recordAccessLog, 
  getAccessLogs, 
  getAccessStats, 
  clearAccessLogs, 
  exportAccessLogsCsv 
} from './accessLogDb.ts';
import { 
  globalSessionStore, 
  extractSessionToken, 
  setSessionCookie,
  clearSessionCookie 
} from './sessionManager.ts';
import { 
  generateSPMetadata, 
  generateAuthnRequest, 
  validateSAMLResponse,
  getPresetFixtureXml
} from './samlBridge.ts';
import { 
  generateWebAuthnChallenge, 
  registerWebAuthnCredential, 
  verifyWebAuthnAssertion, 
  getStoredCredential 
} from './webauthnServer.ts';
import type { SessionUser } from './types/saml.ts';

// Helper to safely extract client IP without unsafe array cast errors
export function getClientIp(req: express.Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (Array.isArray(xff) && xff.length > 0) {
    return xff[0].split(',')[0].trim();
  }
  if (typeof xff === 'string') {
    return xff.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

export function getErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Extend Express Request typing
declare global {
  namespace Express {
    interface Request {
      user?: SessionUser;
      sessionToken?: string;
    }
  }
}

// Google OAuth2 Client
export const googleOAuthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export function validateStartupEnvironment(): void {
  const isProd = process.env.NODE_ENV === 'production';

  console.log(`[Config] Initializing server in ${isProd ? 'PRODUCTION' : 'DEVELOPMENT'} mode.`);

  // Check Google OAuth Client ID
  if (!process.env.GOOGLE_CLIENT_ID) {
    if (isProd) {
      console.warn('[Config] WARNING: GOOGLE_CLIENT_ID is not configured. Google Sign-In will be disabled.');
    } else {
      console.log('[Config] Notice: GOOGLE_CLIENT_ID is unset. /api/auth/verify-google will reject requests until configured.');
    }
  }

  // Check Gemini API Key
  if (!process.env.GEMINI_API_KEY || process.env.GEMINI_API_KEY === 'your_gemini_api_key_here' || process.env.GEMINI_API_KEY === 'MY_GEMINI_API_KEY') {
    console.log('[Config] Notice: GEMINI_API_KEY is unset or using a placeholder. AI features will remain dormant.');
  }

  // Check Institutional Key
  const hasEnvKey = !!process.env.INSTITUTIONAL_KEY_JSON;
  const hasKeyPath = !!process.env.INSTITUTIONAL_KEY_PATH;
  if (!hasEnvKey && !hasKeyPath) {
    if (isProd) {
      console.error('[Config] CRITICAL: Neither INSTITUTIONAL_KEY_JSON nor INSTITUTIONAL_KEY_PATH is set in production!');
    } else {
      console.log('[Config] Notice: Institutional key will be loaded from local file or generated ephemerally.');
    }
  }
}

// =========================================================================
// 🔐 ORIGIN & SECURITY HARDENING CONFIGURATION (REM-03 / Task 1)
// =========================================================================

export const TRUSTED_ORIGINS = new Set([
  process.env.APP_ORIGIN,
  'http://localhost:3000',
  'http://localhost:5173',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173'
].filter(Boolean) as string[]);

export function isOriginAllowedCors(origin: string, reqHost?: string): boolean {
  if (TRUSTED_ORIGINS.has(origin)) return true;
  try {
    const url = new URL(origin);
    // Allow localhost / 127.0.0.1 on any port during local development or automated test runs
    if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') return true;
    if (reqHost && url.host === reqHost) return true;
  } catch {}
  return false;
}

export function getValidatedWebAuthnOrigin(req: express.Request): string | null {
  const host = req.get('host');
  const protocol = req.protocol || 'http';
  const defaultLocalOrigin = `${protocol}://${host}`;

  const originHeader = req.headers.origin;
  if (originHeader) {
    if (TRUSTED_ORIGINS.has(originHeader)) {
      return originHeader;
    }
    try {
      const parsed = new URL(originHeader);
      // In development / tests, accept localhost or 127.0.0.1 ephemeral ports
      if (process.env.NODE_ENV !== 'production' && (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')) {
        return originHeader;
      }
      if (host && parsed.host === host) {
        return originHeader;
      }
    } catch {}
    // Fail-closed against untrusted origins (e.g. phishing / malicious domains)
    return null;
  }

  // If no Origin header, evaluate Host origin
  if (TRUSTED_ORIGINS.has(defaultLocalOrigin)) {
    return defaultLocalOrigin;
  }
  try {
    const parsed = new URL(defaultLocalOrigin);
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
      return defaultLocalOrigin;
    }
  } catch {}

  return process.env.APP_ORIGIN || null;
}

// =========================================================================
// 🔐 INSTITUTIONAL KEY MANAGEMENT (REM-01)
// =========================================================================
let backendInstitutionalKeyPair: webcrypto.CryptoKeyPair | null = null;

export interface ActiveChallengeRecord {
  issuedAt: number;
  consumed: boolean;
  signatureBase64: string;
  institutionId: string;
}
export const activeChallenges = new Map<string, ActiveChallengeRecord>();
export const CHALLENGE_TTL_MS = 60_000; // 60 seconds validity window
export const MAX_ACTIVE_INSTITUTIONAL_CHALLENGES = 5_000;

export function purgeExpiredInstitutionalChallenges(): void {
  const now = Date.now();
  for (const [key, record] of activeChallenges.entries()) {
    if (now - record.issuedAt > CHALLENGE_TTL_MS) {
      activeChallenges.delete(key);
    }
  }
  if (activeChallenges.size > MAX_ACTIVE_INSTITUTIONAL_CHALLENGES) {
    const toDelete = activeChallenges.size - MAX_ACTIVE_INSTITUTIONAL_CHALLENGES;
    let deleted = 0;
    for (const key of activeChallenges.keys()) {
      activeChallenges.delete(key);
      deleted++;
      if (deleted >= toDelete) break;
    }
  }
}

export async function getInstitutionalKeyPair(): Promise<webcrypto.CryptoKeyPair> {
  if (backendInstitutionalKeyPair) {
    return backendInstitutionalKeyPair;
  }

  const algo = { name: 'ECDSA', namedCurve: 'P-256' };

  // Tier 1: Load directly from environment variable (Cloud Run / K8s Secret injection)
  const envKeyJson = process.env.INSTITUTIONAL_KEY_JSON;
  if (envKeyJson && envKeyJson.trim()) {
    try {
      const { publicKeyJwk, privateKeyJwk } = JSON.parse(envKeyJson);
      if (!publicKeyJwk || !privateKeyJwk) {
        throw new Error("Missing 'publicKeyJwk' or 'privateKeyJwk' in INSTITUTIONAL_KEY_JSON.");
      }
      const publicKey = await webcrypto.subtle.importKey('jwk', publicKeyJwk, algo, true, ['verify']);
      const privateKey = await webcrypto.subtle.importKey('jwk', privateKeyJwk, algo, true, ['sign']);
      backendInstitutionalKeyPair = { publicKey, privateKey };
      console.log('[InstitutionalKey] Successfully imported institutional key pair from INSTITUTIONAL_KEY_JSON environment variable.');
      return backendInstitutionalKeyPair;
    } catch (err: unknown) {
      console.error('[InstitutionalKey] Failed to import key pair from INSTITUTIONAL_KEY_JSON:', getErrorMessage(err));
      if (process.env.NODE_ENV === 'production') {
        throw new Error(`[FATAL] Invalid INSTITUTIONAL_KEY_JSON secret: ${getErrorMessage(err)}`);
      }
    }
  }

  // Tier 2 & 3: Load from configured file path or default local file
  const keyFilePath = process.env.INSTITUTIONAL_KEY_PATH || path.join(process.cwd(), 'institutional-key.json');
  try {
    const fileData = await fs.readFile(keyFilePath, 'utf-8');
    const { publicKeyJwk, privateKeyJwk } = JSON.parse(fileData);
    if (!publicKeyJwk || !privateKeyJwk) {
      throw new Error("Missing 'publicKeyJwk' or 'privateKeyJwk' in key file.");
    }
    const publicKey = await webcrypto.subtle.importKey('jwk', publicKeyJwk, algo, true, ['verify']);
    const privateKey = await webcrypto.subtle.importKey('jwk', privateKeyJwk, algo, true, ['sign']);
    backendInstitutionalKeyPair = { publicKey, privateKey };
    console.log(`[InstitutionalKey] Loaded persistent institutional key pair from disk (${keyFilePath}).`);
    return backendInstitutionalKeyPair;
  } catch (err: unknown) {
    const isEnoent = err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT';
    if (!isEnoent) {
      console.warn(`[InstitutionalKey] Warning reading key file at ${keyFilePath}:`, getErrorMessage(err));
    }
  }

  // Tier 4: Production Fail-Closed Check
  if (process.env.NODE_ENV === 'production') {
    throw new Error(
      '[FATAL] Production configuration error: Institutional key pair not found. ' +
      'Set INSTITUTIONAL_KEY_JSON or INSTITUTIONAL_KEY_PATH in environment variables.'
    );
  }

  // Development / Sandbox Fallback: Ephemeral In-Memory Key Pair
  console.warn('[InstitutionalKey] NOTICE: Generating ephemeral in-memory ECDSA P-256 key pair for development/sandbox. Challenges will not persist across restarts.');
  backendInstitutionalKeyPair = await webcrypto.subtle.generateKey(algo, true, ['sign', 'verify']);

  // Optional dev persistence only when explicitly requested
  if (process.env.PERSIST_DEV_KEYS === 'true') {
    try {
      const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', backendInstitutionalKeyPair.publicKey);
      const privateKeyJwk = await webcrypto.subtle.exportKey('jwk', backendInstitutionalKeyPair.privateKey);
      await fs.writeFile(keyFilePath, JSON.stringify({ publicKeyJwk, privateKeyJwk }, null, 2), { mode: 0o600 });
      console.log(`[InstitutionalKey] Persisted development key pair to ${keyFilePath}.`);
    } catch (writeErr: unknown) {
      console.warn('[InstitutionalKey] Could not persist development key pair to disk (ignoring in dev):', getErrorMessage(writeErr));
    }
  }

  return backendInstitutionalKeyPair;
}

/**
 * Creates and configures the core Express application with security headers,
 * CORS policy, body parsers, and all authenticated API routes.
 */
export function createApp(options?: { isTest?: boolean }): express.Express {
  const app = express();

  // 1. Security Headers (CSP, X-Content-Type-Options, X-Frame-Options, X-XSS-Protection)
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-XSS-Protection', '0');
    res.setHeader(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://accounts.google.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https: blob:; connect-src 'self' ws: wss: https://accounts.google.com; frame-src 'self' https://accounts.google.com; object-src 'none'; base-uri 'self';"
    );
    next();
  });

  // 2. CORS Policy
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin && isOriginAllowedCors(origin, req.get('host'))) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    if (req.method === 'OPTIONS') {
      res.sendStatus(204);
      return;
    }
    next();
  });

  // 3. Mount body parsers
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));
  app.use(express.json());
  app.use(express.raw({ type: 'application/octet-stream', limit: '1mb' }));

  // API Route 1: Healthcheck
  app.get("/api/health", (req, res) => {
    res.json({ status: "healthy", timestamp: new Date().toISOString() });
  });

  // =========================================================================
  // 🔐 SESSION AUTHENTICATION & ACCESS LOG DATABASE API
  // =========================================================================

  const requireAuth = (req: express.Request, res: express.Response, next: express.NextFunction) => {
    const token = extractSessionToken(req);
    if (!token) {
      res.status(401).json({ error: "Unauthorized access. Valid session required." });
      return;
    }
    const session = globalSessionStore.getSession(token);
    if (!session) {
      res.status(401).json({ error: "Unauthorized access. Valid session required." });
      return;
    }
    req.user = session;
    req.sessionToken = token;
    next();
  };

  // Verify Google Identity Services ID Token / Credential (REM-02 Hardened)
  app.post("/api/auth/verify-google", async (req, res) => {
    try {
      const { credential, clientInfo } = req.body;
      const clientIp = getClientIp(req);
      const userAgent = req.headers['user-agent'] || 'Unknown Browser';

      if (!credential || typeof credential !== 'string') {
        await recordAccessLog({
          userId: 'anonymous',
          email: 'unknown',
          name: 'Anonymous Visitor',
          authMethod: 'google_jwt_verified',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: 'Missing or malformed credential parameter' }
        });
        res.status(400).json({ success: false, error: "Missing credential token in request." });
        return;
      }

      const expectedClientId = process.env.GOOGLE_CLIENT_ID;
      if (!expectedClientId) {
        console.error("[GoogleAuth] Configuration Error: GOOGLE_CLIENT_ID is not configured.");
        await recordAccessLog({
          userId: 'system',
          email: 'system@server',
          name: 'System Auth',
          authMethod: 'google_jwt_verified',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: 'Server configuration error: GOOGLE_CLIENT_ID missing' }
        });
        res.status(500).json({ success: false, error: "Google OAuth is not configured on this server." });
        return;
      }

      // Cryptographic verification via official Google OAuth2 Client
      let ticketPayload: any = null;
      try {
        const ticket = await googleOAuthClient.verifyIdToken({
          idToken: credential,
          audience: expectedClientId,
        });
        ticketPayload = ticket.getPayload();
      } catch (verifyErr: unknown) {
        const errorMsg = getErrorMessage(verifyErr);
        console.warn("[GoogleAuth] Cryptographic verification failed:", errorMsg);
        await recordAccessLog({
          userId: 'unverified',
          email: 'unverified@token',
          name: 'Unverified Visitor',
          authMethod: 'google_jwt_verified',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: `Cryptographic token verification failed: ${errorMsg}` }
        });
        res.status(401).json({ success: false, error: "Invalid or expired Google credential token." });
        return;
      }

      if (!ticketPayload || !ticketPayload.sub || !ticketPayload.email) {
        await recordAccessLog({
          userId: ticketPayload?.sub || 'unverified',
          email: ticketPayload?.email || 'unverified@token',
          name: ticketPayload?.name || 'Unverified Visitor',
          authMethod: 'google_jwt_verified',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: 'Missing mandatory sub or email claims in verified token' }
        });
        res.status(401).json({ success: false, error: "Incomplete token claims." });
        return;
      }

      // Verify Google Issuer claim
      const validIssuers = ['accounts.google.com', 'https://accounts.google.com'];
      if (!validIssuers.includes(ticketPayload.iss)) {
        await recordAccessLog({
          userId: ticketPayload.sub,
          email: ticketPayload.email,
          name: ticketPayload.name || 'Untrusted Issuer',
          authMethod: 'google_jwt_verified',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: `Untrusted issuer: ${ticketPayload.iss}` }
        });
        res.status(401).json({ success: false, error: "Untrusted token issuer." });
        return;
      }

      const verifiedUser: SessionUser = {
        uid: ticketPayload.sub,
        email: ticketPayload.email,
        name: ticketPayload.name || ticketPayload.email.split('@')[0],
        picture: ticketPayload.picture,
        authMethod: 'google_jwt_verified',
        authenticatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 4 * 60 * 60 * 1000, // 4 hours
        issuer: ticketPayload.iss,
      };

      // Record Verified Access into persistent local database
      const accessRecord = await recordAccessLog({
        userId: verifiedUser.uid,
        email: verifiedUser.email,
        name: verifiedUser.name,
        picture: verifiedUser.picture,
        authMethod: 'google_jwt_verified',
        action: 'LOGIN_SUCCESS',
        ipAddress: clientIp,
        userAgent,
        status: 'SUCCESS',
        metadata: {
          issuer: verifiedUser.issuer,
          clientProvidedDetails: clientInfo || null
        }
      });

      const { token: sessionToken } = globalSessionStore.createSession(verifiedUser);
      setSessionCookie(res, sessionToken);

      console.log(`[GoogleAuth] Successfully verified Google credential for ${verifiedUser.email} (UID: ${verifiedUser.uid}). Log ID: ${accessRecord.id}`);

      res.status(200).json({
        success: true,
        user: verifiedUser,
        sessionToken,
        logId: accessRecord.id,
        message: "Google credential verified successfully."
      });

    } catch (err: unknown) {
      console.error("[GoogleAuth] Unexpected error during verification:", getErrorMessage(err));
      res.status(500).json({ success: false, error: "Authentication system error." });
    }
  });

  // =========================================================================
  // 🔐 LOGOUT & SESSION INVALIDATION (REM-02)
  // =========================================================================
  app.post("/api/auth/logout", async (req, res) => {
    try {
      const token = extractSessionToken(req);
      const clientIp = getClientIp(req);
      const userAgent = req.headers['user-agent'] || 'Unknown Browser';

      if (token) {
        const session = globalSessionStore.getSession(token);
        if (session) {
          await recordAccessLog({
            userId: session.uid,
            email: session.email,
            name: session.name,
            picture: session.picture,
            authMethod: session.authMethod as any,
            action: 'LOGOUT',
            ipAddress: clientIp,
            userAgent,
            status: 'SUCCESS',
            metadata: {
              sessionDurationSeconds: Math.floor((Date.now() - new Date(session.authenticatedAt).getTime()) / 1000)
            }
          });
        }
        globalSessionStore.deleteSession(token);
      }

      clearSessionCookie(res);
      res.json({ success: true, message: "Logged out successfully." });
    } catch (err: unknown) {
      console.error("[Auth] Logout error:", getErrorMessage(err));
      res.status(500).json({ success: false, error: "Logout processing failed." });
    }
  });

  // Record runtime user action/access event into Database
  app.post("/api/auth/record-event", async (req, res) => {
    try {
      const { user, action, metadata } = req.body;
      const clientIp = getClientIp(req);
      const userAgent = req.headers['user-agent'] || 'Unknown Browser';

      const log = await recordAccessLog({
        userId: user?.uid || 'guest',
        email: user?.email || 'guest@session',
        name: user?.name || 'Guest User',
        picture: user?.picture,
        authMethod: user?.uid ? 'credential_verification' : 'guest_audit',
        action: action || 'APP_ACCESS',
        ipAddress: clientIp,
        userAgent,
        status: 'SUCCESS',
        metadata: metadata || {}
      });

      if (action === 'LOGOUT') {
        const token = extractSessionToken(req);
        if (token) {
          globalSessionStore.deleteSession(token);
        }
      }

      res.json({ success: true, log });
    } catch (err: unknown) {
      console.error("[RecordEvent] Error recording log:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to record access event." });
    }
  });

  // =========================================================================
  // 🇪🇺 eIDAS 2.0 SAML ENDPOINTS (Metadata, AuthnRequest, ACS & Session)
  // =========================================================================

  // 1. SAML SP Metadata Endpoint
  app.get(["/saml/metadata", "/metadata"], (req, res) => {
    try {
      const host = req.get('host') || 'localhost:3000';
      const protocol = req.protocol || 'http';
      const spEntityId = process.env.SAML_SP_ENTITY_ID || `${protocol}://${host}/saml/metadata`;
      const acsUrl = process.env.SAML_SP_ACS_URL || `${protocol}://${host}/saml/acs`;

      const metadataXml = generateSPMetadata(spEntityId, acsUrl);
      res.setHeader('Content-Type', 'application/samlmetadata+xml; charset=utf-8');
      res.send(metadataXml);
    } catch (err: unknown) {
      console.error("[SAML Metadata] Error generating metadata:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to generate SAML SP metadata." });
    }
  });

  // 2. SAML AuthnRequest Generation Endpoint
  app.all(["/saml/authn-request", "/saml/login", "/api/saml/authn-request"], (req, res) => {
    try {
      const host = req.get('host') || 'localhost:3000';
      const protocol = req.protocol || 'http';

      const loa = (req.body?.loa || req.query?.loa || 'substantial') as string;
      const relayState = (req.body?.relayState || req.query?.relayState || '') as string;
      const destination = (req.body?.destination || req.query?.destination) as string | undefined;

      const result = generateAuthnRequest({
        loa,
        relayState,
        destination,
        spEntityId: process.env.SAML_SP_ENTITY_ID || `${protocol}://${host}/saml/metadata`,
        acsUrl: process.env.SAML_SP_ACS_URL || `${protocol}://${host}/saml/acs`,
      });

      res.json({
        success: true,
        requestId: result.requestId,
        destination: result.destination,
        authnRequestXml: result.authnRequestXml,
        samlRequestBase64: result.samlRequestBase64,
        relayState: result.relayState,
      });
    } catch (err: unknown) {
      console.error("[SAML AuthnRequest] Error generating request:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to generate AuthnRequest." });
    }
  });

  // 3. SAML Assertion Consumer Service (ACS) Endpoint
  app.post(["/saml/acs", "/auth/callback", "/saml/consume"], async (req, res) => {
    try {
      const clientIp = getClientIp(req);
      const userAgent = req.headers['user-agent'] || 'Unknown Browser';

      let samlResponse = req.body?.SAMLResponse || req.body?.saml_response || req.body?.xml_content || req.body?.samlResponse;
      if (!samlResponse && req.body?.preset) {
        samlResponse = await getPresetFixtureXml(req.body.preset);
      }
      const relayState = req.body?.RelayState || req.body?.relayState || '/';

      if (!samlResponse || typeof samlResponse !== 'string') {
        await recordAccessLog({
          userId: 'anonymous',
          email: 'unknown',
          name: 'Anonymous SAML Attempt',
          authMethod: 'eidas_saml',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: 'Missing SAMLResponse parameter' },
        });
        res.status(400).json({ success: false, error: "Missing SAMLResponse parameter." });
        return;
      }

      // Early defense: block DTD/XXE
      if (/<!\s*(DOCTYPE|ENTITY)/i.test(samlResponse)) {
        await recordAccessLog({
          userId: 'malicious',
          email: 'xxe@attempt',
          name: 'Security Violation',
          authMethod: 'eidas_saml',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: 'Security Violation: DTD declarations or external entities are forbidden.' },
        });
        res.status(400).json({
          success: false,
          error: "Security Violation: DTD declarations or external entities are forbidden."
        });
        return;
      }

      // Validate with Python saml_engine
      const validationResult = await validateSAMLResponse(samlResponse);

      if (!validationResult.is_valid) {
        await recordAccessLog({
          userId: 'unverified',
          email: 'unverified@eidas.europa.eu',
          name: 'Failed SAML Assertion',
          authMethod: 'eidas_saml',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: validationResult.error_message },
        });

        const errMsg = validationResult.error_message || "Validation failed";
        const isBadRequest = errMsg.includes("Missing mandatory")
          || errMsg.includes("Security Violation")
          || errMsg.includes("Invalid root tag")
          || errMsg.includes("Parser Error");

        const statusCode = isBadRequest ? 400 : 401;
        res.status(statusCode).json({
          success: false,
          error: errMsg,
        });
        return;
      }

      const posContext = validationResult.pos_context!;
      const claims = validationResult.claims || {};

      const sessionUser: SessionUser = {
        uid: 'session-user',
        email: 'verified@eidas.europa.eu',
        name: 'eIDAS User',
        authMethod: 'eidas_saml',
        role: posContext.role,
        permissions: posContext.permissions,
        levelOfAssurance: posContext.level_of_assurance,
        age: posContext.age,
        isOver18: posContext.is_over_18,
        isOver21: posContext.is_over_21,
        authenticatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 4 * 60 * 60 * 1000,
        issuer: claims.issuer,
      };

      const { token: sessionToken } = globalSessionStore.createSession(sessionUser);
      sessionUser.uid = sessionToken; // use session token as uid for logs
      setSessionCookie(res, sessionToken);

      await recordAccessLog({
        userId: sessionToken,
        email: 'verified@eidas.europa.eu',
        name: 'eIDAS User',
        authMethod: 'eidas_saml',
        action: 'LOGIN_SUCCESS',
        ipAddress: clientIp,
        userAgent,
        status: 'SUCCESS',
        metadata: {
          loa: sessionUser.levelOfAssurance,
          role: sessionUser.role,
          age: sessionUser.age,
          isOver18: sessionUser.isOver18,
          permissions: sessionUser.permissions,
        },
      });

      const safePosContext = {
        role: posContext.role,
        permissions: posContext.permissions,
        level_of_assurance: posContext.level_of_assurance,
        age: posContext.age,
        is_over_18: posContext.is_over_18,
        is_over_21: posContext.is_over_21,
      };

      res.json({
        success: true,
        relayState,
        sessionToken,
        user: sessionUser,
        pos_context: safePosContext,
      });

    } catch (err: unknown) {
      console.error("[SAML ACS] Unexpected error during assertion processing:", getErrorMessage(err));
      res.status(500).json({ success: false, error: "Internal SAML processing error." });
    }
  });

  // 4. SAML Current Session Endpoint
  app.get("/saml/session", (req, res) => {
    const token = extractSessionToken(req);
    if (!token) {
      res.status(401).json({ active: false, error: "No active SAML session token found." });
      return;
    }
    const session = globalSessionStore.getSession(token);
    if (!session) {
      res.status(401).json({ active: false, error: "Session has expired or is invalid." });
      return;
    }
    res.json({ active: true, user: session });
  });

  // Query Access Logs with filtering and pagination
  app.get("/api/access-logs", requireAuth, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    try {
      const search = (req.query.search as string) || '';
      const action = (req.query.action as string) || '';
      const limit = parseInt(req.query.limit as string, 10) || 50;
      const offset = parseInt(req.query.offset as string, 10) || 0;

      const result = await getAccessLogs({ search, action, limit, offset });
      res.json(result);
    } catch (err: unknown) {
      console.error("[AccessLogs] Error fetching logs:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to query access logs." });
    }
  });

  // Get Aggregate Access Database Statistics
  app.get("/api/access-logs/stats", requireAuth, async (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    try {
      const stats = await getAccessStats();
      res.json(stats);
    } catch (err: unknown) {
      console.error("[AccessLogs] Error fetching stats:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to compute access statistics." });
    }
  });

  // Export Access Logs to CSV
  app.get("/api/access-logs/export", requireAuth, async (req, res) => {
    try {
      const csv = await exportAccessLogsCsv();
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="credentials_hub_access_logs_${Date.now()}.csv"`);
      res.send(csv);
    } catch (err: unknown) {
      console.error("[AccessLogs] Error exporting CSV:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to export logs." });
    }
  });

  // Clear / Reset Access Logs Database
  app.post("/api/access-logs/clear", requireAuth, async (req, res) => {
    try {
      await clearAccessLogs();
      res.json({ success: true, message: "Access logs database cleared successfully." });
    } catch (err: unknown) {
      console.error("[AccessLogs] Error clearing database:", getErrorMessage(err));
      res.status(500).json({ error: "Failed to reset access logs." });
    }
  });

  // =========================================================================
  // 🔐 INSTITUTIONAL CHALLENGE (REM-01)
  // =========================================================================
  app.post("/api/institutional-challenge", async (req, res) => {
    try {
      const { institutionId } = req.body;
      
      // Strict input validation
      if (!institutionId || typeof institutionId !== 'string' || institutionId.trim() === '') {
        console.warn('[Backend Mock] Invalid or missing institutionId in request body.');
        res.status(400).json({ error: "A valid 'institutionId' string is required." });
        return;
      }

      const sanitizedInstitutionId = institutionId.trim();
      console.log(`[Backend Mock] Received challenge request for Institution: ${sanitizedInstitutionId}`);

      const keyPair = await getInstitutionalKeyPair();

      // Create a unique challenge incorporating the institution ID and a secure nonce/timestamp
      const timestamp = Date.now();
      const nonce = webcrypto.randomUUID();
      const challengeStr = `CHALLENGE-${nonce}-${sanitizedInstitutionId}-${timestamp}`;
      const challengeBuffer = new TextEncoder().encode(challengeStr);
      
      // Sign the challenge using the institutional private key
      const instSignatureBuffer = await webcrypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        keyPair.privateKey,
        challengeBuffer
      );

      // Export public key to JWK so frontend can verify the signature
      const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);

      // Convert buffer to Base64 to send over JSON safely
      const signatureBase64 = Buffer.from(instSignatureBuffer).toString('base64');
      
      // Simulate realistic network and processing latency (80-250ms), bypassed during test execution
      const isTestEnv = Boolean(options?.isTest || process.env.NODE_ENV === 'test');
      const latency = isTestEnv ? 0 : Math.floor(Math.random() * (250 - 80 + 1)) + 80;
      if (latency > 0) {
        await new Promise(resolve => setTimeout(resolve, latency));
      }

      // Register challenge in active challenge map for anti-replay tracking
      activeChallenges.set(challengeStr, {
        issuedAt: timestamp,
        consumed: false,
        signatureBase64,
        institutionId: sanitizedInstitutionId
      });

      // Bounded capacity & expired challenges pruning
      purgeExpiredInstitutionalChallenges();

      console.log(`[Backend Mock] Successfully generated and signed challenge (Active nonces: ${activeChallenges.size}). Responding after ${latency}ms latency.`);

      res.status(200).json({
        success: true,
        challenge: challengeStr,
        signatureBase64,
        publicKeyJwk,
      });
    } catch (error: unknown) {
      console.error("[Backend Mock] Institutional Challenge Error:", getErrorMessage(error));
      res.status(500).json({ 
        success: false, 
        error: "Internal Server Error: Failed to generate institutional challenge." 
      });
    }
  });

  // API Route 6: Bilanx DK-SVS Age-Gate Verify
  app.post("/api/v1/age-gate/verify", async (req, res) => {
    try {
      let proofBytes: Uint8Array;
      
      if (Buffer.isBuffer(req.body)) {
        // Raw binary body
        proofBytes = new Uint8Array(req.body);
      } else if (req.body && (req.body.proof || req.body.proofBase64)) {
        // JSON body
        const base64 = req.body.proof || req.body.proofBase64;
        try {
          proofBytes = new Uint8Array(Buffer.from(base64, 'base64'));
        } catch (e) {
          res.status(400).json({ valid: false, verify_ms: 0, proofByteLength: 0, error: "Invalid base64 string" });
          return;
        }
      } else {
        res.status(400).json({ valid: false, verify_ms: 0, proofByteLength: 0, error: "Missing proof binary or JSON proof/proofBase64" });
        return;
      }
      
      if (proofBytes.length === 0) {
        res.status(400).json({ valid: false, verify_ms: 0, proofByteLength: 0, error: "Empty proof" });
        return;
      }
      
      const t0 = performance.now();
      const isValid = await verifyProof(proofBytes);
      const verify_ms = performance.now() - t0;
      
      if (isValid) {
        res.status(200).json({
          valid: true,
          verify_ms,
          proofByteLength: proofBytes.length
        });
      } else {
        res.status(200).json({
          valid: false,
          verify_ms,
          proofByteLength: proofBytes.length,
          error: "Verification failed"
        });
      }
      
    } catch (e: unknown) {
      console.error("[Backend Verify Error]", getErrorMessage(e));
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // API Route 7: Bilanx DK-SVS Dual-Key Verify & Institutional Challenge Verify
  app.post(["/api/v1/dual-key/verify", "/api/institutional-challenge/verify"], async (req, res) => {
    try {
      purgeExpiredInstitutionalChallenges();
      const payload = req.body;
      if (!payload || payload.v !== 1) {
        res.status(400).json({ valid: false, error: "Invalid payload or unsupported version" });
        return;
      }

      const { challengeId, secondFactorHash, userPublicKey, userSignature, institutionalSignature } = payload;
      
      if (!challengeId || !secondFactorHash || !userPublicKey || !userSignature) {
        res.status(400).json({ valid: false, error: "Missing required payload fields" });
        return;
      }

      if (userPublicKey.crv !== 'P-256' || userPublicKey.kty !== 'EC') {
        res.status(400).json({ valid: false, error: "Unsupported key type" });
        return;
      }

      // 1. Priority-0 Anti-Replay & Freshness Check
      const challengeRecord = activeChallenges.get(challengeId);
      if (!challengeRecord) {
        res.status(200).json({ valid: false, reason: "Challenge not found or untracked by institutional node" });
        return;
      }

      if (challengeRecord.consumed) {
        res.status(200).json({ valid: false, reason: "Replay detected: challenge already consumed" });
        return;
      }

      if (Date.now() - challengeRecord.issuedAt > CHALLENGE_TTL_MS) {
        activeChallenges.delete(challengeId);
        res.status(200).json({ valid: false, reason: "Challenge expired" });
        return;
      }

      // Atomically consume challenge immediately BEFORE any asynchronous crypto operations
      // to eliminate race conditions and prevent concurrent parallel replay attacks
      challengeRecord.consumed = true;

      // 2. Server-Side Institutional Signature Verification
      const instKeyPair = await getInstitutionalKeyPair();
      const instSig = institutionalSignature || challengeRecord.signatureBase64;
      if (instSig) {
        try {
          const instSigBuffer = Buffer.from(instSig, 'base64');
          const challengeBuffer = new TextEncoder().encode(challengeId);
          const isInstSigValid = await webcrypto.subtle.verify(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            instKeyPair.publicKey,
            instSigBuffer,
            challengeBuffer
          );
          if (!isInstSigValid) {
            res.status(200).json({ valid: false, reason: "Institutional signature verification failed on server" });
            return;
          }
        } catch (e: unknown) {
          res.status(200).json({ valid: false, reason: "Invalid institutional signature format" });
          return;
        }
      } else {
        res.status(200).json({ valid: false, reason: "Missing institutional signature for challenge verification" });
        return;
      }

      // 3. Reconstruct canonical message and verify User Signature
      const canonicalMessage = `${challengeId}:${secondFactorHash}`;
      const messageBuffer = new TextEncoder().encode(canonicalMessage);

      // Convert userSignature from base64url to Buffer (P1363 format)
      const b64 = userSignature.replace(/-/g, '+').replace(/_/g, '/');
      const signatureBuffer = Buffer.from(b64, 'base64');

      // Import the public key
      let importedKey: webcrypto.CryptoKey;
      try {
        importedKey = await webcrypto.subtle.importKey(
          "jwk",
          userPublicKey,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["verify"]
        );
      } catch (err) {
        res.status(400).json({ valid: false, error: "Invalid JWK format" });
        return;
      }

      // Verify the ECDSA P-256 SHA-256 signature
      const isValid = await webcrypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        importedKey,
        signatureBuffer,
        messageBuffer
      );

      if (isValid) {
        res.status(200).json({ valid: true });
      } else {
        res.status(200).json({ valid: false, reason: "Signature verification failed" });
      }
    } catch (error: unknown) {
      console.error("[Dual-Key Verify Error]", getErrorMessage(error));
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  // WebAuthn / Hardware Enclave API Endpoints (TRL 6 Hybrid: Platform & Cross-Platform / YubiKey)
  app.post(['/api/webauthn/register-options', '/api/auth/webauthn/register-options'], (req, res) => {
    const username = req.body?.username || 'daniele.palagi92@gmail.com';
    const displayName = req.body?.displayName || 'Daniele Palagi';
    const challenge = generateWebAuthnChallenge();
    const rpId = req.hostname;
    const attachment = req.body?.authenticatorAttachment || req.body?.attachment;
    const residentKey = req.body?.residentKey || 'preferred';
    const requireResidentKey = req.body?.requireResidentKey || false;
    const userVerification = req.body?.userVerification || 'preferred';

    const authenticatorSelection: any = {
      userVerification,
      residentKey,
      requireResidentKey
    };
    if (attachment) {
      authenticatorSelection.authenticatorAttachment = attachment;
    }

    res.json({
      challenge,
      rp: { name: 'Project Bilanx Sovereign Node', id: rpId },
      user: { id: Buffer.from(username).toString('base64url'), name: username, displayName },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },  // ES256 (ECDSA P-256)
        { alg: -257, type: 'public-key' } // RS256 (RSA SHA-256)
      ],
      authenticatorSelection,
      attestation: 'direct'
    });
  });

  // Hardened WebAuthn Registration Verification (REM-03 / TRL 6)
  app.post(['/api/webauthn/register-verify', '/api/auth/webauthn/register-verify'], (req, res) => {
    try {
      const { credential, username } = req.body || {};
      if (!credential || !credential.id || !credential.response) {
        res.status(400).json({ verified: false, error: 'Missing credential payload or response' });
        return;
      }
      const expectedRpId = req.hostname;
      const expectedOrigin = getValidatedWebAuthnOrigin(req);
      if (!expectedOrigin) {
        res.status(400).json({ verified: false, error: 'Origin mismatch or untrusted origin' });
        return;
      }

      const requireUserVerification = req.body?.requireUserVerification === true || req.body?.userVerification === 'required';
      const stored = registerWebAuthnCredential({
        credentialId: credential.id,
        username: username || 'daniele.palagi92@gmail.com',
        clientDataJSONB64: credential.response.clientDataJSON,
        attestationObjectB64: credential.response.attestationObject,
        authenticatorDataB64: credential.response.authenticatorData,
        publicKeyPem: credential.response.publicKey,
        authenticatorAttachment: credential.authenticatorAttachment || req.body?.authenticatorAttachment || 'platform',
        expectedOrigin,
        expectedRpId,
        requireUserVerification
      });

      res.status(200).json({ verified: true, credential: stored });
    } catch (err: any) {
      res.status(400).json({ verified: false, error: err.message });
    }
  });

  app.post(['/api/webauthn/authenticate-options', '/api/auth/webauthn/authenticate-options'], (req, res) => {
    const challenge = generateWebAuthnChallenge();
    const credentialId = req.body?.credentialId;
    const responsePayload: any = { challenge, timeout: 60000, rpId: req.hostname };
    if (credentialId) {
      responsePayload.allowCredentials = [{
        id: credentialId,
        type: 'public-key',
        transports: ['usb', 'nfc', 'ble', 'internal', 'hybrid', 'smart-card']
      }];
    }
    res.json(responsePayload);
  });

  // Hardened WebAuthn Assertion Verification (REM-03 / Task 1.2)
  app.post(['/api/webauthn/authenticate-verify', '/api/auth/webauthn/authenticate-verify'], (req, res) => {
    try {
      const assertion = req.body?.assertion || req.body?.credential;
      const credentialId = req.body?.credentialId || assertion?.id;
      if (!assertion || !assertion.response) {
        res.status(400).json({ verified: false, error: 'Missing assertion response' });
        return;
      }
      const expectedRpId = req.hostname;
      const expectedOrigin = getValidatedWebAuthnOrigin(req);
      if (!expectedOrigin) {
        res.status(400).json({ verified: false, error: 'Origin mismatch or untrusted origin' });
        return;
      }

      const requireUserVerification = req.body?.requireUserVerification === true || req.body?.userVerification === 'required';
      const result = verifyWebAuthnAssertion({
        credentialId: credentialId || assertion.id,
        clientDataJSONB64: assertion.response.clientDataJSON,
        authenticatorDataB64: assertion.response.authenticatorData,
        signatureB64: assertion.response.signature || '',
        expectedOrigin,
        expectedRpId,
        requireUserVerification
      });

      if (!result.verified) {
        res.status(400).json(result);
        return;
      }

      res.status(200).json(result);
    } catch (err: any) {
      res.status(400).json({ verified: false, error: err.message });
    }
  });

  // 404 Fallback for all unmatched /api/* routes
  app.all('/api/*', (req, res) => {
    res.status(404).json({ error: `API route not found: ${req.method} ${req.path}` });
  });

  return app;
}
