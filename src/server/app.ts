/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import fs from 'fs/promises';
import { webcrypto } from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

import { getErrorMessage, isOriginAllowedCors } from './httpShared.ts';

export {
  getClientIp,
  getErrorMessage,
  googleOAuthClient,
  TRUSTED_ORIGINS,
  isOriginAllowedCors,
  getValidatedWebAuthnOrigin,
} from './httpShared.ts';

export { activeChallenges, CHALLENGE_TTL_MS } from './clearance.ts';

import { mountAuthRoutes } from './routes/authRoutes.ts';
import { mountSamlRoutes } from './routes/samlRoutes.ts';
import { mountClearanceRoutes } from './routes/clearanceRoutes.ts';
import { mountWebAuthnRoutes } from './routes/webauthnRoutes.ts';

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
// 🔐 INSTITUTIONAL KEY MANAGEMENT (REM-01)
// =========================================================================
let backendInstitutionalKeyPair: webcrypto.CryptoKeyPair | null = null;

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

  mountAuthRoutes(app);
  mountSamlRoutes(app);
  mountClearanceRoutes(app, getInstitutionalKeyPair);
  mountWebAuthnRoutes(app);

  // 404 Fallback for all unmatched /api/* routes
  app.all('/api/*', (req, res) => {
    res.status(404).json({ error: `API route not found: ${req.method} ${req.path}` });
  });

  return app;
}
