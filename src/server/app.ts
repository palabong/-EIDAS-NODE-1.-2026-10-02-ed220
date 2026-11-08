/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import dotenv from 'dotenv';

dotenv.config();

import { isOriginAllowedCors } from './httpShared.ts';
import { getInstitutionalKeyPair } from './institutionalKey.ts';
import { clearanceMetricsSnapshot } from './clearanceAudit.ts';

export {
  getClientIp,
  getErrorMessage,
  googleOAuthClient,
  TRUSTED_ORIGINS,
  isOriginAllowedCors,
  getValidatedWebAuthnOrigin,
} from './httpShared.ts';

export { activeChallenges, CHALLENGE_TTL_MS } from './clearance.ts';
export {
  getInstitutionalKey,
  getInstitutionalKeyPair,
  rotateInstitutionalKey,
  releaseInstitutionalKey,
  listPublishedInstitutionalKeys,
  findPublishedInstitutionalKey,
  backdateRetiredInstitutionalKey,
  jurisdictionForInstitution,
  loadPrimaryKeyOrThrow,
  type InstitutionalJurisdiction,
  type InstitutionalKeyMaterial,
  type InstitutionalKeySource,
  type PublishedInstitutionalKey,
} from './institutionalKey.ts';

import { mountAuthRoutes } from './routes/authRoutes.ts';
import { mountSamlRoutes } from './routes/samlRoutes.ts';
import { mountClearanceRoutes } from './routes/clearanceRoutes.ts';
import { mountStockRoutes } from './routes/stockRoutes.ts';
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

/**
 * Creates and configures the core Express application with security headers,
 * CORS policy, body parsers, and all authenticated API routes.
 */
export interface CreateAppOptions {
  /** Harness boot. Production still refuses preset minting. */
  isTest?: boolean;
  /**
   * Local sandbox server (`npm run dev`). Production still refuses preset minting.
   * A default `createApp()` leaves this off.
   */
  allowLocalDemoPresets?: boolean;
}

/** Preset minting is for the harness and the local demo server. Production always refuses. */
export function samlPresetsAllowed(options?: CreateAppOptions): boolean {
  if (process.env.NODE_ENV === 'production') return false;
  return options?.isTest === true || options?.allowLocalDemoPresets === true;
}

export function createApp(options?: CreateAppOptions): express.Express {
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

  app.get("/api/metrics", (_req, res) => {
    res.json({ clearance: clearanceMetricsSnapshot() });
  });

  mountAuthRoutes(app);
  mountSamlRoutes(app, { allowSamlPresets: samlPresetsAllowed(options) });
  mountClearanceRoutes(app, getInstitutionalKeyPair);
  mountStockRoutes(app);
  mountWebAuthnRoutes(app);

  // 404 Fallback for all unmatched /api/* routes
  app.all('/api/*', (req, res) => {
    res.status(404).json({ error: `API route not found: ${req.method} ${req.path}` });
  });

  return app;
}
