/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';
import type { SessionUser } from './types/saml.ts';

dotenv.config();

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

/** Thrown when an in-memory security map is full. Callers must answer HTTP 429 and leave existing entries in place. */
export class CapacityExceededError extends Error {
  readonly httpStatus = 429;

  constructor(message: string) {
    super(message);
    this.name = 'CapacityExceededError';
  }
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
