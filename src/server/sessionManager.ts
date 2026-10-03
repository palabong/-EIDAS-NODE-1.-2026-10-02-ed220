/**
 * Typed Session Manager with TTL Expiration & Cookie Support
 */

import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import type { SessionUser } from './types/saml.ts';

export class SessionStore {
  private sessions = new Map<string, SessionUser>();
  private defaultTtlMs: number;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor(defaultTtlMs: number = 4 * 60 * 60 * 1000) { // 4 hours
    this.defaultTtlMs = defaultTtlMs;
    // Periodic garbage collection every 10 minutes
    this.cleanupInterval = setInterval(() => this.pruneExpiredSessions(), 10 * 60 * 1000);
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  public createSession(userData: Omit<SessionUser, 'expiresAt'>, ttlMs?: number): { token: string; session: SessionUser } {
    const token = crypto.randomUUID();
    const expiresAt = Date.now() + (ttlMs || this.defaultTtlMs);
    const session: SessionUser = {
      ...userData,
      expiresAt,
    };
    this.sessions.set(token, session);
    return { token, session };
  }

  public getSession(token: string): SessionUser | null {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;

    if (Date.now() > session.expiresAt) {
      this.sessions.delete(token);
      return null;
    }
    return session;
  }

  public touchSession(token: string, extensionMs?: number): boolean {
    const session = this.sessions.get(token);
    if (!session) return false;
    session.expiresAt = Date.now() + (extensionMs || this.defaultTtlMs);
    return true;
  }

  public deleteSession(token: string): boolean {
    return this.sessions.delete(token);
  }

  public pruneExpiredSessions(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [token, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.sessions.delete(token);
        pruned++;
      }
    }
    return pruned;
  }

  public size(): number {
    return this.sessions.size;
  }

  public clear(): void {
    this.sessions.clear();
  }
}

export const globalSessionStore = new SessionStore();

/**
 * Extracts session token from Cookie header (session_token=...) or Authorization header (Bearer ...) or ?token=...
 */
export function extractSessionToken(req: Request): string | null {
  // 1. Authorization header: Bearer <token>
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7).trim();
    if (token) return token;
  }

  // 2. Cookie header: session_token=<token>
  const cookieHeader = req.headers.cookie;
  if (cookieHeader) {
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
      const [name, ...valParts] = cookie.trim().split('=');
      if (name.trim() === 'session_token') {
        const val = valParts.join('=').trim();
        if (val) return decodeURIComponent(val);
      }
    }
  }

  // 3. Query parameter: ?token=<token> (Deprecated & disallowed in production to prevent URL token leakage)
  if (process.env.NODE_ENV !== 'production' && typeof req.query.token === 'string' && req.query.token.trim()) {
    console.warn('[Security] Deprecated: Session token extracted from query parameter. This is disabled in production.');
    return req.query.token.trim();
  }

  return null;
}

/**
 * Helper to set HTTP-only session cookie on Response
 */
export function setSessionCookie(res: Response, token: string, maxAgeMs: number = 4 * 60 * 60 * 1000): void {
  const maxAgeSec = Math.floor(maxAgeMs / 1000);
  const isSecure = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
  const secureFlag = isSecure ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `session_token=${encodeURIComponent(token)}; Path=/; Max-Age=${maxAgeSec}; HttpOnly; SameSite=Lax${secureFlag}`
  );
}

/**
 * Helper to clear session cookie on Response
 */
export function clearSessionCookie(res: Response): void {
  const isSecure = process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === 'true';
  const secureFlag = isSecure ? '; Secure' : '';
  res.setHeader(
    'Set-Cookie',
    `session_token=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax${secureFlag}`
  );
}

/**
 * Express middleware ensuring request has a valid, active session
 */
export function requireSessionAuth(req: Request, res: Response, next: NextFunction): void {
  const token = extractSessionToken(req);
  if (!token) {
    res.status(401).json({ error: "Unauthorized: Missing session credentials." });
    return;
  }

  const session = globalSessionStore.getSession(token);
  if (!session) {
    res.status(401).json({ error: "Unauthorized: Invalid or expired session." });
    return;
  }

  (req as any).user = session;
  (req as any).sessionToken = token;
  next();
}
