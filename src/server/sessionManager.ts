/**
 * Typed Session Manager with TTL Expiration & Cookie Support
 */

import crypto from 'crypto';
import type { Request, Response, NextFunction } from 'express';
import { MemoryDurableMap, openDurableMap, type DurableStore } from './durableStore.ts';
import {
  firestoreClearCollection,
  firestoreDeleteDocument,
  firestoreListDocuments,
  firestoreUpsertDocument,
  isFirestoreEnabled,
} from './firestoreRest.ts';
import type { SessionUser } from './types/saml.ts';

const FIRESTORE_SESSIONS_COLLECTION = 'bilanx_sessions';

export class SessionStore {
  declare ['constructor']: typeof SessionStore;
  private readonly storeName?: string;
  private sessions: DurableStore<SessionUser>;
  private defaultTtlMs: number;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private firestoreHydrated = false;

  constructor(defaultTtlMs: number = 4 * 60 * 60 * 1000, storeName?: string) { // 4 hours
    this.defaultTtlMs = defaultTtlMs;
    this.storeName = storeName;
    this.sessions = storeName ? openDurableMap<SessionUser>(storeName) : new MemoryDurableMap<SessionUser>();
    // Periodic garbage collection every 10 minutes
    this.cleanupInterval = setInterval(() => this.pruneExpiredSessions(), 10 * 60 * 1000);
    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  private syncSessionToFirestore(token: string, session: SessionUser): void {
    if (!this.storeName || !isFirestoreEnabled()) return;
    firestoreUpsertDocument(FIRESTORE_SESSIONS_COLLECTION, token, {
      token: { stringValue: token },
      sessionJson: { stringValue: JSON.stringify(session) },
      expiresAt: { integerValue: String(session.expiresAt) },
    }).catch((err) => {
      console.warn('[SessionStore] Firestore upsert skipped:', err instanceof Error ? err.message : String(err));
    });
  }

  private deleteSessionFromFirestore(token: string): void {
    if (!this.storeName || !isFirestoreEnabled()) return;
    firestoreDeleteDocument(FIRESTORE_SESSIONS_COLLECTION, token).catch((err) => {
      console.warn('[SessionStore] Firestore delete skipped:', err instanceof Error ? err.message : String(err));
    });
  }

  public async hydrateFromFirestore(): Promise<number> {
    if (!this.storeName || !isFirestoreEnabled() || this.firestoreHydrated) return 0;
    this.firestoreHydrated = true;
    try {
      const docs = await firestoreListDocuments(FIRESTORE_SESSIONS_COLLECTION, 1000);
      const now = Date.now();
      let loaded = 0;
      for (const doc of docs) {
        const f = doc.fields;
        const token = f?.token?.stringValue || doc.name.split('/').pop();
        const raw = f?.sessionJson?.stringValue;
        if (!token || !raw) continue;
        try {
          const parsed = JSON.parse(raw) as SessionUser;
          if (typeof parsed.expiresAt === 'number' && parsed.expiresAt > now) {
            this.sessions.set(token, parsed);
            loaded++;
          } else {
            this.deleteSessionFromFirestore(token);
          }
        } catch {}
      }
      if (loaded > 0) {
        console.log(`[SessionStore] Hydrated ${loaded} active session(s) from Cloud Firestore.`);
      }
      return loaded;
    } catch (err) {
      console.warn('[SessionStore] Firestore hydration skipped:', err instanceof Error ? err.message : String(err));
      return 0;
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
    this.syncSessionToFirestore(token, session);
    return { token, session };
  }

  public getSession(token: string): SessionUser | null {
    if (!token) return null;
    const session = this.sessions.get(token);
    if (!session) return null;

    if (Date.now() > session.expiresAt) {
      this.sessions.delete(token);
      this.deleteSessionFromFirestore(token);
      return null;
    }
    return session;
  }

  public touchSession(token: string, extensionMs?: number): boolean {
    const session = this.sessions.get(token);
    if (!session) return false;
    session.expiresAt = Date.now() + (extensionMs || this.defaultTtlMs);
    this.sessions.commit(token);
    this.syncSessionToFirestore(token, session);
    return true;
  }

  public deleteSession(token: string): boolean {
    this.deleteSessionFromFirestore(token);
    return this.sessions.delete(token);
  }

  public pruneExpiredSessions(): number {
    const now = Date.now();
    let pruned = 0;
    for (const [token, session] of this.sessions.entries()) {
      if (now > session.expiresAt) {
        this.sessions.delete(token);
        this.deleteSessionFromFirestore(token);
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
    if (this.storeName && isFirestoreEnabled()) {
      firestoreClearCollection(FIRESTORE_SESSIONS_COLLECTION).catch(() => {});
    }
  }
}

export const globalSessionStore = new SessionStore(4 * 60 * 60 * 1000, 'sessions');

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
