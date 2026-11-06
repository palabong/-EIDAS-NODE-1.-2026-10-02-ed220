/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import { getClientIp, getErrorMessage, googleOAuthClient } from '../httpShared.ts';
import {
  recordAccessLog,
  getAccessLogs,
  getAccessStats,
  clearAccessLogs,
  exportAccessLogsCsv
} from '../accessLogDb.ts';
import {
  globalSessionStore,
  extractSessionToken,
  setSessionCookie,
  clearSessionCookie
} from '../sessionManager.ts';
import type { SessionUser } from '../types/saml.ts';

export function mountAuthRoutes(app: express.Express): void {
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

  // Expose public OAuth client configuration dynamically from runtime environment / Secret Manager
  app.get("/api/auth/config", (_req, res) => {
    const googleClientId = process.env.GOOGLE_CLIENT_ID || process.env.VITE_GOOGLE_CLIENT_ID || null;
    res.json({ googleClientId });
  });

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
}

