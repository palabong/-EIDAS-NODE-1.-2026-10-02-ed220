/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import { getClientIp, getErrorMessage } from '../httpShared.ts';
import { recordAccessLog } from '../accessLogDb.ts';
import {
  globalSessionStore,
  extractSessionToken,
  setSessionCookie
} from '../sessionManager.ts';
import {
  generateSPMetadata,
  generateAuthnRequest,
  validateSAMLResponse,
  getPresetFixtureXml,
  isKnownSamlPreset
} from '../samlBridge.ts';
import type { SessionUser } from '../types/saml.ts';

export function mountSamlRoutes(app: express.Express, options?: { allowSamlPresets?: boolean }): void {
  const allowSamlPresets = options?.allowSamlPresets === true;
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
      if (!samlResponse && req.body?.preset !== undefined) {
        if (!allowSamlPresets) {
          await recordAccessLog({
            userId: 'anonymous',
            email: 'unknown',
            name: 'Anonymous SAML Attempt',
            authMethod: 'eidas_saml',
            action: 'LOGIN_FAILURE',
            ipAddress: clientIp,
            userAgent,
            status: 'DENIED',
            metadata: { reason: 'SAML preset fixtures are disabled' },
          });
          res.status(403).json({
            success: false,
            error: 'SAML preset fixtures are disabled outside the test harness.'
          });
          return;
        }
        if (typeof req.body.preset !== 'string' || !isKnownSamlPreset(req.body.preset)) {
          await recordAccessLog({
            userId: 'anonymous',
            email: 'unknown',
            name: 'Anonymous SAML Attempt',
            authMethod: 'eidas_saml',
            action: 'LOGIN_FAILURE',
            ipAddress: clientIp,
            userAgent,
            status: 'DENIED',
            metadata: { reason: 'Unknown SAML preset' },
          });
          res.status(400).json({
            success: false,
            error: 'Unknown SAML preset.'
          });
          return;
        }
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
}

