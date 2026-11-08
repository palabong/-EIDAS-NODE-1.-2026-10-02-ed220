/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import type { webcrypto } from 'crypto';
import { CapacityExceededError, getErrorMessage, getValidatedWebAuthnOrigin } from '../httpShared.ts';
import { issueInstitutionalChallenge, verifyClearance, type ClearanceSessionGate } from '../clearance.ts';
import { findPublishedInstitutionalKey, getInstitutionalKey, jurisdictionForInstitution, listPublishedInstitutionalKeys } from '../institutionalKey.ts';
import { readClearanceEnvelope, verifyClearanceEnvelope } from '../../lib/crypto/clearanceEnvelope.ts';
import { extractSessionToken, globalSessionStore } from '../sessionManager.ts';

export function mountClearanceRoutes(
  app: express.Express,
  getInstitutionalKeyPair: () => Promise<webcrypto.CryptoKeyPair>
): void {
  app.post("/api/institutional-challenge", async (req, res) => {
    try {
      const { institutionId } = req.body;
      if (!institutionId || typeof institutionId !== 'string' || institutionId.trim() === '') {
        res.status(400).json({ error: "A valid 'institutionId' string is required." });
        return;
      }
      const jurisdiction = jurisdictionForInstitution(institutionId.trim());
      const material = await getInstitutionalKey(jurisdiction);
      const issued = await issueInstitutionalChallenge(
        institutionId.trim(),
        { publicKey: material.publicKey, privateKey: material.privateKey },
        material.keyId
      );
      res.status(200).json({
        success: true,
        challenge: issued.challenge,
        signatureBase64: issued.signatureBase64,
        publicKeyJwk: issued.publicKeyJwk,
        keyId: issued.keyId,
        jurisdiction,
      });
    } catch (error: unknown) {
      if (error instanceof CapacityExceededError) {
        res.status(429).json({ success: false, error: error.message });
        return;
      }
      console.error("[Institutional Challenge] Error:", getErrorMessage(error));
      res.status(500).json({
        success: false,
        error: "Internal Server Error: Failed to generate institutional challenge."
      });
    }
  });

  const handleClearance = async (req: express.Request, res: express.Response) => {
    try {
      const keyPair = await getInstitutionalKeyPair();
      const result = await verifyClearance(req.body, keyPair, sessionGate(req), {
        origin: getValidatedWebAuthnOrigin(req),
        rpId: req.hostname,
      });
      res.status(result.status).json(result.body);
    } catch (error: unknown) {
      console.error("[Clearance] Error:", getErrorMessage(error));
      res.status(500).json({ error: "Internal Server Error" });
    }
  };

  app.post("/api/v1/age-gate/verify", handleClearance);
  app.post(["/api/v1/dual-key/verify", "/api/institutional-challenge/verify"], handleClearance);

  app.get("/api/v1/jwks", async (_req, res) => {
    try {
      const published = await listPublishedInstitutionalKeys();
      res.status(200).json({
        keys: published.map((key) => ({
          kty: key.publicKeyJwk.kty,
          crv: key.publicKeyJwk.crv,
          x: key.publicKeyJwk.x,
          y: key.publicKeyJwk.y,
          kid: key.keyId,
          use: 'sig',
          alg: 'ES256',
          jurisdiction: key.jurisdiction,
          status: key.retiredAt === undefined ? 'active' : 'retired',
          ...(key.retiredAt !== undefined ? { retiredAt: key.retiredAt } : {}),
        })),
      });
    } catch (error: unknown) {
      console.error("[JWKS] Error:", getErrorMessage(error));
      res.status(500).json({ error: "Internal Server Error" });
    }
  });

  app.post("/api/v1/envelope/verify", async (req, res) => {
    try {
      const signature = req.body?.envelopeSignature;
      if (typeof signature !== 'string' || signature.length === 0) {
        res.status(200).json({ valid: false, reason: 'unsigned' });
        return;
      }
      const envelope = parseEnvelopeBody(req.body?.envelope);
      const parsed = readClearanceEnvelope(envelope);
      if (!parsed) {
        res.status(200).json({ valid: false, reason: 'malformed' });
        return;
      }
      const published = await findPublishedInstitutionalKey(parsed.keyId);
      if (!published) {
        res.status(200).json({ valid: false, reason: 'signature_rejected' });
        return;
      }
      const verdict = await verifyClearanceEnvelope(parsed, signature, published.publicKey);
      if (verdict.ok === false) {
        res.status(200).json({ valid: false, reason: verdict.reason });
        return;
      }
      res.status(200).json({
        valid: true,
        keyId: verdict.envelope.keyId,
        jurisdiction: verdict.envelope.jurisdiction,
        retailSale: verdict.envelope.retailSale === true,
      });
    } catch (error: unknown) {
      console.error("[Envelope Verify] Error:", getErrorMessage(error));
      res.status(500).json({ valid: false, error: "Internal Server Error" });
    }
  });
}

function parseEnvelopeBody(envelope: unknown): unknown {
  if (typeof envelope !== 'string') return envelope;
  try {
    return JSON.parse(envelope);
  } catch {
    return null;
  }
}

function sessionGate(req: express.Request): ClearanceSessionGate {
  const token = extractSessionToken(req);
  if (!token) return { present: false, claims: null };
  const session = globalSessionStore.getSession(token);
  if (!session) return { present: true, claims: null };
  return {
    present: true,
    claims: {
      levelOfAssurance: session.levelOfAssurance,
      isOver18: typeof session.isOver18 === 'boolean' ? session.isOver18 : undefined,
    },
  };
}

