/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import type { webcrypto } from 'crypto';
import { CapacityExceededError, getErrorMessage } from '../httpShared.ts';
import { issueInstitutionalChallenge, verifyClearance } from '../clearance.ts';
import { getInstitutionalKey, jurisdictionForInstitution } from '../institutionalKey.ts';

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
      const result = await verifyClearance(req.body, keyPair);
      res.status(result.status).json(result.body);
    } catch (error: unknown) {
      console.error("[Clearance] Error:", getErrorMessage(error));
      res.status(500).json({ error: "Internal Server Error" });
    }
  };

  app.post("/api/v1/age-gate/verify", handleClearance);
  app.post(["/api/v1/dual-key/verify", "/api/institutional-challenge/verify"], handleClearance);
}

