/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import { CapacityExceededError, getValidatedWebAuthnOrigin } from '../httpShared.ts';
import {
  generateWebAuthnChallenge,
  registerWebAuthnCredential,
  verifyWebAuthnAssertion
} from '../webauthnServer.ts';
import { recordClearanceAudit } from '../clearanceAudit.ts';

function rejectCapacity(err: unknown, res: express.Response): boolean {
  if (err instanceof CapacityExceededError) {
    res.status(429).json({ verified: false, error: err.message });
    return true;
  }
  return false;
}

export function mountWebAuthnRoutes(app: express.Express): void {
  // WebAuthn ceremony against a software or platform authenticator. Credentials stay in process memory.
  app.post(['/api/webauthn/register-options', '/api/auth/webauthn/register-options'], (req, res) => {
    const username = req.body?.username;
    if (!username || typeof username !== 'string') {
      res.status(400).json({ error: 'username is required' });
      return;
    }
    const displayName = req.body?.displayName || username;
    let challenge: string;
    try {
      challenge = generateWebAuthnChallenge();
    } catch (err: unknown) {
      if (rejectCapacity(err, res)) return;
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
      return;
    }
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
        { alg: -7, type: 'public-key' } // ES256 (ECDSA P-256)
      ],
      authenticatorSelection,
      attestation: 'direct'
    });
  });

  // Registration verification for the in-memory WebAuthn credential store.
  app.post(['/api/webauthn/register-verify', '/api/auth/webauthn/register-verify'], (req, res) => {
    try {
      const { credential, username } = req.body || {};
      if (!credential || !credential.id || !credential.response) {
        res.status(400).json({ verified: false, error: 'Missing credential payload or response' });
        return;
      }
      if (!username || typeof username !== 'string') {
        res.status(400).json({ verified: false, error: 'username is required' });
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
        username,
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
      if (rejectCapacity(err, res)) return;
      const message = typeof err?.message === 'string' ? err.message : '';
      if (/attestation|certificate/i.test(message)) {
        recordClearanceAudit({ event: 'attestation_failure', reason: 'attestation_rejected' });
      }
      res.status(400).json({ verified: false, error: err.message });
    }
  });

  app.post(['/api/webauthn/authenticate-options', '/api/auth/webauthn/authenticate-options'], (req, res) => {
    let challenge: string;
    try {
      challenge = generateWebAuthnChallenge();
    } catch (err: unknown) {
      if (rejectCapacity(err, res)) return;
      res.status(400).json({ error: err instanceof Error ? err.message : String(err) });
      return;
    }
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
      if (rejectCapacity(err, res)) return;
      res.status(400).json({ verified: false, error: err.message });
    }
  });
}

