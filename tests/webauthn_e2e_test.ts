/**
 * Automated End-to-End Cryptographic Test Suite for WebAuthn / FIDO2 (REM-03 & REM-06)
 * 
 * Verifies authentic W3C WebAuthn Level 2/3 verification on an ephemeral Express server:
 * 1. Challenge Generation & Registration Options
 * 2. Authentic Attestation & Registration with ECDSA P-256 Keypair
 * 3. Authentication Options Generation
 * 4. Authentic Assertion Signing & Verification with Secure Enclave Emulation
 * 5. Negative Vector: Tampered Signature Bytes (Cryptographic Verification Failure)
 * 6. Negative Vector: Replay Attack (Reused / Consumed Challenge)
 * 7. Negative Vector: Origin Mismatch (Phishing Protection)
 * 8. Negative Vector: Cloned Authenticator (Counter Stagnation / Replay)
 * 9. Negative Vector: Wrong Event Type
 * 10. Negative Vector: Malformed ClientDataJSON
 * 11. Negative Vector: Unregistered Credential ID
 */

import express from 'express';
import { createServer } from 'http';
import crypto from 'crypto';
import type { AddressInfo } from 'net';
import assert from 'assert';
import {
  clearWebAuthnState,
  encodeCbor
} from '../src/server/webauthnServer.ts';
import { createApp } from '../src/server/app.ts';

function createMockAuthenticatorKeys() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x!, 'base64url');
  const y = Buffer.from(jwk.y!, 'base64url');
  return { privateKey, publicKey, x, y };
}

function buildMockAttestationObject(
  rpId: string,
  credentialId: Buffer,
  x: Buffer,
  y: Buffer
): Buffer {
  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const flags = 0x41; // UP (0x01) | AT (0x40)
  const aaguid = Buffer.alloc(16);

  const coseKey = new Map<number, any>();
  coseKey.set(1, 2);   // EC2
  coseKey.set(3, -7);  // ES256
  coseKey.set(-1, 1);  // P-256
  coseKey.set(-2, x);
  coseKey.set(-3, y);
  const coseKeyBuf = encodeCbor(coseKey);

  const credIdLenBuf = Buffer.alloc(2);
  credIdLenBuf.writeUInt16BE(credentialId.length, 0);

  const authData = Buffer.concat([
    rpIdHash,
    Buffer.from([flags]),
    Buffer.alloc(4), // counter 0
    aaguid,
    credIdLenBuf,
    credentialId,
    coseKeyBuf
  ]);

  const attestationMap = new Map<string, any>();
  attestationMap.set('fmt', 'none');
  attestationMap.set('attStmt', new Map());
  attestationMap.set('authData', authData);

  return encodeCbor(attestationMap);
}

function buildMockAssertion(
  privateKey: crypto.KeyObject,
  rpId: string,
  challenge: string,
  origin: string,
  counter: number,
  eventType: string = 'webauthn.get',
  userPresent: boolean = true
) {
  const clientDataJSON = JSON.stringify({
    type: eventType,
    challenge,
    origin,
    crossOrigin: false
  });
  const clientDataJSONB64 = Buffer.from(clientDataJSON, 'utf-8').toString('base64');

  const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
  const flags = userPresent ? 0x01 : 0x00;
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);

  const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf]);
  const authenticatorDataB64 = authenticatorData.toString('base64');

  const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'utf-8')).digest();
  const signedBytes = Buffer.concat([authenticatorData, clientDataHash]);

  const signature = crypto.sign('SHA256', signedBytes, privateKey);
  const signatureB64 = signature.toString('base64');

  return { clientDataJSONB64, authenticatorDataB64, signatureB64 };
}

async function runWebAuthnTests() {
  console.log('[WebAuthn Test Suite] Booting ephemeral Express server...');
  clearWebAuthnState();

  const app = createApp({ isTest: true });
  const server = createServer(app);
  let passed = 0;
  let failed = 0;

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const rpId = '127.0.0.1';
  const origin = baseUrl;
  console.log(`[WebAuthn Test Server] Running at ${baseUrl} (RP ID: ${rpId})`);

  try {
    const username = 'daniele.palagi92@gmail.com';
    const rawCredId = crypto.randomBytes(16);
    const credentialId = rawCredId.toString('base64url');
    const { privateKey, publicKey, x, y } = createMockAuthenticatorKeys();

    // -------------------------------------------------------------------------
    // Test 1: Registration Options
    // -------------------------------------------------------------------------
    const optRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName: 'Daniele Palagi' })
    });
    const optData = await optRes.json();
    assert.strictEqual(optRes.status, 200);
    assert.ok(optData.challenge, 'Challenge must be present');
    assert.strictEqual(optData.rp.name, 'Project Bilanx Sovereign Node');
    console.log('  ✅ [PASS] 1. POST /api/webauthn/register-options generates valid parameters');
    passed++;

    // -------------------------------------------------------------------------
    // Test 2: Authentic Attestation & Registration
    // -------------------------------------------------------------------------
    const regChallenge = optData.challenge;
    const regClientDataJSON = JSON.stringify({
      type: 'webauthn.create',
      challenge: regChallenge,
      origin
    });
    const regClientDataJSONB64 = Buffer.from(regClientDataJSON).toString('base64');
    const attestationObject = buildMockAttestationObject(rpId, rawCredId, x, y);
    const attestationObjectB64 = attestationObject.toString('base64');

    const regRes = await fetch(`${baseUrl}/api/webauthn/register-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        credential: {
          id: credentialId,
          response: {
            clientDataJSON: regClientDataJSONB64,
            attestationObject: attestationObjectB64
          }
        }
      })
    });
    const regData = await regRes.json();
    assert.strictEqual(regRes.status, 200);
    assert.strictEqual(regData.verified, true);
    assert.strictEqual(regData.credential.credentialId, credentialId);
    assert.ok(regData.credential.publicKeyPem.includes('BEGIN PUBLIC KEY'), 'Stored key must be SPKI PEM');
    console.log('  ✅ [PASS] 2. POST /api/webauthn/register-verify stores authentic credential from COSE Key');
    passed++;

    // -------------------------------------------------------------------------
    // Test 2b: Registration clientDataJSON without origin
    // -------------------------------------------------------------------------
    const missingOriginOptRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    const missingOriginOptData = await missingOriginOptRes.json();
    const missingOriginClientData = JSON.stringify({
      type: 'webauthn.create',
      challenge: missingOriginOptData.challenge
    });
    const missingOriginCredId = crypto.randomBytes(16);
    const missingOriginAttestation = buildMockAttestationObject(rpId, missingOriginCredId, x, y);
    const missingOriginRes = await fetch(`${baseUrl}/api/webauthn/register-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        credential: {
          id: missingOriginCredId.toString('base64url'),
          response: {
            clientDataJSON: Buffer.from(missingOriginClientData).toString('base64'),
            attestationObject: missingOriginAttestation.toString('base64')
          }
        }
      })
    });
    const missingOriginData = await missingOriginRes.json();
    assert.strictEqual(missingOriginRes.status, 400);
    assert.strictEqual(missingOriginData.verified, false);
    assert.ok(String(missingOriginData.error).includes('Origin mismatch'));
    assert.ok(String(missingOriginData.error).includes('missing'));
    console.log('  ✅ [PASS] 2b. Registration without clientDataJSON.origin is rejected');
    passed++;

    // -------------------------------------------------------------------------
    // Test 3: Authentication Options
    // -------------------------------------------------------------------------
    const authOptRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    const authOptData = await authOptRes.json();
    assert.strictEqual(authOptRes.status, 200);
    assert.ok(authOptData.challenge, 'Fresh challenge must be present');
    console.log('  ✅ [PASS] 3. POST /api/webauthn/authenticate-options generates challenge');
    passed++;

    // -------------------------------------------------------------------------
    // Test 4: Authentic Assertion Verification (Valid)
    // -------------------------------------------------------------------------
    const authChallenge = authOptData.challenge;
    const assertion = buildMockAssertion(privateKey, rpId, authChallenge, origin, 1);

    const authRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: assertion.clientDataJSONB64,
            authenticatorData: assertion.authenticatorDataB64,
            signature: assertion.signatureB64
          }
        }
      })
    });
    const authData = await authRes.json();
    assert.strictEqual(authRes.status, 200);
    assert.strictEqual(authData.verified, true);
    assert.strictEqual(authData.credential?.counter, 1);
    console.log('  ✅ [PASS] 4. POST /api/webauthn/authenticate-verify verifies authentic ECDSA assertion');
    passed++;

    // -------------------------------------------------------------------------
    // Test 5: Negative - Tampered Signature
    // -------------------------------------------------------------------------
    const tamperedOptRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
    const tamperedOptData = await tamperedOptRes.json();
    const tamperedAssertion = buildMockAssertion(privateKey, rpId, tamperedOptData.challenge, origin, 2);

    const badSigBuf = Buffer.from(tamperedAssertion.signatureB64, 'base64');
    badSigBuf[badSigBuf.length - 2] ^= 0xff; // flip bits
    const badSigB64 = badSigBuf.toString('base64');

    const tamperedRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: tamperedAssertion.clientDataJSONB64,
            authenticatorData: tamperedAssertion.authenticatorDataB64,
            signature: badSigB64
          }
        }
      })
    });
    assert.strictEqual(tamperedRes.status, 400);
    const tamperedData = await tamperedRes.json();
    assert.strictEqual(tamperedData.verified, false);
    console.log('  ✅ [PASS] 5. Negative: Tampered signature rejected with 400');
    passed++;

    // -------------------------------------------------------------------------
    // Test 6: Negative - Replay Attack (Reusing consumed challenge)
    // -------------------------------------------------------------------------
    const replayRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: assertion.clientDataJSONB64,
            authenticatorData: assertion.authenticatorDataB64,
            signature: assertion.signatureB64
          }
        }
      })
    });
    assert.strictEqual(replayRes.status, 400);
    const replayData = await replayRes.json();
    assert.strictEqual(replayData.verified, false);
    assert.ok(replayData.error.includes('Challenge not found') || replayData.error.includes('replay'));
    console.log('  ✅ [PASS] 6. Negative: Challenge replay attack rejected');
    passed++;

    // -------------------------------------------------------------------------
    // Test 7: Negative - Origin Mismatch (Phishing Protection)
    // -------------------------------------------------------------------------
    const originOptRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
    const originOptData = await originOptRes.json();
    const phishingAssertion = buildMockAssertion(privateKey, rpId, originOptData.challenge, 'https://phishing.evil-bank.com', 3);

    const originRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: phishingAssertion.clientDataJSONB64,
            authenticatorData: phishingAssertion.authenticatorDataB64,
            signature: phishingAssertion.signatureB64
          }
        }
      })
    });
    assert.strictEqual(originRes.status, 400);
    const originData = await originRes.json();
    assert.strictEqual(originData.verified, false);
    assert.ok(originData.error.includes('Origin mismatch'));
    console.log('  ✅ [PASS] 7. Negative: Origin mismatch rejected');
    passed++;

    // -------------------------------------------------------------------------
    // Test 8: Negative - Cloned Authenticator (Counter did not increment)
    // -------------------------------------------------------------------------
    const cloneOptRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
    const cloneOptData = await cloneOptRes.json();
    // Stored counter is 1 from Test 4; sending counter 1 again simulates cloned device
    const cloneAssertion = buildMockAssertion(privateKey, rpId, cloneOptData.challenge, origin, 1);

    const cloneRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: cloneAssertion.clientDataJSONB64,
            authenticatorData: cloneAssertion.authenticatorDataB64,
            signature: cloneAssertion.signatureB64
          }
        }
      })
    });
    assert.strictEqual(cloneRes.status, 400);
    const cloneData = await cloneRes.json();
    assert.strictEqual(cloneData.verified, false);
    assert.ok(cloneData.error.includes('Cloned authenticator'));
    console.log('  ✅ [PASS] 8. Negative: Cloned authenticator counter stagnation rejected');
    passed++;

    // -------------------------------------------------------------------------
    // Test 9: Negative - Wrong Event Type in clientDataJSON
    // -------------------------------------------------------------------------
    const wrongTypeOptRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
    const wrongTypeOptData = await wrongTypeOptRes.json();
    const wrongTypeAssertion = buildMockAssertion(privateKey, rpId, wrongTypeOptData.challenge, origin, 4, 'webauthn.create');

    const wrongTypeRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: wrongTypeAssertion.clientDataJSONB64,
            authenticatorData: wrongTypeAssertion.authenticatorDataB64,
            signature: wrongTypeAssertion.signatureB64
          }
        }
      })
    });
    assert.strictEqual(wrongTypeRes.status, 400);
    console.log('  ✅ [PASS] 9. Negative: Wrong event type rejected');
    passed++;

    // -------------------------------------------------------------------------
    // Test 10: Negative - Malformed clientDataJSON
    // -------------------------------------------------------------------------
    const malformedRes = await fetch(`${baseUrl}/api/webauthn/register-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credential: {
          id: 'bad_cred',
          response: { clientDataJSON: 'NOT_VALID_BASE64_!@#$' }
        }
      })
    });
    assert.strictEqual(malformedRes.status, 400);
    console.log('  ✅ [PASS] 10. Negative: Malformed clientDataJSON rejected with 400');
    passed++;

    // -------------------------------------------------------------------------
    // Test 11: Negative - Unregistered Credential ID
    // -------------------------------------------------------------------------
    const unregAssertion = buildMockAssertion(privateKey, rpId, 'dummy_challenge', origin, 5);
    const unregRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId: 'non_existent_credential_id',
        assertion: {
          id: 'non_existent_credential_id',
          response: {
            clientDataJSON: unregAssertion.clientDataJSONB64,
            authenticatorData: unregAssertion.authenticatorDataB64,
            signature: unregAssertion.signatureB64
          }
        }
      })
    });
    assert.strictEqual(unregRes.status, 400);
    const unregData = await unregRes.json();
    assert.strictEqual(unregData.verified, false);
    assert.ok(unregData.error.includes('Credential not found'));
    console.log('  ✅ [PASS] 11. Negative: Unregistered credential ID rejected');
    passed++;

    console.log('======================================================================');
    console.log(`📊 WEBAUTHN TEST SUMMARY: ${passed} PASSED | ${failed} FAILED (100% Pass Rate)`);
    console.log('======================================================================');

    server.close();
    if (failed > 0) process.exit(1);
  } catch (err) {
    console.error('Unhandled test failure:', err);
    server.close();
    process.exit(1);
  }
}

runWebAuthnTests();
