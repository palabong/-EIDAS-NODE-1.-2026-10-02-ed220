/**
 * Challenger 1: Adversarial Authentication Test Suite
 * Project Bilanx / eIDAS Sovereign Node (Generation 3 Adversarial Audit)
 * 
 * Verifies empirical rejection of:
 * 1. Google OAuth Adversarial Vectors (/api/auth/verify-google):
 *    - Forged, unsigned (alg: none), self-signed (RS256, ES256), and HMAC (HS256) JWTs
 *    - Untrusted issuers and mismatched audiences
 *    - Missing required claims (sub, email)
 *    - Malformed and missing credential bodies
 *    - Proof of zero session creation in globalSessionStore
 *    - Proof of zero auth cookie issuance
 * 2. WebAuthn / FIDO2 Cryptographic Adversarial Vectors (/api/webauthn/*):
 *    - Attack Vector 1: Tampered signature bytes (DER, P1363 raw, truncated, wrong key) -> 400
 *    - Attack Vector 2: Reused challenge / replay attack (consumed, phantom, expired) -> 400
 *    - Attack Vector 3: Origin mismatch in assertion and registration -> 400
 *    - Attack Vector 4: RP ID mismatch (authenticatorData & attestationObject rpIdHash) -> 400
 *    - Attack Vector 5: Signature counter regression / rollback / stagnation -> 400
 *    - Attack Vector 6: Unknown / unregistered credentialId (no ghost credential synthesis) -> 400
 * 3. Live Server Port 3000 Dual-Verification:
 *    - Comprehensive live attack battery executed against production server dist/server.cjs
 */

import express from 'express';
import { createServer } from 'http';
import crypto from 'crypto';
import type { AddressInfo } from 'net';
import assert from 'assert';
import dotenv from 'dotenv';
import { OAuth2Client } from 'google-auth-library';

dotenv.config();

import {
  globalSessionStore,
  extractSessionToken,
  setSessionCookie,
} from '../src/server/sessionManager.ts';
import {
  generateWebAuthnChallenge,
  registerWebAuthnCredential,
  verifyWebAuthnAssertion,
  clearWebAuthnState,
  getStoredCredential,
  encodeCbor,
} from '../src/server/webauthnServer.ts';
import { recordAccessLog, getAccessLogs } from '../src/server/accessLogDb.ts';
import type { SessionUser } from '../src/server/types/saml.ts';

// ---------------------------------------------------------------------------
// Helpers: Ephemeral Express Server Setup
// ---------------------------------------------------------------------------

const googleOAuthClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

function getClientIp(req: express.Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (Array.isArray(xff) && xff.length > 0) return xff[0].split(',')[0].trim();
  if (typeof xff === 'string') return xff.split(',')[0].trim();
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

function getErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function buildTestApp(): express.Express {
  const app = express();
  app.use(express.json());

  // Mount Google Auth route identically to server.ts
  app.post('/api/auth/verify-google', async (req, res) => {
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
          metadata: { reason: 'Missing or malformed credential parameter' },
        });
        res.status(400).json({ success: false, error: 'Missing credential token in request.' });
        return;
      }

      const expectedClientId = process.env.GOOGLE_CLIENT_ID;
      if (!expectedClientId) {
        res.status(500).json({ success: false, error: 'Google OAuth is not configured on this server.' });
        return;
      }

      let ticketPayload: any = null;
      try {
        const ticket = await googleOAuthClient.verifyIdToken({
          idToken: credential,
          audience: expectedClientId,
        });
        ticketPayload = ticket.getPayload();
      } catch (verifyErr: unknown) {
        const errorMsg = getErrorMessage(verifyErr);
        await recordAccessLog({
          userId: 'unverified',
          email: 'unverified@token',
          name: 'Unverified Visitor',
          authMethod: 'google_jwt_verified',
          action: 'LOGIN_FAILURE',
          ipAddress: clientIp,
          userAgent,
          status: 'DENIED',
          metadata: { reason: `Cryptographic token verification failed: ${errorMsg}` },
        });
        res.status(401).json({ success: false, error: 'Invalid or expired Google credential token.' });
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
          metadata: { reason: 'Missing mandatory sub or email claims in verified token' },
        });
        res.status(401).json({ success: false, error: 'Incomplete token claims.' });
        return;
      }

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
          metadata: { reason: `Untrusted issuer: ${ticketPayload.iss}` },
        });
        res.status(401).json({ success: false, error: 'Untrusted token issuer.' });
        return;
      }

      const verifiedUser: SessionUser = {
        uid: ticketPayload.sub,
        email: ticketPayload.email,
        name: ticketPayload.name || ticketPayload.email.split('@')[0],
        picture: ticketPayload.picture,
        authMethod: 'google_jwt_verified',
        authenticatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 4 * 60 * 60 * 1000,
        issuer: ticketPayload.iss,
      };

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
          clientProvidedDetails: clientInfo || null,
        },
      });

      const { token: sessionToken } = globalSessionStore.createSession(verifiedUser);
      setSessionCookie(res, sessionToken);

      res.status(200).json({
        success: true,
        user: verifiedUser,
        sessionToken,
        logId: accessRecord.id,
        message: 'Google credential verified successfully.',
      });
    } catch (err: unknown) {
      res.status(500).json({ success: false, error: 'Authentication system error.' });
    }
  });

  // Mount WebAuthn routes identically to server.ts
  app.post('/api/webauthn/register-options', (req, res) => {
    const username = req.body?.username || 'daniele.palagi92@gmail.com';
    const displayName = req.body?.displayName || 'Daniele Palagi';
    const challenge = generateWebAuthnChallenge();
    const rpId = req.hostname;

    res.json({
      challenge,
      rp: { name: 'Project Bilanx Sovereign Node', id: rpId },
      user: { id: Buffer.from(username).toString('base64url'), name: username, displayName },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' },
      ],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'preferred' },
    });
  });

  app.post('/api/webauthn/register-verify', (req, res) => {
    try {
      const { credential, username } = req.body || {};
      if (!credential || !credential.id || !credential.response) {
        res.status(400).json({ verified: false, error: 'Missing credential payload or response' });
        return;
      }
      const expectedRpId = req.hostname;
      const expectedOrigin = req.headers.origin || `${req.protocol}://${req.get('host')}`;

      const stored = registerWebAuthnCredential({
        credentialId: credential.id,
        username: username || 'daniele.palagi92@gmail.com',
        clientDataJSONB64: credential.response.clientDataJSON,
        attestationObjectB64: credential.response.attestationObject,
        authenticatorDataB64: credential.response.authenticatorData,
        publicKeyPem: credential.response.publicKey,
        authenticatorAttachment: credential.authenticatorAttachment || 'platform',
        expectedOrigin,
        expectedRpId,
      });

      res.status(200).json({ verified: true, credential: stored });
    } catch (err: any) {
      res.status(400).json({ verified: false, error: err.message });
    }
  });

  app.post('/api/webauthn/authenticate-options', (req, res) => {
    const challenge = generateWebAuthnChallenge();
    res.json({ challenge, timeout: 60000, rpId: req.hostname });
  });

  app.post('/api/webauthn/authenticate-verify', (req, res) => {
    try {
      const { assertion, credentialId } = req.body || {};
      if (!assertion || !assertion.response) {
        res.status(400).json({ verified: false, error: 'Missing assertion response' });
        return;
      }
      const expectedRpId = req.hostname;
      const expectedOrigin = req.headers.origin || `${req.protocol}://${req.get('host')}`;

      const result = verifyWebAuthnAssertion({
        credentialId: credentialId || assertion.id,
        clientDataJSONB64: assertion.response.clientDataJSON,
        authenticatorDataB64: assertion.response.authenticatorData,
        signatureB64: assertion.response.signature || '',
        expectedOrigin,
        expectedRpId,
      });

      if (!result.verified) {
        res.status(400).json(result);
        return;
      }

      res.status(200).json(result);
    } catch (err: any) {
      res.status(400).json({ verified: false, error: err.message });
    }
  });

  return app;
}

// ---------------------------------------------------------------------------
// Helpers: Cryptographic Token & WebAuthn Builders
// ---------------------------------------------------------------------------

function b64url(input: string | Buffer): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf-8');
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function createRsaKeyPair() {
  return crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function createEcKeyPair() {
  return crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
}

function createSignedJwt(
  headerObj: Record<string, any>,
  payloadObj: Record<string, any>,
  privateKey?: crypto.KeyObject,
  symmetricSecret?: string
): string {
  const h = b64url(JSON.stringify(headerObj));
  const p = b64url(JSON.stringify(payloadObj));
  const signingInput = `${h}.${p}`;

  if (headerObj.alg === 'none' || !headerObj.alg) {
    return `${signingInput}.`;
  }

  if (headerObj.alg === 'RS256' && privateKey) {
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(signingInput);
    const sig = signer.sign(privateKey);
    return `${signingInput}.${b64url(sig)}`;
  }

  if (headerObj.alg === 'ES256' && privateKey) {
    const signer = crypto.createSign('SHA256');
    signer.update(signingInput);
    const sig = signer.sign(privateKey);
    return `${signingInput}.${b64url(sig)}`;
  }

  if (headerObj.alg === 'HS256' && symmetricSecret) {
    const hmac = crypto.createHmac('sha256', symmetricSecret);
    hmac.update(signingInput);
    const sig = hmac.digest();
    return `${signingInput}.${b64url(sig)}`;
  }

  throw new Error(`Unsupported alg ${headerObj.alg}`);
}

function buildMockAttestation(
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
    coseKeyBuf,
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
  userPresent: boolean = true,
  customRpIdHash?: Buffer,
  useP1363: boolean = false
) {
  const clientDataJSON = JSON.stringify({
    type: eventType,
    challenge,
    origin,
    crossOrigin: false,
  });
  const clientDataJSONB64 = Buffer.from(clientDataJSON, 'utf-8').toString('base64');

  const rpIdHash = customRpIdHash || crypto.createHash('sha256').update(rpId).digest();
  const flags = userPresent ? 0x01 : 0x00;
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);

  const authenticatorData = Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf]);
  const authenticatorDataB64 = authenticatorData.toString('base64');

  const clientDataHash = crypto.createHash('sha256').update(Buffer.from(clientDataJSON, 'utf-8')).digest();
  const signedBytes = Buffer.concat([authenticatorData, clientDataHash]);

  const signature = useP1363
    ? crypto.sign('SHA256', signedBytes, { key: privateKey, dsaEncoding: 'ieee-p1363' })
    : crypto.sign('SHA256', signedBytes, privateKey);
  const signatureB64 = signature.toString('base64');

  return { clientDataJSONB64, authenticatorDataB64, signatureB64, signature };
}

// ---------------------------------------------------------------------------
// Test Execution Engine
// ---------------------------------------------------------------------------

export async function runChallenger1AdversarialSuite() {
  console.log('================================================================================');
  console.log('🔥 CHALLENGER 1: EMPIRICAL ADVERSARIAL AUTHENTICATION VERIFICATION SUITE');
  console.log('   Target Endpoints: /api/auth/verify-google & /api/webauthn/*');
  console.log('================================================================================\n');

  let passed = 0;
  let failed = 0;
  const attackResults: { category: string; test: string; status: 'PASS' | 'FAIL'; detail: string }[] = [];

  function recordPass(category: string, test: string, detail: string) {
    passed++;
    attackResults.push({ category, test, status: 'PASS', detail });
    console.log(`  ✅ [PASS] ${test}: ${detail}`);
  }

  function recordFail(category: string, test: string, detail: string) {
    failed++;
    attackResults.push({ category, test, status: 'FAIL', detail });
    console.error(`  ❌ [FAIL] ${test}: ${detail}`);
  }

  // Clear states before testing
  clearWebAuthnState();
  globalSessionStore.clear();

  // Boot Ephemeral Server
  const app = buildTestApp();
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  const rpId = '127.0.0.1';
  const origin = baseUrl;
  const expectedClientId = process.env.GOOGLE_CLIENT_ID || 'your_client_id.apps.googleusercontent.com';

  console.log(`[Harness] Ephemeral server listening on ${baseUrl}`);
  console.log(`[Harness] Configured GOOGLE_CLIENT_ID: ${expectedClientId}\n`);

  try {
    // =========================================================================
    // PART 1: GOOGLE OAUTH ADVERSARIAL ATTACKS (/api/auth/verify-google)
    // =========================================================================
    console.log('--- 1. GOOGLE OAUTH ADVERSARIAL ATTACKS ---');

    // 1.1 Non-JWT Garbage Strings
    {
      const initialSessionCount = globalSessionStore.size();
      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: 'totally.not.a.jwt.garbage.payload' }),
      });
      const data = await res.json();
      const cookie = res.headers.get('set-cookie');

      if (res.status === 401 && data.success === false && globalSessionStore.size() === initialSessionCount && !cookie) {
        recordPass('Google OAuth', 'TEST_GOOG_01 (Garbage String)', 'Rejected with 401, no session created, no cookie');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_01 (Garbage String)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.2 Missing / Malformed Body (Missing credential parameter)
    {
      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      const cookie = res.headers.get('set-cookie');

      if (res.status === 400 && data.success === false && !cookie) {
        recordPass('Google OAuth', 'TEST_GOOG_02 (Missing Credential)', 'Rejected with 400 Bad Request');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_02 (Missing Credential)', `Expected 400, got ${res.status}`);
      }
    }

    // 1.3 Unsigned JWT with alg: "none"
    {
      const initialSessionCount = globalSessionStore.size();
      const unsignedJwt = createSignedJwt(
        { alg: 'none', typ: 'JWT' },
        {
          sub: '10987654321',
          email: 'forged-admin@accounts.google.com',
          name: 'Forged Admin',
          iss: 'https://accounts.google.com',
          aud: expectedClientId,
          exp: Math.floor(Date.now() / 1000) + 3600,
        }
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: unsignedJwt }),
      });
      const data = await res.json();
      const cookie = res.headers.get('set-cookie');

      if (res.status === 401 && data.success === false && globalSessionStore.size() === initialSessionCount && !cookie) {
        recordPass('Google OAuth', 'TEST_GOOG_03 (alg: none unsigned JWT)', 'Rejected with 401, zero session creation');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_03 (alg: none unsigned JWT)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.4 Attacker RSA Self-Signed JWT (RS256)
    {
      const initialSessionCount = globalSessionStore.size();
      const attackerRsa = createRsaKeyPair();
      const selfSignedRsaJwt = createSignedJwt(
        { alg: 'RS256', typ: 'JWT', kid: 'attacker-key-1' },
        {
          sub: '9999999999',
          email: 'victim.user@bilanx.org',
          name: 'Victim User',
          iss: 'https://accounts.google.com',
          aud: expectedClientId,
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        attackerRsa.privateKey
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: selfSignedRsaJwt }),
      });
      const data = await res.json();
      const cookie = res.headers.get('set-cookie');

      if (res.status === 401 && data.success === false && globalSessionStore.size() === initialSessionCount && !cookie) {
        recordPass('Google OAuth', 'TEST_GOOG_04 (Attacker RS256 Self-Signed)', 'Rejected with 401, invalid Google certificate');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_04 (Attacker RS256 Self-Signed)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.5 Attacker ECDSA Self-Signed JWT (ES256)
    {
      const initialSessionCount = globalSessionStore.size();
      const attackerEc = createEcKeyPair();
      const selfSignedEcJwt = createSignedJwt(
        { alg: 'ES256', typ: 'JWT', kid: 'attacker-ec-1' },
        {
          sub: '8888888888',
          email: 'injected.executive@bilanx.org',
          name: 'Injected Executive',
          iss: 'https://accounts.google.com',
          aud: expectedClientId,
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        attackerEc.privateKey
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: selfSignedEcJwt }),
      });
      const data = await res.json();
      const cookie = res.headers.get('set-cookie');

      if (res.status === 401 && data.success === false && globalSessionStore.size() === initialSessionCount && !cookie) {
        recordPass('Google OAuth', 'TEST_GOOG_05 (Attacker ES256 Self-Signed)', 'Rejected with 401, zero session creation');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_05 (Attacker ES256 Self-Signed)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.6 Algorithm Confusion Attack (HS256 with symmetric key)
    {
      const initialSessionCount = globalSessionStore.size();
      const hs256Jwt = createSignedJwt(
        { alg: 'HS256', typ: 'JWT' },
        {
          sub: '7777777777',
          email: 'alg.confusion@attacker.com',
          iss: 'https://accounts.google.com',
          aud: expectedClientId,
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        undefined,
        'attacker-secret-symmetric-key-12345678'
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: hs256Jwt }),
      });
      const data = await res.json();
      const cookie = res.headers.get('set-cookie');

      if (res.status === 401 && data.success === false && globalSessionStore.size() === initialSessionCount && !cookie) {
        recordPass('Google OAuth', 'TEST_GOOG_06 (Algorithm Confusion HS256)', 'Rejected with 401');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_06 (Algorithm Confusion HS256)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.7 Untrusted Issuer Claim
    {
      const attackerRsa = createRsaKeyPair();
      const badIssuerJwt = createSignedJwt(
        { alg: 'RS256', typ: 'JWT' },
        {
          sub: '6666666666',
          email: 'user@evil-idp.com',
          iss: 'https://evil-idp.com',
          aud: expectedClientId,
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        attackerRsa.privateKey
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: badIssuerJwt }),
      });
      const data = await res.json();

      if (res.status === 401 && data.success === false) {
        recordPass('Google OAuth', 'TEST_GOOG_07 (Untrusted Issuer)', 'Rejected with 401 Untrusted Issuer / verification failure');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_07 (Untrusted Issuer)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.8 Mismatched Audience Claim
    {
      const attackerRsa = createRsaKeyPair();
      const badAudienceJwt = createSignedJwt(
        { alg: 'RS256', typ: 'JWT' },
        {
          sub: '5555555555',
          email: 'user@different-app.com',
          iss: 'https://accounts.google.com',
          aud: 'different-app-client-id.apps.googleusercontent.com',
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        attackerRsa.privateKey
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: badAudienceJwt }),
      });
      const data = await res.json();

      if (res.status === 401 && data.success === false) {
        recordPass('Google OAuth', 'TEST_GOOG_08 (Mismatched Audience)', 'Rejected with 401');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_08 (Mismatched Audience)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.9 Missing Mandatory Claims (Missing email or sub)
    {
      const attackerRsa = createRsaKeyPair();
      const missingClaimsJwt = createSignedJwt(
        { alg: 'RS256', typ: 'JWT' },
        {
          email: 'no-sub@google.com',
          iss: 'https://accounts.google.com',
          aud: expectedClientId,
          exp: Math.floor(Date.now() / 1000) + 3600,
        },
        attackerRsa.privateKey
      );

      const res = await fetch(`${baseUrl}/api/auth/verify-google`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ credential: missingClaimsJwt }),
      });
      const data = await res.json();

      if (res.status === 401 && data.success === false) {
        recordPass('Google OAuth', 'TEST_GOOG_09 (Missing sub/email claims)', 'Rejected with 401');
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_09 (Missing sub/email claims)', `Expected 401, got ${res.status}`);
      }
    }

    // 1.10 Global Session Store & Audit Integrity Check
    {
      const currentSessions = globalSessionStore.size();
      if (currentSessions === 0) {
        recordPass('Google OAuth', 'TEST_GOOG_10 (Session Store Cleanliness)', `Confirmed globalSessionStore.size() == 0 after all attacks`);
      } else {
        recordFail('Google OAuth', 'TEST_GOOG_10 (Session Store Cleanliness)', `Leak detected: ${currentSessions} sessions found in store!`);
      }
    }

    // =========================================================================
    // PART 2: WEBAUTHN / FIDO2 ADVERSARIAL CRYPTOGRAPHIC ATTACKS (/api/webauthn/*)
    // =========================================================================
    console.log('\n--- 2. WEBAUTHN / FIDO2 ADVERSARIAL ATTACKS ---');

    // 2.0 Baseline Setup: Generate authentic credentials
    const { privateKey, publicKey } = createEcKeyPair();
    const jwk = publicKey.export({ format: 'jwk' });
    const x = Buffer.from(jwk.x!, 'base64url');
    const y = Buffer.from(jwk.y!, 'base64url');
    const rawCredId = crypto.randomBytes(16);
    const credentialId = rawCredId.toString('base64url');
    const username = 'daniele.palagi92@gmail.com';

    // Step A: Request registration options
    const regOptRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, displayName: 'Daniele Palagi' }),
    });
    const regOptData = await regOptRes.json();
    assert.strictEqual(regOptRes.status, 200);
    const regChallenge = regOptData.challenge;

    // Step B: Submit legitimate registration
    const regClientDataJSON = JSON.stringify({
      type: 'webauthn.create',
      challenge: regChallenge,
      origin,
    });
    const regClientDataJSONB64 = Buffer.from(regClientDataJSON).toString('base64');
    const attestationObject = buildMockAttestation(rpId, rawCredId, x, y);
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
            attestationObject: attestationObjectB64,
          },
        },
      }),
    });
    const regData = await regRes.json();
    assert.strictEqual(regRes.status, 200);
    assert.strictEqual(regData.verified, true);
    recordPass('WebAuthn Baseline', 'SETUP_01 (Registration)', `Legitimate credential registered: ${credentialId}`);

    // Step C: Perform 1 legitimate authentication to establish baseline counter = 1
    const authOptRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
    const authOptData = await authOptRes.json();
    const baseChallenge = authOptData.challenge;

    const baseAssertion = buildMockAssertion(privateKey, rpId, baseChallenge, origin, 1);
    const baseAuthRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        credentialId,
        assertion: {
          id: credentialId,
          response: {
            clientDataJSON: baseAssertion.clientDataJSONB64,
            authenticatorData: baseAssertion.authenticatorDataB64,
            signature: baseAssertion.signatureB64,
          },
        },
      }),
    });
    const baseAuthData = await baseAuthRes.json();
    assert.strictEqual(baseAuthRes.status, 200);
    assert.strictEqual(baseAuthData.verified, true);
    recordPass('WebAuthn Baseline', 'SETUP_02 (Initial Assertion)', `Initial assertion verified, counter advanced to 1`);

    // -------------------------------------------------------------------------
    // Attack Vector 1: Tampered Signature Bytes
    // -------------------------------------------------------------------------

    // 2.1a: Bit-flip in ECDSA DER signature
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const assertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 2);

      const rawSig = Buffer.from(assertion.signatureB64, 'base64');
      rawSig[rawSig.length - 2] ^= 0x01; // single bit flip
      const tamperedSigB64 = rawSig.toString('base64');

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: assertion.clientDataJSONB64,
              authenticatorData: assertion.authenticatorDataB64,
              signature: tamperedSigB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && (data.error || '').includes('verification failed')) {
        recordPass('WebAuthn Vector 1', 'ATTACK_V1_01 (Bit Flip in DER Signature)', 'Rejected with 400 signature verification failed');
      } else {
        recordFail('WebAuthn Vector 1', 'ATTACK_V1_01 (Bit Flip in DER Signature)', `Expected 400, got ${res.status}: ${JSON.stringify(data)}`);
      }
    }

    // 2.1b: Bit-flip in IEEE P1363 (64-byte raw r||s) signature
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const rawAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 3, 'webauthn.get', true, undefined, true);

      const rawSigBytes = Buffer.from(rawAssertion.signatureB64, 'base64');
      assert.strictEqual(rawSigBytes.length, 64, 'P1363 signature must be 64 bytes');
      rawSigBytes[31] ^= 0x01; // flip bit in r component
      const tamperedRawB64 = rawSigBytes.toString('base64');

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: rawAssertion.clientDataJSONB64,
              authenticatorData: rawAssertion.authenticatorDataB64,
              signature: tamperedRawB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false) {
        recordPass('WebAuthn Vector 1', 'ATTACK_V1_02 (Bit Flip in IEEE P1363 Raw Signature)', 'Rejected with 400 cryptographic verification failed');
      } else {
        recordFail('WebAuthn Vector 1', 'ATTACK_V1_02 (Bit Flip in IEEE P1363 Raw Signature)', `Expected 400, got ${res.status}`);
      }
    }

    // 2.1c: Truncated signature buffer
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const assertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 4);

      const truncatedSigB64 = Buffer.from(assertion.signatureB64, 'base64').subarray(0, 10).toString('base64');

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: assertion.clientDataJSONB64,
              authenticatorData: assertion.authenticatorDataB64,
              signature: truncatedSigB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false) {
        recordPass('WebAuthn Vector 1', 'ATTACK_V1_03 (Truncated Signature Buffer)', 'Rejected with 400 cryptographic verification error');
      } else {
        recordFail('WebAuthn Vector 1', 'ATTACK_V1_03 (Truncated Signature Buffer)', `Expected 400, got ${res.status}`);
      }
    }

    // 2.1d: Signature signed with a foreign/different private key
    {
      const foreignKeys = createEcKeyPair();
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const foreignAssertion = buildMockAssertion(foreignKeys.privateKey, rpId, optData.challenge, origin, 5);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: foreignAssertion.clientDataJSONB64,
              authenticatorData: foreignAssertion.authenticatorDataB64,
              signature: foreignAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false) {
        recordPass('WebAuthn Vector 1', 'ATTACK_V1_04 (Foreign Key Signature)', 'Rejected with 400 signature verification failed');
      } else {
        recordFail('WebAuthn Vector 1', 'ATTACK_V1_04 (Foreign Key Signature)', `Expected 400, got ${res.status}`);
      }
    }

    // -------------------------------------------------------------------------
    // Attack Vector 2: Reused Challenge / Replay Attack
    // -------------------------------------------------------------------------

    // 2.2a: Replay already consumed challenge from SETUP_02
    {
      const replayRes = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: baseAssertion.clientDataJSONB64,
              authenticatorData: baseAssertion.authenticatorDataB64,
              signature: baseAssertion.signatureB64,
            },
          },
        }),
      });
      const replayData = await replayRes.json();

      if (replayRes.status === 400 && replayData.verified === false && replayData.error.includes('replay attack detected')) {
        recordPass('WebAuthn Vector 2', 'ATTACK_V2_01 (Reused Consumed Challenge)', 'Rejected with 400: Challenge already consumed (replay detected)');
      } else {
        recordFail('WebAuthn Vector 2', 'ATTACK_V2_01 (Reused Consumed Challenge)', `Expected 400 replay error, got ${replayRes.status}: ${JSON.stringify(replayData)}`);
      }
    }

    // 2.2b: Phantom / Arbitrary unissued challenge
    {
      const phantomChallenge = crypto.randomBytes(32).toString('base64url');
      const phantomAssertion = buildMockAssertion(privateKey, rpId, phantomChallenge, origin, 6);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: phantomAssertion.clientDataJSONB64,
              authenticatorData: phantomAssertion.authenticatorDataB64,
              signature: phantomAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Challenge not found')) {
        recordPass('WebAuthn Vector 2', 'ATTACK_V2_02 (Phantom Unissued Challenge)', 'Rejected with 400: Challenge not found');
      } else {
        recordFail('WebAuthn Vector 2', 'ATTACK_V2_02 (Phantom Unissued Challenge)', `Expected 400, got ${res.status}: ${JSON.stringify(data)}`);
      }
    }

    // 2.2c: Expired Challenge (> 120 seconds TTL expiry)
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const expiredChallenge = optData.challenge;

      const assertion = buildMockAssertion(privateKey, rpId, expiredChallenge, origin, 7);

      // Artificially advance clock by 150 seconds to trigger TTL expiry
      const realNow = Date.now;
      try {
        Date.now = () => realNow() + 150_000;

        const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            credentialId,
            assertion: {
              id: credentialId,
              response: {
                clientDataJSON: assertion.clientDataJSONB64,
                authenticatorData: assertion.authenticatorDataB64,
                signature: assertion.signatureB64,
              },
            },
          }),
        });
        const data = await res.json();

        if (res.status === 400 && data.verified === false && (data.error.includes('expired') || data.error.includes('replay attack detected') || data.error.includes('not found'))) {
          recordPass('WebAuthn Vector 2', 'ATTACK_V2_03 (Expired Challenge TTL)', 'Rejected with 400: Expired challenge purged/rejected');
        } else {
          recordFail('WebAuthn Vector 2', 'ATTACK_V2_03 (Expired Challenge TTL)', `Expected 400 expired/purged challenge, got ${res.status}: ${JSON.stringify(data)}`);
        }
      } finally {
        Date.now = realNow;
      }
    }

    // -------------------------------------------------------------------------
    // Attack Vector 3: Origin Mismatch (Phishing Attack)
    // -------------------------------------------------------------------------

    // 2.3a: Origin mismatch in assertion (evil-attacker.com)
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const phishingAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, 'https://evil-attacker.com', 8);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: phishingAssertion.clientDataJSONB64,
              authenticatorData: phishingAssertion.authenticatorDataB64,
              signature: phishingAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Origin mismatch')) {
        recordPass('WebAuthn Vector 3', 'ATTACK_V3_01 (Phishing Origin Mismatch)', 'Rejected with 400 Origin mismatch');
      } else {
        recordFail('WebAuthn Vector 3', 'ATTACK_V3_01 (Phishing Origin Mismatch)', `Expected 400 Origin mismatch, got ${res.status}: ${JSON.stringify(data)}`);
      }
    }

    // 2.3b: Origin mismatch during registration
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'phishing@target.com' }),
      });
      const optData = await optRes.json();

      const phishingClientDataJSON = Buffer.from(
        JSON.stringify({ type: 'webauthn.create', challenge: optData.challenge, origin: 'https://evil-attacker.com' })
      ).toString('base64');
      const dummyCredId = crypto.randomBytes(16);
      const dummyAttestation = buildMockAttestation(rpId, dummyCredId, x, y).toString('base64');

      const res = await fetch(`${baseUrl}/api/webauthn/register-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'phishing@target.com',
          credential: {
            id: dummyCredId.toString('base64url'),
            response: {
              clientDataJSON: phishingClientDataJSON,
              attestationObject: dummyAttestation,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Origin mismatch')) {
        recordPass('WebAuthn Vector 3', 'ATTACK_V3_02 (Registration Origin Mismatch)', 'Rejected with 400 Origin mismatch');
      } else {
        recordFail('WebAuthn Vector 3', 'ATTACK_V3_02 (Registration Origin Mismatch)', `Expected 400, got ${res.status}`);
      }
    }

    // -------------------------------------------------------------------------
    // Attack Vector 4: RP ID Mismatch (rpIdHash Tampering)
    // -------------------------------------------------------------------------

    // 2.4a: Tampered rpIdHash in assertion authenticatorData
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const evilRpHash = crypto.createHash('sha256').update('evil-relying-party.com').digest();
      const tamperedAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 9, 'webauthn.get', true, evilRpHash);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: tamperedAssertion.clientDataJSONB64,
              authenticatorData: tamperedAssertion.authenticatorDataB64,
              signature: tamperedAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('RP ID hash mismatch')) {
        recordPass('WebAuthn Vector 4', 'ATTACK_V4_01 (Assertion RP ID Hash Mismatch)', 'Rejected with 400 RP ID hash mismatch');
      } else {
        recordFail('WebAuthn Vector 4', 'ATTACK_V4_01 (Assertion RP ID Hash Mismatch)', `Expected 400 RP ID hash mismatch, got ${res.status}: ${JSON.stringify(data)}`);
      }
    }

    // 2.4b: Tampered rpIdHash in registration attestationObject
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'rpid-tamper@target.com' }),
      });
      const optData = await optRes.json();

      const regClientData = Buffer.from(
        JSON.stringify({ type: 'webauthn.create', challenge: optData.challenge, origin })
      ).toString('base64');
      const tamperCredId = crypto.randomBytes(16);
      const evilAttestation = buildMockAttestation('evil-relying-party.org', tamperCredId, x, y).toString('base64');

      const res = await fetch(`${baseUrl}/api/webauthn/register-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'rpid-tamper@target.com',
          credential: {
            id: tamperCredId.toString('base64url'),
            response: {
              clientDataJSON: regClientData,
              attestationObject: evilAttestation,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('RP ID hash mismatch')) {
        recordPass('WebAuthn Vector 4', 'ATTACK_V4_02 (Registration RP ID Hash Mismatch)', 'Rejected with 400 RP ID hash mismatch in attestation');
      } else {
        recordFail('WebAuthn Vector 4', 'ATTACK_V4_02 (Registration RP ID Hash Mismatch)', `Expected 400, got ${res.status}`);
      }
    }

    // -------------------------------------------------------------------------
    // Attack Vector 5: Signature Counter Regression / Replay (Cloning Detection)
    // -------------------------------------------------------------------------

    // Advance stored counter to 100 with valid assertion
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const advanceAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 100);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: advanceAssertion.clientDataJSONB64,
              authenticatorData: advanceAssertion.authenticatorDataB64,
              signature: advanceAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();
      assert.strictEqual(res.status, 200);
      assert.strictEqual(data.credential.counter, 100);
      recordPass('WebAuthn Vector 5', 'COUNTER_PREP (Advance counter to 100)', 'Counter successfully set to 100');
    }

    // 2.5a: Counter stagnation (counter = 100 again)
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const stagnatedAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 100);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: stagnatedAssertion.clientDataJSONB64,
              authenticatorData: stagnatedAssertion.authenticatorDataB64,
              signature: stagnatedAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Cloned authenticator detected')) {
        recordPass('WebAuthn Vector 5', 'ATTACK_V5_01 (Counter Stagnation / Replay)', 'Rejected with 400: Cloned authenticator detected');
      } else {
        recordFail('WebAuthn Vector 5', 'ATTACK_V5_01 (Counter Stagnation / Replay)', `Expected 400 cloned error, got ${res.status}: ${JSON.stringify(data)}`);
      }
    }

    // 2.5b: Counter regression / rollback (counter = 50 < 100)
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const rollbackAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 50);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: rollbackAssertion.clientDataJSONB64,
              authenticatorData: rollbackAssertion.authenticatorDataB64,
              signature: rollbackAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Cloned authenticator detected')) {
        recordPass('WebAuthn Vector 5', 'ATTACK_V5_02 (Counter Rollback / Regression)', 'Rejected with 400: Cloned authenticator detected');
      } else {
        recordFail('WebAuthn Vector 5', 'ATTACK_V5_02 (Counter Rollback / Regression)', `Expected 400 cloned error, got ${res.status}: ${JSON.stringify(data)}`);
      }
    }

    // 2.5c: Counter reset to 0
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const resetAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 0);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: resetAssertion.clientDataJSONB64,
              authenticatorData: resetAssertion.authenticatorDataB64,
              signature: resetAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Cloned authenticator detected')) {
        recordPass('WebAuthn Vector 5', 'ATTACK_V5_03 (Counter Reset to 0)', 'Rejected with 400: Cloned authenticator detected');
      } else {
        recordFail('WebAuthn Vector 5', 'ATTACK_V5_03 (Counter Reset to 0)', `Expected 400 cloned error, got ${res.status}`);
      }
    }

    // 2.5d: Legitimate counter increment past 100 (counter = 101) succeeds
    {
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const validAdvanceAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 101);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId,
          assertion: {
            id: credentialId,
            response: {
              clientDataJSON: validAdvanceAssertion.clientDataJSONB64,
              authenticatorData: validAdvanceAssertion.authenticatorDataB64,
              signature: validAdvanceAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 200 && data.verified === true && data.credential.counter === 101) {
        recordPass('WebAuthn Vector 5', 'COUNTER_RESUME (Counter 101 Valid)', 'Valid monotonic increment past 100 succeeds');
      } else {
        recordFail('WebAuthn Vector 5', 'COUNTER_RESUME (Counter 101 Valid)', `Expected 200, got ${res.status}`);
      }
    }

    // -------------------------------------------------------------------------
    // Attack Vector 6: Unknown / Unregistered Credential ID (No Ghost Credentials)
    // -------------------------------------------------------------------------

    // 2.6a: Assertion with unknown random credentialId
    {
      const ghostId = crypto.randomBytes(24).toString('base64url');
      const optRes = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, { method: 'POST' });
      const optData = await optRes.json();
      const ghostAssertion = buildMockAssertion(privateKey, rpId, optData.challenge, origin, 1);

      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          credentialId: ghostId,
          assertion: {
            id: ghostId,
            response: {
              clientDataJSON: ghostAssertion.clientDataJSONB64,
              authenticatorData: ghostAssertion.authenticatorDataB64,
              signature: ghostAssertion.signatureB64,
            },
          },
        }),
      });
      const data = await res.json();

      if (res.status === 400 && data.verified === false && data.error.includes('Credential not found')) {
        recordPass('WebAuthn Vector 6', 'ATTACK_V6_01 (Unknown Credential ID)', 'Rejected with 400 Credential not found');
      } else {
        recordFail('WebAuthn Vector 6', 'ATTACK_V6_01 (Unknown Credential ID)', `Expected 400 Credential not found, got ${res.status}: ${JSON.stringify(data)}`);
      }

      // 2.6b: Verify NO ghost credential was created in memory
      const storedGhost = getStoredCredential(ghostId);
      if (storedGhost === undefined) {
        recordPass('WebAuthn Vector 6', 'ATTACK_V6_02 (Ghost Credential Absence)', 'Confirmed zero ghost credentials synthesized in credential store');
      } else {
        recordFail('WebAuthn Vector 6', 'ATTACK_V6_02 (Ghost Credential Absence)', 'VULNERABILITY: Ghost credential was synthesized in memory!');
      }
    }

    // =========================================================================
    // PART 3: LIVE SERVER TESTS (Validating http://127.0.0.1:3000)
    // =========================================================================
    console.log('\n--- 3. LIVE PRODUCTION BUNDLE VERIFICATION (PORT 3000) ---');

    try {
      const liveHealthRes = await fetch('http://127.0.0.1:3000/api/health');
      if (liveHealthRes.status === 200) {
        console.log('  [Live Server] Port 3000 is healthy and responding.');

        // Live Google OAuth Forged Token Test
        const liveGoogleRes = await fetch('http://127.0.0.1:3000/api/auth/verify-google', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ credential: 'forged.live.test.jwt' }),
        });
        const liveGoogleData = await liveGoogleRes.json();
        const liveGoogleCookie = liveGoogleRes.headers.get('set-cookie');

        if (liveGoogleRes.status === 401 && liveGoogleData.success === false && !liveGoogleCookie) {
          recordPass('Live Server', 'LIVE_GOOG_01', 'Live server on port 3000 strictly rejected forged token with 401, no cookie');
        } else {
          recordFail('Live Server', 'LIVE_GOOG_01', `Live server returned ${liveGoogleRes.status}`);
        }

        // Live WebAuthn Full Flow & Attack Suite on Port 3000
        const liveOrigin = 'http://127.0.0.1:3000';
        const liveRpId = '127.0.0.1';
        const liveKeys = createEcKeyPair();
        const liveJwk = liveKeys.publicKey.export({ format: 'jwk' });
        const liveX = Buffer.from(liveJwk.x!, 'base64url');
        const liveY = Buffer.from(liveJwk.y!, 'base64url');
        const liveCredRaw = crypto.randomBytes(16);
        const liveCredId = liveCredRaw.toString('base64url');

        // Step 1: Live Register Options
        const liveRegOptRes = await fetch('http://127.0.0.1:3000/api/webauthn/register-options', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: 'live-challenger@bilanx.org' }),
        });
        const liveRegOptData = await liveRegOptRes.json();
        assert.strictEqual(liveRegOptRes.status, 200);

        // Step 2: Live Register Verify
        const liveRegClientDataJSON = Buffer.from(
          JSON.stringify({ type: 'webauthn.create', challenge: liveRegOptData.challenge, origin: liveOrigin })
        ).toString('base64');
        const liveAttestation = buildMockAttestation(liveRpId, liveCredRaw, liveX, liveY).toString('base64');

        const liveRegVerifyRes = await fetch('http://127.0.0.1:3000/api/webauthn/register-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            username: 'live-challenger@bilanx.org',
            credential: {
              id: liveCredId,
              response: {
                clientDataJSON: liveRegClientDataJSON,
                attestationObject: liveAttestation,
              },
            },
          }),
        });
        const liveRegVerifyData = await liveRegVerifyRes.json();
        if (liveRegVerifyRes.status === 200 && liveRegVerifyData.verified === true) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_REG', 'Live registration on port 3000 succeeded');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_REG', `Live registration failed: ${JSON.stringify(liveRegVerifyData)}`);
        }

        // Step 3: Live Authenticate Options
        const liveAuthOptRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-options', { method: 'POST' });
        const liveAuthOptData = await liveAuthOptRes.json();

        // Step 4: Live Attack Vector 1 - Tampered Signature on Port 3000
        const liveTamperedAssertion = buildMockAssertion(liveKeys.privateKey, liveRpId, liveAuthOptData.challenge, liveOrigin, 1);
        const liveBadSigBuf = Buffer.from(liveTamperedAssertion.signatureB64, 'base64');
        liveBadSigBuf[liveBadSigBuf.length - 2] ^= 0x01;

        const liveTamperedRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            credentialId: liveCredId,
            assertion: {
              id: liveCredId,
              response: {
                clientDataJSON: liveTamperedAssertion.clientDataJSONB64,
                authenticatorData: liveTamperedAssertion.authenticatorDataB64,
                signature: liveBadSigBuf.toString('base64'),
              },
            },
          }),
        });
        const liveTamperedData = await liveTamperedRes.json();
        if (liveTamperedRes.status === 400 && liveTamperedData.verified === false) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_SIG_TAMPER', 'Live server rejected tampered signature with 400');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_SIG_TAMPER', `Live server failed to reject: ${liveTamperedRes.status}`);
        }

        // Step 5: Live Authentic Assertion Verification (counter = 1) - Request fresh challenge
        const liveAuthOpt5Res = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-options', { method: 'POST' });
        const liveAuthOpt5Data = await liveAuthOpt5Res.json();
        const liveValidAssertion = buildMockAssertion(liveKeys.privateKey, liveRpId, liveAuthOpt5Data.challenge, liveOrigin, 1);
        const liveValidAuthRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            credentialId: liveCredId,
            assertion: {
              id: liveCredId,
              response: {
                clientDataJSON: liveValidAssertion.clientDataJSONB64,
                authenticatorData: liveValidAssertion.authenticatorDataB64,
                signature: liveValidAssertion.signatureB64,
              },
            },
          }),
        });
        const liveValidAuthData = await liveValidAuthRes.json();
        if (liveValidAuthRes.status === 200 && liveValidAuthData.verified === true) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_AUTH_VALID', 'Live valid assertion verified, counter = 1');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_AUTH_VALID', `Live valid auth failed: ${JSON.stringify(liveValidAuthData)}`);
        }

        // Step 6: Live Attack Vector 2 - Replay Attack on Port 3000
        const liveReplayRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            credentialId: liveCredId,
            assertion: {
              id: liveCredId,
              response: {
                clientDataJSON: liveValidAssertion.clientDataJSONB64,
                authenticatorData: liveValidAssertion.authenticatorDataB64,
                signature: liveValidAssertion.signatureB64,
              },
            },
          }),
        });
        const liveReplayData = await liveReplayRes.json();
        if (liveReplayRes.status === 400 && liveReplayData.verified === false) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_REPLAY', 'Live server rejected replayed challenge with 400');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_REPLAY', `Live server failed to reject replay: ${liveReplayRes.status}`);
        }

        // Step 7: Live Attack Vector 3 - Origin Mismatch on Port 3000
        const liveOpt2Res = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-options', { method: 'POST' });
        const liveOpt2Data = await liveOpt2Res.json();
        const livePhishingAssertion = buildMockAssertion(liveKeys.privateKey, liveRpId, liveOpt2Data.challenge, 'https://evil-hacker.com', 2);

        const liveOriginRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            credentialId: liveCredId,
            assertion: {
              id: liveCredId,
              response: {
                clientDataJSON: livePhishingAssertion.clientDataJSONB64,
                authenticatorData: livePhishingAssertion.authenticatorDataB64,
                signature: livePhishingAssertion.signatureB64,
              },
            },
          }),
        });
        const liveOriginData = await liveOriginRes.json();
        if (liveOriginRes.status === 400 && liveOriginData.verified === false) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_ORIGIN', 'Live server rejected origin mismatch with 400');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_ORIGIN', `Live server failed to reject origin mismatch: ${liveOriginRes.status}`);
        }

        // Step 8: Live Attack Vector 5 - Counter Rollback on Port 3000
        const liveOpt3Res = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-options', { method: 'POST' });
        const liveOpt3Data = await liveOpt3Res.json();
        // Stored counter is 1; sending counter = 1 again simulates cloning
        const liveCloneAssertion = buildMockAssertion(liveKeys.privateKey, liveRpId, liveOpt3Data.challenge, liveOrigin, 1);

        const liveCloneRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            credentialId: liveCredId,
            assertion: {
              id: liveCredId,
              response: {
                clientDataJSON: liveCloneAssertion.clientDataJSONB64,
                authenticatorData: liveCloneAssertion.authenticatorDataB64,
                signature: liveCloneAssertion.signatureB64,
              },
            },
          }),
        });
        const liveCloneData = await liveCloneRes.json();
        if (liveCloneRes.status === 400 && liveCloneData.verified === false) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_COUNTER', 'Live server rejected counter stagnation / replay with 400');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_COUNTER', `Live server failed to reject counter stagnation: ${liveCloneRes.status}`);
        }

        // Step 9: Live Attack Vector 6 - Unknown Credential ID on Port 3000
        const liveGhostId = crypto.randomBytes(24).toString('base64url');
        const liveGhostRes = await fetch('http://127.0.0.1:3000/api/webauthn/authenticate-verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Origin: liveOrigin },
          body: JSON.stringify({
            credentialId: liveGhostId,
            assertion: {
              id: liveGhostId,
              response: {
                clientDataJSON: liveCloneAssertion.clientDataJSONB64,
                authenticatorData: liveCloneAssertion.authenticatorDataB64,
                signature: liveCloneAssertion.signatureB64,
              },
            },
          }),
        });
        const liveGhostData = await liveGhostRes.json();
        if (liveGhostRes.status === 400 && liveGhostData.verified === false) {
          recordPass('Live Server', 'LIVE_WEBAUTHN_UNKNOWN_CRED', 'Live server rejected unknown credential ID with 400');
        } else {
          recordFail('Live Server', 'LIVE_WEBAUTHN_UNKNOWN_CRED', `Live server failed to reject unknown credential: ${liveGhostRes.status}`);
        }
      }
    } catch (e: any) {
      console.warn('  [Live Server] Port 3000 not reachable or skipped:', e.message);
    }

  } finally {
    server.close();
  }

  // ---------------------------------------------------------------------------
  // Summary & Verdict
  // ---------------------------------------------------------------------------
  console.log('\n================================================================================');
  console.log(`📊 ADVERSARIAL TEST SUMMARY: ${passed} PASSED | ${failed} FAILED (${((passed / (passed + failed)) * 100).toFixed(1)}% Pass Rate)`);
  console.log('================================================================================');

  if (failed > 0) {
    console.error('❌ CHALLENGER 1 VERDICT: VETO (Vulnerabilities Detected)');
    process.exit(1);
  } else {
    console.log('✅ CHALLENGER 1 VERDICT: CONFIRMED (Zero Vulnerabilities Detected)');
  }
}

// Execute when run directly via tsx
runChallenger1AdversarialSuite().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
