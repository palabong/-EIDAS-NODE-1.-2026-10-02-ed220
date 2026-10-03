/**
 * Comprehensive Automated End-to-End Test Suite for eIDAS 2.0 SAML Compliance
 * Tests HTTP SAML Endpoints on Express Server:
 * 1. GET /saml/metadata and GET /metadata
 * 2. POST /saml/authn-request and GET /saml/login
 * 3. POST /saml/acs (Valid RSA & ECDSA responses via JSON and form-urlencoded)
 * 4. Negative Vector: Tampered Assertion Content (Digest Mismatch)
 * 5. Negative Vector: Tampered Signature Bytes (Cryptographic Verification Failure)
 * 6. Negative Vector: Expired Assertion (NotOnOrAfter in past)
 * 7. Negative Vector: Premature Assertion (NotBefore in future)
 * 8. Negative Vector: Assertion Replay Attack (Duplicate Assertion ID)
 * 9. Negative Vector: Audience Mismatch
 * 10. Negative Vector: Missing Mandatory eIDAS Attribute (DateOfBirth / PersonIdentifier)
 * 11. Negative Vector: XXE / DTD Injection Defense
 * 12. GET /saml/session (Authenticated Session Check & Cookie / Bearer Verification)
 */

import express from 'express';
import { createServer } from 'http';
import { execSync } from 'child_process';
import type { AddressInfo } from 'net';

import {
  generateSPMetadata,
  generateAuthnRequest,
  validateSAMLResponse,
} from '../src/server/samlBridge.ts';
import {
  globalSessionStore,
  extractSessionToken,
  setSessionCookie,
} from '../src/server/sessionManager.ts';
import { recordAccessLog } from '../src/server/accessLogDb.ts';
import type { SessionUser } from '../src/server/types/saml.ts';

// Helper to get fresh fixtures directly from Python engine
function getPythonFixture(funcCall: string): string {
  const res = execSync(`python3 -c "from saml_engine.fixtures import *; print(${funcCall})"`, {
    cwd: process.cwd(),
    encoding: 'utf-8',
  });
  return res.trim();
}

function getClientIp(req: express.Request): string {
  const xff = req.headers['x-forwarded-for'];
  if (Array.isArray(xff) && xff.length > 0) {
    return xff[0].split(',')[0].trim();
  }
  if (typeof xff === 'string') {
    return xff.split(',')[0].trim();
  }
  return req.ip || req.socket.remoteAddress || '127.0.0.1';
}

function getErrorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Build dedicated Express Test App with all SAML endpoints
function buildTestApp(): express.Express {
  const app = express();
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));
  app.use(express.json());

  // 1. Metadata
  app.get(['/saml/metadata', '/metadata'], (req, res) => {
    try {
      const spEntityId = 'http://localhost:3099/saml/metadata';
      const acsUrl = 'http://localhost:3099/saml/acs';
      const metadataXml = generateSPMetadata(spEntityId, acsUrl);
      res.setHeader('Content-Type', 'application/samlmetadata+xml; charset=utf-8');
      res.send(metadataXml);
    } catch (err: unknown) {
      res.status(500).json({ error: getErrorMessage(err) });
    }
  });

  // 2. AuthnRequest
  app.all(['/saml/authn-request', '/saml/login'], (req, res) => {
    try {
      const loa = (req.body?.loa || req.query?.loa || 'substantial') as string;
      const relayState = (req.body?.relayState || req.query?.relayState || '') as string;
      const destination = (req.body?.destination || req.query?.destination) as string | undefined;

      const result = generateAuthnRequest({
        loa,
        relayState,
        destination,
        spEntityId: 'http://localhost:3099/saml/metadata',
        acsUrl: 'http://localhost:3099/saml/acs',
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
      res.status(500).json({ error: getErrorMessage(err) });
    }
  });

  // 3. ACS Ingestion
  app.post(['/saml/acs', '/auth/callback', '/saml/consume'], async (req, res) => {
    try {
      const clientIp = getClientIp(req);
      const userAgent = req.headers['user-agent'] || 'E2E Test Runner';

      const samlResponse = req.body?.SAMLResponse || req.body?.saml_response || req.body?.xml_content;
      const relayState = req.body?.RelayState || req.body?.relayState || '/';

      if (!samlResponse || typeof samlResponse !== 'string') {
        res.status(400).json({ success: false, error: 'Missing SAMLResponse parameter.' });
        return;
      }

      if (/<!\s*(DOCTYPE|ENTITY)/i.test(samlResponse)) {
        res.status(400).json({
          success: false,
          error: 'Security Violation: DTD declarations or external entities are forbidden.',
        });
        return;
      }

      const validationResult = await validateSAMLResponse(samlResponse);

      if (!validationResult.is_valid) {
        const errMsg = validationResult.error_message || 'Validation failed';
        const isBadRequest =
          errMsg.includes('Missing mandatory') ||
          errMsg.includes('Security Violation') ||
          errMsg.includes('Invalid root tag') ||
          errMsg.includes('Parser Error');

        const statusCode = isBadRequest ? 400 : 401;
        res.status(statusCode).json({ success: false, error: errMsg });
        return;
      }

      const posContext = validationResult.pos_context!;
      const claims = validationResult.claims || {};

      const sessionUser: SessionUser = {
        uid: posContext.user_id,
        email: `${posContext.user_id.toLowerCase().replace(/[^a-z0-9]/g, '_')}@eidas.europa.eu`,
        name:
          posContext.given_name && posContext.family_name
            ? `${posContext.given_name} ${posContext.family_name}`
            : `eIDAS User ${posContext.user_id}`,
        authMethod: 'eidas_saml',
        role: posContext.role,
        permissions: posContext.permissions,
        levelOfAssurance: posContext.level_of_assurance,
        personIdentifier: posContext.user_id,
        familyName: posContext.family_name,
        givenName: posContext.given_name,
        dateOfBirth: posContext.date_of_birth,
        age: posContext.age,
        isOver18: posContext.is_over_18,
        isOver21: posContext.is_over_21,
        authenticatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 4 * 60 * 60 * 1000,
        issuer: claims.issuer,
        posContext,
      };

      const { token: sessionToken } = globalSessionStore.createSession(sessionUser);
      setSessionCookie(res, sessionToken);

      res.json({
        success: true,
        relayState,
        sessionToken,
        user: sessionUser,
        pos_context: posContext,
      });
    } catch (err: unknown) {
      res.status(500).json({ success: false, error: getErrorMessage(err) });
    }
  });

  // 4. Session check
  app.get('/saml/session', (req, res) => {
    const token = extractSessionToken(req);
    if (!token) {
      res.status(401).json({ active: false, error: 'No active SAML session token found.' });
      return;
    }
    const session = globalSessionStore.getSession(token);
    if (!session) {
      res.status(401).json({ active: false, error: 'Session has expired or is invalid.' });
      return;
    }
    res.json({ active: true, user: session });
  });

  return app;
}

// Test Runner
async function runE2ETests() {
  console.log('======================================================================');
  console.log('🚀 STARTING eIDAS 2.0 SAML INTEGRATION & HARDENING E2E TEST SUITE');
  console.log('======================================================================\n');

  const app = buildTestApp();
  const server = createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[Test Server] Ephemeral test server active on ${baseUrl}\n`);

  let passed = 0;
  let failed = 0;

  async function testCase(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err: unknown) {
      console.error(`  ❌ [FAIL] ${name}:`, getErrorMessage(err));
      failed++;
    }
  }

  try {
    // 1. Metadata Endpoint
    await testCase('1. GET /saml/metadata returns valid EntityDescriptor XML', async () => {
      const res = await fetch(`${baseUrl}/saml/metadata`);
      if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
      const ct = res.headers.get('content-type') || '';
      if (!ct.includes('application/samlmetadata+xml') && !ct.includes('xml')) {
        throw new Error(`Unexpected Content-Type: ${ct}`);
      }
      const text = await res.text();
      if (!text.includes('<md:EntityDescriptor')) throw new Error('Missing <md:EntityDescriptor');
      if (!text.includes('<md:SPSSODescriptor')) throw new Error('Missing <md:SPSSODescriptor');
      if (!text.includes('<md:KeyDescriptor use="signing">')) throw new Error('Missing signing KeyDescriptor');
    });

    // 2. AuthnRequest Endpoint
    await testCase('2. POST /saml/authn-request generates valid eIDAS AuthnRequest', async () => {
      const res = await fetch(`${baseUrl}/saml/authn-request`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ loa: 'substantial', relayState: '/dashboard' }),
      });
      if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
      const data = await res.json();
      if (!data.success) throw new Error(`AuthnRequest failed: ${data.error}`);
      if (!data.requestId.startsWith('_authn_')) throw new Error(`Invalid requestId: ${data.requestId}`);
      if (!data.authnRequestXml.includes('http://eidas.europa.eu/LoA/substantial')) {
        throw new Error('Missing requested LoA in AuthnRequest XML');
      }
      if (!data.samlRequestBase64) throw new Error('Missing Base64 SAMLRequest');
    });

    // 3. Valid Response (RSA-SHA256) via JSON
    let activeSessionToken = '';
    await testCase('3. POST /saml/acs (Valid RSA Signed Response via JSON)', async () => {
      const validXml = getPythonFixture('get_valid_rsa_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: validXml, RelayState: '/pos' }),
      });
      if (res.status !== 200) {
        const body = await res.text();
        throw new Error(`Expected 200, got ${res.status}: ${body}`);
      }
      const data = await res.json();
      if (!data.success) throw new Error(`Expected success=true, got: ${JSON.stringify(data)}`);
      if (data.relayState !== '/pos') {
        throw new Error(`Expected relayState '/pos', got ${data.relayState}`);
      }
      if (data.user.personIdentifier !== 'IT/IT/TINIT-PLGDNL85M01H501Z') {
        throw new Error(`Wrong PersonIdentifier: ${data.user.personIdentifier}`);
      }
      if (data.user.familyName !== 'Palagi' || data.user.givenName !== 'Daniele') {
        throw new Error(`Wrong Name: ${data.user.givenName} ${data.user.familyName}`);
      }
      if (data.user.dateOfBirth !== '1985-08-01' || !data.user.isOver18) {
        throw new Error(`Age check failed: DOB=${data.user.dateOfBirth}, over18=${data.user.isOver18}`);
      }
      if (data.user.role !== 'STORE_MANAGER') {
        throw new Error(`Wrong role for substantial LoA: ${data.user.role}`);
      }
      if (!data.sessionToken) throw new Error('Missing sessionToken');
      activeSessionToken = data.sessionToken;

      const setCookie = res.headers.get('set-cookie');
      if (!setCookie || !setCookie.includes('session_token=')) {
        throw new Error(`Missing Set-Cookie header: ${setCookie}`);
      }
    });

    // 4. Valid Response (ECDSA-SHA256) via form-urlencoded
    await testCase('4. POST /saml/acs (Valid ECDSA Signed Response via Form-Urlencoded)', async () => {
      const ecdsaXml = getPythonFixture('get_valid_ecdsa_response()');
      const b64 = Buffer.from(ecdsaXml).toString('base64');
      const formBody = new URLSearchParams({
        SAMLResponse: b64,
        RelayState: '/checkout',
      }).toString();

      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formBody,
      });
      if (res.status !== 200) {
        const body = await res.text();
        throw new Error(`Expected 200, got ${res.status}: ${body}`);
      }
      const data = await res.json();
      if (!data.success) throw new Error(`ECDSA form POST failed: ${JSON.stringify(data)}`);
      if (data.user.personIdentifier !== 'IT/IT/TINIT-PLGDNL85M01H501Z') {
        throw new Error(`Wrong user: ${data.user.personIdentifier}`);
      }
    });

    // 5. Tampered Content (Attribute Modified)
    await testCase('5. Negative: Tampered Assertion Content is Rejected (400/401)', async () => {
      const tamperedXml = getPythonFixture('get_tampered_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: tamperedXml }),
      });
      if (res.status !== 401 && res.status !== 400) {
        throw new Error(`Expected 401/400, got ${res.status}`);
      }
      const data = await res.json();
      if (data.success !== false) throw new Error('Expected success=false for tampered assertion');
      if (!data.error.includes('Digest Mismatch') && !data.error.includes('tamper')) {
        throw new Error(`Expected Digest Mismatch error, got: ${data.error}`);
      }
    });

    // 6. Tampered Signature Bytes
    await testCase('6. Negative: Tampered Signature Bytes are Rejected (401)', async () => {
      const tamperedSigXml = getPythonFixture('get_tampered_sig_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: tamperedSigXml }),
      });
      if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
      const data = await res.json();
      if (data.success !== false) throw new Error('Expected success=false');
    });

    // 7. Expired Assertion
    await testCase('7. Negative: Expired Assertion is Rejected (401)', async () => {
      const expiredXml = getPythonFixture('get_expired_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: expiredXml }),
      });
      if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
      const data = await res.json();
      if (!data.error.includes('expired')) throw new Error(`Expected expired error, got: ${data.error}`);
    });

    // 8. Premature Assertion
    await testCase('8. Negative: Premature Assertion is Rejected (401)', async () => {
      const prematureXml = getPythonFixture('get_premature_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: prematureXml }),
      });
      if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
      const data = await res.json();
      if (!data.error.includes('premature')) throw new Error(`Expected premature error, got: ${data.error}`);
    });

    // 9. Replay Attack
    await testCase('9. Negative: Replay of Processed Assertion is Rejected (401)', async () => {
      const replayXml = getPythonFixture('get_valid_rsa_response()');
      // 1st request -> Success
      const res1 = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: replayXml }),
      });
      if (res1.status !== 200) throw new Error(`First presentation failed with status ${res1.status}`);

      // 2nd request -> Replay detected
      const res2 = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: replayXml }),
      });
      if (res2.status !== 401) throw new Error(`Expected 401 for replay, got ${res2.status}`);
      const data2 = await res2.json();
      if (!data2.error.includes('Replay Attack Detected')) {
        throw new Error(`Expected Replay Attack error, got: ${data2.error}`);
      }
    });

    // 10. Audience Mismatch
    await testCase('10. Negative: Audience Mismatch is Rejected (401)', async () => {
      const audXml = getPythonFixture('get_audience_mismatch_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: audXml }),
      });
      if (res.status !== 401) throw new Error(`Expected 401, got ${res.status}`);
      const data = await res.json();
      if (!data.error.includes('Audience Mismatch')) {
        throw new Error(`Expected Audience Mismatch error, got: ${data.error}`);
      }
    });

    // 11. Missing Mandatory eIDAS Attribute
    await testCase('11. Negative: Missing DateOfBirth is Rejected (400)', async () => {
      const missingDobXml = getPythonFixture('get_missing_dob_response()');
      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: missingDobXml }),
      });
      if (res.status !== 400 && res.status !== 401) {
        throw new Error(`Expected 400/401, got ${res.status}`);
      }
      const data = await res.json();
      if (!data.error.includes('Missing mandatory eIDAS attribute: DateOfBirth')) {
        throw new Error(`Expected missing DateOfBirth error, got: ${data.error}`);
      }
    });

    // 12. DTD / XXE Injection
    await testCase('12. Negative: Inline DTD/XXE Injection is Rejected (400)', async () => {
      const xxePayload = `<?xml version="1.0"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" ID="_xxe">&xxe;</saml2p:Response>`;

      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: xxePayload }),
      });
      if (res.status !== 400) throw new Error(`Expected 400, got ${res.status}`);
      const data = await res.json();
      if (!data.error.includes('Security Violation')) {
        throw new Error(`Expected Security Violation error, got: ${data.error}`);
      }
    });

    // 13. Session Verification
    await testCase('13. GET /saml/session verifies active authenticated session', async () => {
      if (!activeSessionToken) throw new Error('No active session token from step 3');

      // Request with Bearer token
      const res = await fetch(`${baseUrl}/saml/session`, {
        headers: { Authorization: `Bearer ${activeSessionToken}` },
      });
      if (res.status !== 200) throw new Error(`Expected 200, got ${res.status}`);
      const data = await res.json();
      if (!data.active) throw new Error('Session reported as inactive');
      if (data.user.personIdentifier !== 'IT/IT/TINIT-PLGDNL85M01H501Z') {
        throw new Error(`Wrong user in session: ${data.user.personIdentifier}`);
      }

      // Request without token -> 401
      const unauthRes = await fetch(`${baseUrl}/saml/session`);
      if (unauthRes.status !== 401) throw new Error(`Expected 401 for unauthenticated session check, got ${unauthRes.status}`);
    });

  } finally {
    server.close();
  }

  console.log('\n======================================================================');
  console.log(`📊 E2E TEST SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('======================================================================\n');

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runE2ETests().catch((err) => {
  console.error('Fatal E2E Test Failure:', err);
  process.exit(1);
});
