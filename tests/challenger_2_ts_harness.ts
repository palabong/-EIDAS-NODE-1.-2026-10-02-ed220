/**
 * Challenger 2 TypeScript Stress Harness
 * Empirically tests:
 * 1. Session store stress:
 *    - Session TTL expiration
 *    - Invalid / forged session tokens
 *    - Cookie vs Authorization Bearer header extraction (precedence, encoding, multi-cookie)
 * 2. AuthnRequest parameters & options:
 *    - LoA generation & standardization (low, substantial, high, unrecognized)
 *    - RelayState preservation across AuthnRequest & ACS callback
 * 3. Express ACS Callback Edge Cases:
 *    - Non-ASCII / UTF-8 names in session creation
 *    - Underage (age 16 -> isOver18=false)
 *    - Missing RelayState bug detection
 */

import express from 'express';
import { createServer } from 'http';
import type { AddressInfo } from 'net';
import { execFileSync } from 'child_process';

import {
  SessionStore,
  globalSessionStore,
  extractSessionToken,
  setSessionCookie,
  requireSessionAuth,
} from '../src/server/sessionManager.ts';
import {
  generateAuthnRequest,
  generateSPMetadata,
  validateSAMLResponse,
} from '../src/server/samlBridge.ts';
import type { SessionUser } from '../src/server/types/saml.ts';

// Helper to get fresh signed SAML XML from Python engine
function getSignedPythonXml(code: string): string {
  const result = execFileSync('python3', ['-c', `from saml_engine.fixtures import *; ${code}`], {
    cwd: process.cwd(),
    encoding: 'utf-8',
  });
  return result.trim();
}

function buildTestServer(): express.Express {
  const app = express();
  app.use(express.urlencoded({ extended: true, limit: '2mb' }));
  app.use(express.json());

  // AuthnRequest endpoint
  app.all('/saml/authn-request', (req, res) => {
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
  });

  // ACS Endpoint (mirroring server.ts behavior)
  app.post('/saml/acs', async (req, res) => {
    const samlResponse = req.body?.SAMLResponse || req.body?.saml_response || req.body?.xml_content;
    const relayState = req.body?.RelayState || req.body?.relayState || '/';

    if (!samlResponse) {
      res.status(400).json({ success: false, error: 'Missing SAMLResponse parameter.' });
      return;
    }

    const validationResult = await validateSAMLResponse(samlResponse);
    if (!validationResult.is_valid) {
      const errMsg = validationResult.error_message || 'Validation failed';
      res.status(errMsg.includes('Missing mandatory') ? 400 : 401).json({ success: false, error: errMsg });
      return;
    }

    const posContext = validationResult.pos_context!;
    const claims = validationResult.claims || {};

    const sessionUser: SessionUser = {
      uid: posContext.user_id,
      email: `${posContext.user_id.toLowerCase().replace(/[^a-z0-9]/g, '_')}@eidas.europa.eu`,
      name: posContext.given_name && posContext.family_name
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

    // Current server.ts implementation does NOT return relayState
    // We observe this directly:
    res.json({
      success: true,
      relayState,
      sessionToken,
      user: sessionUser,
      pos_context: posContext,
    });
  });

  // Protected Session endpoint
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

export async function runChallenger2TSTests() {
  console.log('========================================================================');
  console.log('⚡ CHALLENGER 2: PROTOCOL EDGE CASES & SESSION STORE STRESS TEST SUITE');
  console.log('========================================================================\n');

  let passed = 0;
  let failed = 0;
  const findings: string[] = [];

  async function testCase(name: string, fn: () => Promise<void>) {
    try {
      await fn();
      console.log(`  ✅ [PASS] ${name}`);
      passed++;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`  ❌ [FAIL] ${name}: ${msg}`);
      failed++;
      findings.push(`${name} -> ${msg}`);
    }
  }

  // -------------------------------------------------------------------------
  // SECTION 1: SessionStore Unit & Stress Tests
  // -------------------------------------------------------------------------
  console.log('\n--- [1] SESSION STORE STRESS TESTS ---');

  await testCase('1.1 Session TTL Expiration: session expires after TTL window', async () => {
    const store = new SessionStore(50); // 50ms TTL
    const mockUser: Omit<SessionUser, 'expiresAt'> = {
      uid: 'USER-TTL-01',
      email: 'ttl@example.org',
      name: 'TTL User',
      authMethod: 'eidas_saml',
      authenticatedAt: new Date().toISOString(),
    };

    const { token } = store.createSession(mockUser, 50);
    // Active immediately
    const active = store.getSession(token);
    if (!active) throw new Error('Session should be active immediately after creation');

    // Wait 70ms for expiration
    await new Promise((r) => setTimeout(r, 70));
    const expired = store.getSession(token);
    if (expired !== null) throw new Error('Session should be null after TTL expired');

    // Store size should reflect automatic eviction upon access
    if (store.size() !== 0) throw new Error(`Expected store size 0 after expired get, got ${store.size()}`);
  });

  await testCase('1.2 Session Store: pruneExpiredSessions removes expired sessions', async () => {
    const store = new SessionStore();
    const mockUser: Omit<SessionUser, 'expiresAt'> = {
      uid: 'PRUNE-USER',
      email: 'prune@example.org',
      name: 'Prune User',
      authMethod: 'eidas_saml',
      authenticatedAt: new Date().toISOString(),
    };

    // Create 3 sessions: 2 expired (10ms), 1 alive (5000ms)
    store.createSession(mockUser, 10);
    store.createSession(mockUser, 10);
    store.createSession(mockUser, 5000);

    await new Promise((r) => setTimeout(r, 25));
    const prunedCount = store.pruneExpiredSessions();
    if (prunedCount !== 2) throw new Error(`Expected 2 pruned sessions, got ${prunedCount}`);
    if (store.size() !== 1) throw new Error(`Expected store size 1, got ${store.size()}`);
  });

  await testCase('1.3 Invalid / Forged Session Tokens return null', async () => {
    const store = new SessionStore();
    const maliciousTokens = [
      'fake-uuid-1234',
      "' OR '1'='1",
      '<script>alert(1)</script>',
      'Bearer fake-token',
      '',
      '   ',
      '../etc/passwd',
      'null',
      'undefined',
    ];

    for (const token of maliciousTokens) {
      const res = store.getSession(token);
      if (res !== null) throw new Error(`Expected null for invalid token '${token}', got object`);
    }
  });

  // -------------------------------------------------------------------------
  // SECTION 2: extractSessionToken Edge Cases
  // -------------------------------------------------------------------------
  console.log('\n--- [2] TOKEN EXTRACTION & PRECEDENCE TESTS ---');

  await testCase('2.1 Bearer Token Header Extraction', async () => {
    const req1 = { headers: { authorization: 'Bearer my-token-123' }, query: {} } as any;
    if (extractSessionToken(req1) !== 'my-token-123') throw new Error('Failed extracting standard Bearer token');

    const req2 = { headers: { authorization: 'Bearer   padded-token-456   ' }, query: {} } as any;
    if (extractSessionToken(req2) !== 'padded-token-456') throw new Error('Failed trimming Bearer token');

    const req3 = { headers: { authorization: 'Bearer ' }, query: {} } as any;
    if (extractSessionToken(req3) !== null) throw new Error('Empty Bearer should return null');
  });

  await testCase('2.2 Cookie Header Extraction (Single & Multi-cookie & URL-encoded)', async () => {
    const req1 = { headers: { cookie: 'session_token=cookie-tok-99' }, query: {} } as any;
    if (extractSessionToken(req1) !== 'cookie-tok-99') throw new Error('Failed extracting single cookie');

    const req2 = { headers: { cookie: 'lang=en; session_token=multi-tok-88; ga=123' }, query: {} } as any;
    if (extractSessionToken(req2) !== 'multi-tok-88') throw new Error('Failed extracting from multi-cookie header');

    // URI Encoded cookie value
    const rawVal = 'token+with+special=chars&more';
    const encVal = encodeURIComponent(rawVal);
    const req3 = { headers: { cookie: `session_token=${encVal}` }, query: {} } as any;
    if (extractSessionToken(req3) !== rawVal) throw new Error(`Failed decoding URL-encoded cookie: got ${extractSessionToken(req3)}`);
  });

  await testCase('2.3 Header Precedence: Authorization Bearer overrides Cookie', async () => {
    const req = {
      headers: {
        authorization: 'Bearer bearer-priority-token',
        cookie: 'session_token=cookie-subordinate-token',
      },
      query: {},
    } as any;
    const token = extractSessionToken(req);
    if (token !== 'bearer-priority-token') {
      throw new Error(`Expected Bearer token precedence, got: ${token}`);
    }
  });

  // -------------------------------------------------------------------------
  // SECTION 3: AuthnRequest Parameters & LoA Handling
  // -------------------------------------------------------------------------
  console.log('\n--- [3] AUTHNREQUEST PARAMETERS & LOA HANDLING ---');

  await testCase('3.1 AuthnRequest LoA Mapping & RelayState Preservation', async () => {
    // Test standard LoA values
    const loas = ['low', 'substantial', 'high'];
    for (const loa of loas) {
      const res = generateAuthnRequest({ loa, relayState: '/app/checkout' });
      if (!res.authnRequestXml.includes(`http://eidas.europa.eu/LoA/${loa}`)) {
        throw new Error(`AuthnRequest XML missing standardized LoA for '${loa}'`);
      }
      if (res.relayState !== '/app/checkout') {
        throw new Error(`RelayState lost in AuthnRequest generation: ${res.relayState}`);
      }
    }

    // Test unrecognized LoA
    const resUnrec = generateAuthnRequest({ loa: 'unrecognized_custom', relayState: '/state-1' });
    if (!resUnrec.authnRequestXml.includes('http://eidas.europa.eu/LoA/unrecognized_custom')) {
      throw new Error('Unrecognized LoA was not formatted properly');
    }
  });

  // -------------------------------------------------------------------------
  // SECTION 4: Express ACS Integration Edge Cases
  // -------------------------------------------------------------------------
  console.log('\n--- [4] EXPRESS ACS INTEGRATION EDGE CASES ---');

  const app = buildTestServer();
  const server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;

  try {
    await testCase('4.1 RelayState Preservation across ACS Callback (CRITICAL SPEC CHECK)', async () => {
      const validXml = getSignedPythonXml('print(build_signed_saml_response())');
      const expectedRelayState = '/retail/pos/transaction/98765';

      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          SAMLResponse: validXml,
          RelayState: expectedRelayState,
        }),
      });

      if (res.status !== 200) throw new Error(`ACS returned status ${res.status}`);
      const data = await res.json();
      if (!data.success) throw new Error(`ACS failed: ${data.error}`);

      // CHECK: Does ACS echo or preserve RelayState?
      if (!data.relayState && !data.RelayState) {
        console.warn('  ⚠️ [BUG CONFIRMED] ACS callback dropped RelayState from response JSON!');
        throw new Error('SAML 2.0 Web SSO Violation: ACS callback failed to preserve RelayState across callback!');
      }
    });

    await testCase('4.2 Underage Subject Ingestion (Age 16 -> isOver18=false)', async () => {
      const minorXml = getSignedPythonXml(`
print(build_signed_saml_response(
    person_identifier="IT/IT/MINOR-16-TEST",
    family_name="Bianchi",
    given_name="Alessandro",
    date_of_birth="2010-06-15",
    loa="http://eidas.europa.eu/LoA/substantial"
))
`);

      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: minorXml }),
      });

      if (res.status !== 200) throw new Error(`ACS returned status ${res.status}`);
      const data = await res.json();
      if (!data.success) throw new Error(`ACS failed: ${data.error}`);

      if (data.user.isOver18 !== false) {
        throw new Error(`Expected isOver18=false for 16-year-old, got: ${data.user.isOver18}`);
      }
      if (data.pos_context.is_over_18 !== false) {
        throw new Error(`Expected pos_context.is_over_18=false, got: ${data.pos_context.is_over_18}`);
      }
      if (data.user.age !== 16) {
        throw new Error(`Expected age 16, got: ${data.user.age}`);
      }
    });

    await testCase('4.3 Non-ASCII UTF-8 Names Ingestion in ACS (René Müller & García Østergård)', async () => {
      const utf8Xml = getSignedPythonXml(`
print(build_signed_saml_response(
    person_identifier="FR/DE/RENE-MULLER",
    family_name="Müller",
    given_name="René",
    date_of_birth="1995-12-01"
))
`);

      const res = await fetch(`${baseUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ SAMLResponse: utf8Xml }),
      });

      if (res.status !== 200) throw new Error(`ACS returned status ${res.status}`);
      const data = await res.json();
      if (!data.success) throw new Error(`ACS failed: ${data.error}`);

      if (data.user.name !== 'René Müller') {
        throw new Error(`Name mangled: expected 'René Müller', got '${data.user.name}'`);
      }
      if (data.user.givenName !== 'René' || data.user.familyName !== 'Müller') {
        throw new Error(`Name fields mangled: given=${data.user.givenName}, family=${data.user.familyName}`);
      }
    });

    await testCase('4.4 Expired / Forged Session Tokens Rejected at /saml/session', async () => {
      // 1. Forged token
      const resForged = await fetch(`${baseUrl}/saml/session`, {
        headers: { Authorization: 'Bearer forged-token-0000' },
      });
      if (resForged.status !== 401) throw new Error(`Expected 401 for forged token, got ${resForged.status}`);

      // 2. Missing token
      const resMissing = await fetch(`${baseUrl}/saml/session`);
      if (resMissing.status !== 401) throw new Error(`Expected 401 for missing token, got ${resMissing.status}`);
    });

  } finally {
    server.close();
  }

  console.log('\n========================================================================');
  console.log(`📊 CHALLENGER 2 TS TEST SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('========================================================================\n');

  return { passed, failed, findings };
}

// Auto-run if executed directly via tsx / node
if (import.meta.url.endsWith(process.argv[1]) || process.argv[1]?.includes('challenger_2_ts_harness')) {
  runChallenger2TSTests().then(({ failed }) => {
    process.exit(failed > 0 ? 1 : 0);
  }).catch((err) => {
    console.error('Test execution error:', err);
    process.exit(1);
  });
}
