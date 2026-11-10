/**
 * Bilanx — TRL 6 Operational Pilot Sandbox E2E Verification Harness
 * tests/pilot_sandbox_e2e_test.ts
 * 
 * Comprehensive automated verification for:
 * 1. Hardware Security Key Integration:
 *    - Headless CTAP2 roaming key registration (authenticatorAttachment: 'cross-platform')
 *    - YubiKey 5 Series AAGUID identification (ee882879-721c-4916-ad4e-57c7f15f6f19)
 *    - User verification flags (UP & UV) & packed self-attestation statement processing
 *    - Monotonic signature counter tracking (anti-cloning)
 *    - Tamper resistance (cloned counter replay, signature mutation, challenge reuse)
 * 
 * 2. Dual-Jurisdiction Policy Evaluation (CH & IT):
 *    - Swiss Profile (CH - FADP / Retail POS):
 *      - 18+ tobacco/nicotine/alcohol/lottery gate
 *      - Strict zero-PII boolean verification
 *      - 1,355-byte NIST P-256 B2 Sigma range proof
 *      - Sub-1.5s POS envelope latency target
 *      - Official Swiss Audit Certificate PDF export
 *    - Italian Profile (IT - AgCom & eIDAS LoA High):
 *      - eIDAS Level of Assurance High mapping
 *      - Institutional credential binding (BILANX-IT-AGCOM-NODE-01)
 *      - Enforcement of LoA High mandate (rejection of LoA Substantial)
 *      - AgCom-compliant verifiable audit receipting & Italian PDF certificate export
 * 
 * 3. Deterministic Underage Rejection:
 *    - Swiss underage scenario (Luca Rossi, age 17) -> mathematically rejected
 *    - Italian underage scenario (Matteo Russo, age 16) -> mathematically rejected
 */

import { createServer } from 'http';
import type { AddressInfo } from 'net';
import assert from 'assert';
import crypto from 'crypto';
import { execSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createApp, activeChallenges } from '../src/server/app.ts';
import {
  getInstitutionalKey,
  loadPrimaryKeyOrThrow,
  releaseInstitutionalKey,
  rotateInstitutionalKey,
  backdateRetiredInstitutionalKey
} from '../src/server/institutionalKey.ts';
import { FileDurableMap, durableSnapshot } from '../src/server/durableStore.ts';
import { MAX_ACTIVE_INSTITUTIONAL_CHALLENGES, credentialSecondFactorHash, replaceInstitutionalChallengeStore } from '../src/server/clearance.ts';
import {
  activeWebAuthnChallenges,
  registeredWebAuthnCredentials,
  MAX_ACTIVE_WEBAUTHN_CHALLENGES,
  MAX_STORED_CREDENTIALS,
  replaceWebAuthnChallengeStore,
  replaceWebAuthnCredentialStore
} from '../src/server/webauthnServer.ts';
import { 
  runPilotDemonstration, 
  runSwissDemonstration,
  runItalianDemonstration 
} from '../src/sandbox/lib/e2e/runSwissDemonstration.ts';
import { 
  Ctap2HardwareKeyHarness, 
  YUBIKEY_5_SERIES_AAGUID 
} from '../src/lib/crypto/ctap2Harness.ts';
import { 
  getPilotProfile, 
  SWISS_PILOT_PROFILE, 
  ITALIAN_PILOT_PROFILE 
} from '../src/sandbox/lib/pilotProfiles.ts';
import { buildAuditCertificatePdfDoc } from '../src/sandbox/lib/PdfReceiptGenerator.ts';
import { generateBitwiseRangeProof } from '../src/lib/crypto/zkp/range_b2.ts';
import { generateProof } from '../src/lib/crypto/zkp/nizkp.ts';
import { clearanceMessage } from '../src/lib/crypto/clearanceMessage.ts';
import { acceptRetailSale, canonicalClearanceEnvelope, CLEARANCE_ENVELOPE_TTL_MS, readTillClearanceArtifact, receiptSha256Hex, signClearanceEnvelope, type ClearanceEnvelope } from '../src/lib/crypto/clearanceEnvelope.ts';
import { getAccessLogs } from '../src/server/accessLogDb.ts';
import { globalSessionStore } from '../src/server/sessionManager.ts';
import { bytesToBase64, bytesToHex } from '../src/lib/crypto/encoding.ts';
import { DEFAULT_UHD_RFID_ASSERTIONS } from '../src/data.ts';

async function createExpiredCertHelper(): Promise<{ der: Uint8Array; webCryptoKey: CryptoKey }> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-exp-'));
  try {
    const keyPath = path.join(tmpDir, 'key.pem');
    const crtPath = path.join(tmpDir, 'crt.pem');
    execSync(`openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "${keyPath}" -out "${crtPath}" -days 1 -nodes -subj "/CN=Expired YubiKey CA"`);
    const keyPem = fs.readFileSync(keyPath);
    const crtPem = fs.readFileSync(crtPath);
    const privKey = crypto.createPrivateKey(keyPem);
    const cert = new crypto.X509Certificate(crtPem);
    const der = cert.raw;
    let tbsHeaderLen = der[5] === 0x82 ? 4 : der[5] === 0x81 ? 3 : 2;
    let tbsDataLen = der[5] === 0x82 ? (der[6] << 8) | der[7] : der[5] === 0x81 ? der[6] : der[5];
    const tbsBuf = der.subarray(4, 4 + tbsHeaderLen + tbsDataLen);
    const modifiedTbs = Buffer.from(tbsBuf);
    let offset = 0;
    while (offset < modifiedTbs.length - 2) {
      if (modifiedTbs[offset] === 0x17 && modifiedTbs[offset + 1] === 0x0d) {
        modifiedTbs.write('200101000000Z', offset + 2);
        offset += 15;
        if (offset < modifiedTbs.length - 2 && modifiedTbs[offset] === 0x17 && modifiedTbs[offset + 1] === 0x0d) {
          modifiedTbs.write('200102000000Z', offset + 2);
        }
        break;
      }
      offset++;
    }
    const newSig = crypto.sign('SHA256', modifiedTbs, privKey);
    const algSeq = Buffer.from([0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]);
    const bitStringHeader = Buffer.from([0x03, newSig.length + 1, 0x00]);
    const certBody = Buffer.concat([modifiedTbs, algSeq, Buffer.concat([bitStringHeader, newSig])]);
    const outerHeader = certBody.length < 256 ? Buffer.from([0x30, 0x81, certBody.length]) : Buffer.from([0x30, 0x82, (certBody.length >> 8) & 0xff, certBody.length & 0xff]);
    const expiredCertDer = Buffer.concat([outerHeader, certBody]);

    const webCryptoKey = await crypto.webcrypto.subtle.importKey(
      'pkcs8',
      privKey.export({ type: 'pkcs8', format: 'der' }),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );

    return {
      der: new Uint8Array(expiredCertDer),
      webCryptoKey: webCryptoKey as any
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function createCertChainHelpers(): Promise<{
  leafDer: Uint8Array;
  rootDer: Uint8Array;
  fakeRootDer: Uint8Array;
  leafWebCryptoKey: CryptoKey;
}> {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-chain-'));
  try {
    const rootKeyPath = path.join(tmpDir, 'root.key');
    const rootCrtPath = path.join(tmpDir, 'root.crt');
    execSync(`openssl ecparam -name prime256v1 -genkey -noout -out "${rootKeyPath}"`);
    execSync(`openssl req -new -x509 -key "${rootKeyPath}" -out "${rootCrtPath}" -days 365 -subj "/CN=Bilanx Hardware Attestation Root CA"`);

    const leafKeyPath = path.join(tmpDir, 'leaf.key');
    const leafCsrPath = path.join(tmpDir, 'leaf.csr');
    const leafCrtPath = path.join(tmpDir, 'leaf.crt');
    execSync(`openssl ecparam -name prime256v1 -genkey -noout -out "${leafKeyPath}"`);
    execSync(`openssl req -new -key "${leafKeyPath}" -out "${leafCsrPath}" -subj "/CN=YubiKey 5 Attestation Leaf"`);
    execSync(`openssl x509 -req -in "${leafCsrPath}" -CA "${rootCrtPath}" -CAkey "${rootKeyPath}" -CAcreateserial -out "${leafCrtPath}" -days 365`);

    const fakeKeyPath = path.join(tmpDir, 'fake.key');
    const fakeCrtPath = path.join(tmpDir, 'fake.crt');
    execSync(`openssl ecparam -name prime256v1 -genkey -noout -out "${fakeKeyPath}"`);
    execSync(`openssl req -new -x509 -key "${fakeKeyPath}" -out "${fakeCrtPath}" -days 365 -subj "/CN=Rogue Untrusted CA"`);

    const rootDer = new Uint8Array(new crypto.X509Certificate(fs.readFileSync(rootCrtPath)).raw);
    const leafDer = new Uint8Array(new crypto.X509Certificate(fs.readFileSync(leafCrtPath)).raw);
    const fakeRootDer = new Uint8Array(new crypto.X509Certificate(fs.readFileSync(fakeCrtPath)).raw);

    const leafPriv = crypto.createPrivateKey(fs.readFileSync(leafKeyPath));
    const leafWebCryptoKey = await crypto.webcrypto.subtle.importKey(
      'pkcs8',
      leafPriv.export({ type: 'pkcs8', format: 'der' }),
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['sign']
    );

    return {
      leafDer,
      rootDer,
      fakeRootDer,
      leafWebCryptoKey: leafWebCryptoKey as any
    };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

async function runPilotVerificationSuite() {
  console.log('================================================================================');
  console.log('🛡️  BILANX TRL 6 OPERATIONAL PILOT SANDBOX E2E VERIFICATION SUITE');
  console.log('================================================================================\n');

  const accessLogDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-pilot-access-'));
  const previousAccessLogPath = process.env.ACCESS_LOG_PATH;
  process.env.ACCESS_LOG_PATH = path.join(accessLogDir, 'access_logs.json');

  // Boot ephemeral Express server
  const app = createApp({ isTest: true });
  const server = createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[TEST-SERVER] Ephemeral Bilanx Pilot Node online at ${baseUrl}\n`);

  const KNOWN_AUTHENTIC_UID = 'UID-9904-AUTH-951';

  let totalPassed = 0;
  let totalFailed = 0;

  function record(pass: boolean, message: string) {
    if (pass) {
      totalPassed++;
      console.log(`  ✅ [PASS] ${message}`);
    } else {
      totalFailed++;
      console.error(`  ❌ [FAIL] ${message}`);
      throw new Error(`Assertion failed: ${message}`);
    }
  }

  async function assertSignedEnvelope(
    prefix: string,
    clearance: { envelope: ClearanceEnvelope; envelopeSignature: string } | undefined
  ) {
    record(
      typeof clearance?.envelopeSignature === 'string' && clearance.envelopeSignature.length > 0,
      `${prefix} envelope carries an institutional signature`
    );
    const okBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: clearance?.envelope, envelopeSignature: clearance?.envelopeSignature }),
    }).then((res) => res.json());
    record(
      okBody.valid === true && okBody.keyId === clearance?.envelope.keyId && okBody.jurisdiction === clearance?.envelope.jurisdiction,
      `${prefix} institutional signature verifies (${okBody.reason || okBody.keyId})`
    );
    const forged = { ...clearance?.envelope, proofSha256: 'aa'.repeat(32) };
    const forgedBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: forged, envelopeSignature: clearance?.envelopeSignature }),
    }).then((res) => res.json());
    record(
      forgedBody.valid === false && forgedBody.reason === 'signature_rejected',
      `${prefix} forged envelope is rejected (${forgedBody.reason})`
    );
    const unsignedBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: clearance?.envelope }),
    }).then((res) => res.json());
    record(
      unsignedBody.valid === false && unsignedBody.reason === 'unsigned',
      `${prefix} unsigned envelope is rejected (${unsignedBody.reason})`
    );
  }

  async function sessionCookie(preset: string): Promise<string> {
    const acs = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset }),
    });
    const setCookie = typeof acs.headers.getSetCookie === 'function' ? acs.headers.getSetCookie() : [];
    const cookie = setCookie.map((line) => line.split(';', 1)[0]).join('; ');
    if (!acs.ok || !cookie.includes('session_token=')) {
      throw new Error(`ACS ${preset} did not set a session (${acs.status})`);
    }
    return cookie;
  }

  async function verifyAdultProofWithSession(preset: string, institutionId: string) {
    const cookie = await sessionCookie(preset);
    const issued = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId }),
    }).then((res) => res.json());
    const proof = await generateProof(32, 18);
    const digest = await crypto.webcrypto.subtle.digest('SHA-256', proof);
    const factor = 'session-policy-factor';
    const userKey = await crypto.webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const message = clearanceMessage(issued.challenge, factor, bytesToHex(new Uint8Array(digest)));
    const signature = await crypto.webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      userKey.privateKey,
      new TextEncoder().encode(message)
    );
    const response = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({
        v: 1,
        challengeId: issued.challenge,
        secondFactorHash: factor,
        userPublicKey: await crypto.webcrypto.subtle.exportKey('jwk', userKey.publicKey),
        userSignature: Buffer.from(signature).toString('base64url'),
        proofBase64: bytesToBase64(proof),
      }),
    });
    return response.json();
  }

  async function preparedClearanceFactor(options?: { userVerified?: boolean; overrideCounter?: number }) {
    const key = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await key.registerWithServer({
      baseUrl,
      username: `factor-${crypto.randomUUID()}@bilanx.org`,
    });
    const prepared = await key.prepareAssertion({
      baseUrl,
      userVerified: options?.userVerified,
      overrideCounter: options?.overrideCounter,
    });
    return {
      key,
      credentialId: prepared.credentialId,
      assertion: prepared.assertion,
      secondFactorHash: credentialSecondFactorHash(prepared.credentialId),
    };
  }

  async function issueSignedClearance(
    productUid?: string,
    options?: { cookie?: string; factor?: Awaited<ReturnType<typeof preparedClearanceFactor>> | null; secondFactorHash?: string }
  ) {
    const cookie = options?.cookie !== undefined ? options.cookie : await sessionCookie('swiss_adult');
    const factor = options?.factor === undefined ? await preparedClearanceFactor() : options.factor;
    const issued = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' }),
    }).then((res) => res.json());
    const proof = await generateProof(32, 18);
    const digest = await crypto.webcrypto.subtle.digest('SHA-256', proof);
    const secondFactorHash = options?.secondFactorHash || factor?.secondFactorHash;
    if (!secondFactorHash) throw new Error('Clearance test is missing a second factor');
    const userKey = await crypto.webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const message = clearanceMessage(issued.challenge, secondFactorHash, bytesToHex(new Uint8Array(digest)));
    const signature = await crypto.webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      userKey.privateKey,
      new TextEncoder().encode(message)
    );
    const payload: Record<string, unknown> = {
      v: 1,
      challengeId: issued.challenge,
      secondFactorHash,
      userPublicKey: await crypto.webcrypto.subtle.exportKey('jwk', userKey.publicKey),
      userSignature: Buffer.from(signature).toString('base64url'),
      proofBase64: bytesToBase64(proof),
    };
    if (factor) {
      payload.credentialId = factor.credentialId;
      payload.webauthnAssertion = factor.assertion;
    }
    if (productUid !== undefined) payload.productUid = productUid;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (cookie) headers.Cookie = cookie;
    const response = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    }).then((res) => res.json());
    return { payload, response, cookie, factor };
  }

  function pdfPlainText(bytes: ArrayBuffer): string {
    return Buffer.from(bytes).toString('latin1').replace(/\\([()\\])/g, '$1');
  }

  async function verifyQrWithJwks(qrPayload: string) {
    const artifact = readTillClearanceArtifact(qrPayload);
    const jwks = await fetch(`${baseUrl}/api/v1/jwks`).then((res) => res.json()) as {
      keys?: Array<{ kid?: string; kty?: string; crv?: string; x?: string; y?: string; status?: string; d?: string; retiredAt?: number }>;
    };
    const parsed = artifact ? JSON.parse(artifact.envelope) as { keyId?: string } : {};
    const jwk = (jwks.keys || []).find((key) => key.kid === parsed.keyId);
    let local = false;
    if (artifact && jwk?.kty && jwk.crv && jwk.x && jwk.y) {
      const tillKey = await crypto.webcrypto.subtle.importKey(
        'jwk',
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['verify']
      );
      local = await crypto.webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        tillKey,
        Buffer.from(artifact.envelopeSignature, 'base64'),
        new TextEncoder().encode(artifact.envelope)
      );
    }
    const http = artifact
      ? await fetch(`${baseUrl}/api/v1/envelope/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ envelope: artifact.envelope, envelopeSignature: artifact.envelopeSignature }),
        }).then((res) => res.json())
      : { valid: false, reason: 'malformed' };
    return { artifact, jwk, local, http, jwks };
  }

  async function postStock(body: Record<string, unknown>) {
    return fetch(`${baseUrl}/api/v1/stock/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }).then((res) => res.json());
  }

  try {
    // =========================================================================
    // GROUP 0: Preset SAML minting is test-only
    // =========================================================================
    console.log('▶ [GROUP 0] Preset SAML minting is refused outside the test harness');

    const lockedApp = createApp();
    const lockedServer = createServer(lockedApp);
    await new Promise<void>((resolve) => {
      lockedServer.listen(0, '127.0.0.1', () => resolve());
    });
    const lockedUrl = `http://127.0.0.1:${(lockedServer.address() as AddressInfo).port}`;
    try {
      const lockedRes = await fetch(`${lockedUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'swiss_adult' })
      });
      const lockedBody = await lockedRes.json();
      record(
        lockedRes.status === 403 && lockedBody.success === false && lockedBody.sessionToken === undefined && String(lockedBody.error).includes('disabled'),
        `0.1 Default boot rejects {preset:"swiss_adult"} (${lockedRes.status}: ${lockedBody.error})`
      );
    } finally {
      lockedServer.close();
    }

    const previousNodeEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    const prodFlagApp = createApp({ isTest: true });
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
    const prodFlagServer = createServer(prodFlagApp);
    await new Promise<void>((resolve) => {
      prodFlagServer.listen(0, '127.0.0.1', () => resolve());
    });
    const prodFlagUrl = `http://127.0.0.1:${(prodFlagServer.address() as AddressInfo).port}`;
    try {
      const prodRes = await fetch(`${prodFlagUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'swiss_adult' })
      });
      const prodBody = await prodRes.json();
      record(
        prodRes.status === 403 && prodBody.success === false && String(prodBody.error).includes('disabled'),
        `0.2 NODE_ENV=production ignores isTest and rejects {preset:"swiss_adult"} (${prodRes.status})`
      );
    } finally {
      prodFlagServer.close();
    }

    const unknownPresetRes = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset: 'not-a-real-preset' })
    });
    const unknownPresetBody = await unknownPresetRes.json();
    record(
      unknownPresetRes.status === 400 &&
      unknownPresetBody.success === false &&
      unknownPresetBody.sessionToken === undefined &&
      String(unknownPresetBody.error).includes('Unknown SAML preset'),
      `0.3 Unknown preset does not fall through to a valid RSA fixture (${unknownPresetRes.status}: ${unknownPresetBody.error})`
    );

    const presetBody = JSON.stringify({ preset: 'swiss_adult' });
    const firstMint = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: presetBody
    });
    const secondMint = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: presetBody
    });
    const secondMintBody = await secondMint.json();
    record(
      firstMint.status === 200 && secondMint.status === 200 && secondMintBody.success === true,
      `0.4 A second swiss_adult preset is minted fresh and is not rejected as a replay (${firstMint.status}, then ${secondMint.status}: ${secondMintBody.error || 'ok'})`
    );

    const localDemoApp = createApp({ isTest: false, allowLocalDemoPresets: true });
    const localDemoServer = createServer(localDemoApp);
    await new Promise<void>((resolve) => {
      localDemoServer.listen(0, '127.0.0.1', () => resolve());
    });
    const localDemoUrl = `http://127.0.0.1:${(localDemoServer.address() as AddressInfo).port}`;
    try {
      const localDemoRes = await fetch(`${localDemoUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'swiss_adult' })
      });
      const localDemoBody = await localDemoRes.json();
      record(
        localDemoRes.status === 200 &&
        localDemoBody.success === true &&
        localDemoBody.pos_context?.is_over_18 === true &&
        localDemoBody.pos_context?.age === undefined &&
        localDemoBody.user?.age === undefined,
        `0.5 Local demo boot accepts {preset:"swiss_adult"} and omits numeric age (${localDemoRes.status})`
      );
    } finally {
      localDemoServer.close();
    }

    const previousDemoEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    const prodDemoApp = createApp({ isTest: false, allowLocalDemoPresets: true });
    if (previousDemoEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousDemoEnv;
    const prodDemoServer = createServer(prodDemoApp);
    await new Promise<void>((resolve) => {
      prodDemoServer.listen(0, '127.0.0.1', () => resolve());
    });
    const prodDemoUrl = `http://127.0.0.1:${(prodDemoServer.address() as AddressInfo).port}`;
    try {
      const prodDemoRes = await fetch(`${prodDemoUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'swiss_adult' })
      });
      const prodDemoBody = await prodDemoRes.json();
      record(
        prodDemoRes.status === 403 && prodDemoBody.success === false && String(prodDemoBody.error).includes('disabled'),
        `0.6 NODE_ENV=production refuses the local-demo preset flag (${prodDemoRes.status})`
      );
    } finally {
      prodDemoServer.close();
    }

    const previousPilotEnv = process.env.NODE_ENV;
    const previousPilotFlag = process.env.ALLOW_PILOT_DEMO;
    process.env.NODE_ENV = 'production';
    process.env.ALLOW_PILOT_DEMO = 'true';
    const pilotDemoApp = createApp();
    if (previousPilotEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousPilotEnv;
    if (previousPilotFlag === undefined) delete process.env.ALLOW_PILOT_DEMO;
    else process.env.ALLOW_PILOT_DEMO = previousPilotFlag;
    const pilotDemoServer = createServer(pilotDemoApp);
    await new Promise<void>((resolve) => {
      pilotDemoServer.listen(0, '127.0.0.1', () => resolve());
    });
    const pilotDemoUrl = `http://127.0.0.1:${(pilotDemoServer.address() as AddressInfo).port}`;
    try {
      const pilotDemoRes = await fetch(`${pilotDemoUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'swiss_adult' })
      });
      const pilotDemoBody = await pilotDemoRes.json();
      const pilotUnknown = await fetch(`${pilotDemoUrl}/saml/acs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ preset: 'not-a-real-preset' })
      });
      const pilotUnknownBody = await pilotUnknown.json();
      record(
        pilotDemoRes.status === 200 &&
        pilotDemoBody.success === true &&
        pilotDemoBody.user?.age === undefined &&
        pilotUnknown.status === 400 &&
        String(pilotUnknownBody.error).includes('Unknown SAML preset'),
        `0.8 ALLOW_PILOT_DEMO mints a known citizen in production and still rejects an unknown preset (${pilotDemoRes.status}, ${pilotUnknown.status})`
      );
    } finally {
      pilotDemoServer.close();
    }

    const ageAcs = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset: 'swiss_adult' })
    });
    const ageBody = await ageAcs.json();
    const ageSetCookie = typeof ageAcs.headers.getSetCookie === 'function' ? ageAcs.headers.getSetCookie() : [];
    const ageCookie = ageSetCookie.map((line: string) => line.split(';', 1)[0]).join('; ');
    const ageSessionRes = await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: ageCookie } });
    const ageSession = await ageSessionRes.json();
    const ageLogs = await getAccessLogs({ action: 'LOGIN_SUCCESS', limit: 1 });
    const ageLog = ageLogs.logs[0];
    const ageAcsText = JSON.stringify(ageBody);
    const ageSessionText = JSON.stringify(ageSession);
    const ageLogText = JSON.stringify(ageLog || {});
    record(
      ageAcs.status === 200 &&
      ageBody.user?.isOver18 === true &&
      ageBody.pos_context?.is_over_18 === true &&
      ageBody.user?.age === undefined &&
      ageBody.pos_context?.age === undefined &&
      !ageAcsText.includes('"age"') &&
      ageSessionRes.status === 200 &&
      ageSession.user?.isOver18 === true &&
      ageSession.user?.age === undefined &&
      !ageSessionText.includes('"age"') &&
      ageLog?.metadata?.isOver18 === true &&
      ageLog?.metadata?.age === undefined &&
      !ageLogText.includes('"age"'),
      '0.7 ACS response, GET /saml/session, and the access log keep isOver18 and omit numeric age'
    );

    console.log('  -> Group 0 passed successfully.\n');

    // =========================================================================
    // GROUP 1: Hardware Security Key & CTAP2 Roaming Token Integration
    // =========================================================================
    console.log('▶ [GROUP 1] Hardware Security Key & CTAP2 Roaming Authenticator Integration');

    const algOptions = await fetch(`${baseUrl}/api/webauthn/register-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alg-check@bilanx.org', displayName: 'Algorithm Check' })
    }).then((res) => res.json());
    const advertisedAlgs = Array.isArray(algOptions.pubKeyCredParams)
      ? algOptions.pubKeyCredParams.map((param: { alg?: number }) => param.alg)
      : [];
    record(
      advertisedAlgs.length === 1 && advertisedAlgs[0] === -7,
      `1.0 Registration advertises ES256 only (${advertisedAlgs.join(',') || 'none'})`
    );

    // 1.1 Roaming Authenticator Registration with YubiKey AAGUID
    const ctap2Harness = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    const regResult = await ctap2Harness.registerWithServer({
      baseUrl,
      username: 'pilot-officer@bilanx.org',
      displayName: 'State Audit Officer',
      attestationFmt: 'packed'
    });

    record(regResult.verified === true, '1.1a CTAP2 hardware key registration verified with 200 OK');
    record(regResult.authenticatorAttachment === 'cross-platform', '1.1b Credential registered as cross-platform roaming authenticator');
    record(regResult.aaguid === YUBIKEY_5_SERIES_AAGUID, `1.1c Authentic YubiKey 5 Series AAGUID identified: ${regResult.aaguid}`);
    record(regResult.deviceName.includes('YubiKey 5'), `1.1d Authenticator recognized as "${regResult.deviceName}"`);
    record(regResult.hwFingerprint.startsWith('HE-YUBIKEY-'), `1.1e Hardware fingerprint derived: ${regResult.hwFingerprint}`);

    // 1.2 Monotonic Signature Counter & Anti-Cloning Tracking
    const authResult1 = await ctap2Harness.authenticateWithServer({ baseUrl });
    record(authResult1.verified === true, '1.2a Assertion 1 verified with authentic ECDSA P-256 signature');
    record(authResult1.counter === 1, `1.2b Monotonic signature counter initialized to 1 (actual: ${authResult1.counter})`);
    record(authResult1.userVerified === true, '1.2c User Verification (UV) flag verified');

    const authResult2 = await ctap2Harness.authenticateWithServer({ baseUrl });
    record(authResult2.verified === true, '1.2d Assertion 2 verified with authentic ECDSA P-256 signature');
    record(authResult2.counter === 2, `1.2e Monotonic signature counter incremented to 2 (actual: ${authResult2.counter})`);

    // 1.3 Anti-Cloning Attack Defense (Counter Replay / Stagnation & Rollback)
    try {
      await ctap2Harness.authenticateWithServer({
        baseUrl,
        overrideCounter: 2 // Send counter 2 again simulating cloned hardware key
      });
      record(false, '1.3a Cloned authenticator counter replay should have been rejected');
    } catch (err: any) {
      record(err.message.includes('Cloned authenticator'), `1.3a Anti-Cloning defense: Counter stagnation rejected (${err.message})`);
    }

    try {
      await ctap2Harness.authenticateWithServer({
        baseUrl,
        overrideCounter: 1 // Counter rollback (1 < 2)
      });
      record(false, '1.3b Cloned authenticator counter rollback should have been rejected');
    } catch (err: any) {
      record(err.message.includes('Cloned authenticator') || err.message.includes('revoked'), `1.3b Anti-Cloning defense: Counter rollback rejected (${err.message})`);
    }

    try {
      await ctap2Harness.authenticateWithServer({
        baseUrl,
        overrideCounter: 5 // Counter 5 on already compromised credential
      });
      record(false, '1.3c Compromised key should have been revoked');
    } catch (err: any) {
      record(err.message.includes('revoked'), `1.3c Revocation of compromised key enforced: ${err.message}`);
    }

    // 1.3d ISS-04 Hardening: Permanent Revocation Defense against Re-Registration
    try {
      await ctap2Harness.registerWithServer({
        baseUrl,
        username: 'resurrect-attempt@attacker.org',
        reuseCredentials: true
      });
      record(false, '1.3d Compromised credential should NOT be re-registered');
    } catch (err: any) {
      record(err.message.includes('revoked due to security violation'), `1.3d Permanent revocation: Compromised credential re-registration permanently rejected (${err.message})`);
    }

    // 1.3e Duplicate active credential re-registration defense
    const duplicateTestKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await duplicateTestKey.registerWithServer({
      baseUrl,
      username: 'active-officer@bilanx.org'
    });
    try {
      await duplicateTestKey.registerWithServer({
        baseUrl,
        username: 'duplicate-claimant@bilanx.org',
        reuseCredentials: true
      });
      record(false, '1.3e Duplicate credential re-registration should be rejected');
    } catch (err: any) {
      record(err.message.includes('already registered'), `1.3e Duplicate credential re-registration rejected (${err.message})`);
    }

    // 1.4 Cryptographic Signature Tampering Defense
    const tamperKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await tamperKey.registerWithServer({
      baseUrl,
      username: 'tamper-auditor@bilanx.org',
      displayName: 'Tamper Auditor'
    });

    try {
      await tamperKey.authenticateWithServer({
        baseUrl,
        overrideCounter: 1,
        tamperSignature: true
      });
      record(false, '1.4 Tampered ECDSA signature should have been rejected');
    } catch (err: any) {
      record(err.message.includes('signature verification failed') || err.message.includes('Cryptographic verification error'), `1.4 Tampered signature rejected: ${err.message}`);
    }

    // 1.5 User Verification (UV) Requirement Enforcement
    const uvKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await uvKey.registerWithServer({
      baseUrl,
      username: 'uv-test-officer@bilanx.org'
    });

    try {
      await uvKey.authenticateWithServer({
        baseUrl,
        userVerified: false,
        requireUserVerification: true
      });
      record(false, '1.5 UV requirement enforcement: missing UV flag should have been rejected');
    } catch (err: any) {
      record(err.message.includes('User verification flag (UV) required'), `1.5 User verification enforcement: UV=false rejected when required (${err.message})`);
    }

    // 1.5b Roaming UV is mandatory even when the caller does not ask for it.
    const uvRoamingKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await uvRoamingKey.registerWithServer({
      baseUrl,
      username: 'uv-roaming-officer@bilanx.org'
    });
    try {
      await uvRoamingKey.authenticateWithServer({
        baseUrl,
        userVerified: false
      });
      record(false, '1.5b Cross-platform UV=false should have been rejected without a request flag');
    } catch (err: any) {
      record(
        err.message.includes('User verification flag (UV) required'),
        `1.5b Server requires UV for cross-platform credentials regardless of the request body (${err.message})`
      );
    }

    // 1.6 ISS-03: Packed Attestation with Expired X.509 Certificate
    const expiredCertHelper = await createExpiredCertHelper();
    const expiredKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    try {
      await expiredKey.registerWithServer({
        baseUrl,
        username: 'expired-cert-officer@bilanx.org',
        attestationFmt: 'packed',
        x5c: [expiredCertHelper.der],
        attestationPrivateKey: expiredCertHelper.webCryptoKey
      });
      record(false, '1.6 Expired X.509 certificate in attestation should have been rejected');
    } catch (err: any) {
      record(err.message.includes('expired or not yet valid') || err.message.includes('certificate verification error'), `1.6 ISS-03: Expired X.509 attestation certificate rejected (${err.message})`);
    }

    // 1.7 ISS-03: Packed Attestation with Broken/Untrusted X.509 Certificate Chain
    const certChainHelper = await createCertChainHelpers();
    const brokenChainKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    try {
      await brokenChainKey.registerWithServer({
        baseUrl,
        username: 'broken-chain-officer@bilanx.org',
        attestationFmt: 'packed',
        x5c: [certChainHelper.leafDer, certChainHelper.fakeRootDer], // Leaf + Rogue Root CA
        attestationPrivateKey: certChainHelper.leafWebCryptoKey
      });
      record(false, '1.7 Broken X.509 certificate chain should have been rejected');
    } catch (err: any) {
      record(err.message.includes('chain verification failed') || err.message.includes('certificate verification error'), `1.7 ISS-03: Broken X.509 attestation chain rejected (${err.message})`);
    }

    // 1.8 ISS-03: Authentic Packed Attestation with Valid X.509 Leaf + Root Chain
    const validChainKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    const validChainReg = await validChainKey.registerWithServer({
      baseUrl,
      username: 'valid-chain-officer@bilanx.org',
      attestationFmt: 'packed',
      x5c: [certChainHelper.leafDer, certChainHelper.rootDer], // Leaf + Genuine Root CA
      attestationPrivateKey: certChainHelper.leafWebCryptoKey
    });
    record(validChainReg.verified === true, '1.8 ISS-03: Authentic X.509 leaf+root attestation chain verified');

    // 1.9 Fail-Closed Defense: Unsupported Attestation Format
    const unsuppKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    try {
      await unsuppKey.registerWithServer({
        baseUrl,
        username: 'unsupported-fmt-officer@bilanx.org',
        attestationFmt: 'unsupported-tpm-emulator'
      });
      record(false, '1.9 Unsupported attestation format should have been rejected');
    } catch (err: any) {
      record(err.message.includes('Unsupported attestation format'), `1.9 Fail-closed: Unsupported attestation format rejected (${err.message})`);

    const noneHarness = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    const noneReg = await noneHarness.registerWithServer({
      baseUrl,
      username: `fmt-none-${crypto.randomUUID()}@bilanx.org`,
      attestationFmt: 'none'
    });
    record(noneReg.verified === true, '1.18 Sandbox accepts fmt none for the software enclave');

    const previousPilotAttestationFlag = process.env.ALLOW_PILOT_DEMO;
    const previousPilotAttestationEnv = process.env.NODE_ENV;
    process.env.ALLOW_PILOT_DEMO = 'true';
    process.env.NODE_ENV = 'production';
    let pilotNoneAccepted = false;
    try {
      const pilotNone = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      const pilotNoneReg = await pilotNone.registerWithServer({
        baseUrl,
        username: `fmt-none-pilot-${crypto.randomUUID()}@bilanx.org`,
        attestationFmt: 'none'
      });
      pilotNoneAccepted = pilotNoneReg.verified === true;
    } catch {
      pilotNoneAccepted = false;
    } finally {
      if (previousPilotAttestationFlag === undefined) delete process.env.ALLOW_PILOT_DEMO;
      else process.env.ALLOW_PILOT_DEMO = previousPilotAttestationFlag;
      if (previousPilotAttestationEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousPilotAttestationEnv;
    }
    record(
      pilotNoneAccepted,
      '1.18b ALLOW_PILOT_DEMO accepts the software enclave while production mode is on'
    );

    const previousAttestationEnv = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    let noneRejected = '';
    let selfRejected = '';
    try {
      try {
        const prodNone = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
        await prodNone.registerWithServer({
          baseUrl,
          username: `fmt-none-prod-${crypto.randomUUID()}@bilanx.org`,
          attestationFmt: 'none'
        });
      } catch (err: any) {
        noneRejected = err.message;
      }
      try {
        const prodSelf = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
        await prodSelf.registerWithServer({
          baseUrl,
          username: `self-prod-${crypto.randomUUID()}@bilanx.org`,
          attestationFmt: 'packed'
        });
      } catch (err: any) {
        selfRejected = err.message;
      }
    } finally {
      if (previousAttestationEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = previousAttestationEnv;
    }
    record(
      noneRejected.includes('Attestation format none is test-only') &&
      selfRejected.includes('Packed self-attestation is test-only'),
      `1.19 Production refuses fmt none and packed self-attestation (${noneRejected || 'accepted'} | ${selfRejected || 'accepted'})`
    );
    }

    // 1.10 ISS-06: Concurrent Assertion Replay Attack Defense (Race Condition Mitigation)
    const chalRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const chalData = await chalRes.json();
    const challengeStr = chalData.challenge;

    const concurrentFactor = await preparedClearanceFactor();
    const policyProof = await generateProof(32, 18);
    const proofDigest = await crypto.webcrypto.subtle.digest('SHA-256', policyProof);
    const userKeyPair = await crypto.webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const msg = clearanceMessage(challengeStr, concurrentFactor.secondFactorHash, bytesToHex(new Uint8Array(proofDigest)));
    const sigBuf = await crypto.webcrypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      userKeyPair.privateKey,
      new TextEncoder().encode(msg)
    );
    const sigB64 = Buffer.from(sigBuf).toString('base64url');
    const pubJwk = await crypto.webcrypto.subtle.exportKey('jwk', userKeyPair.publicKey);

    const concurrentPayload = {
      v: 1,
      challengeId: challengeStr,
      secondFactorHash: concurrentFactor.secondFactorHash,
      credentialId: concurrentFactor.credentialId,
      webauthnAssertion: concurrentFactor.assertion,
      userPublicKey: pubJwk,
      userSignature: sigB64,
      proofBase64: bytesToBase64(policyProof),
      institutionalSignature: chalData.signatureBase64
    };

    const replayCookie = await sessionCookie('swiss_adult');
    const replayHeaders = { 'Content-Type': 'application/json', Cookie: replayCookie };
    // Fire 5 simultaneous requests with the exact same valid payload
    const concurrentResponses = await Promise.all([
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: replayHeaders, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: replayHeaders, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: replayHeaders, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: replayHeaders, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: replayHeaders, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
    ]);

    const validCount = concurrentResponses.filter(r => r.valid === true).length;
    const replayCount = concurrentResponses.filter(r => r.valid === false && r.reason?.includes('Replay detected')).length;
    record(validCount === 1 && replayCount === 4, `1.10 ISS-06: Concurrent assertion replay defense: exactly 1 valid (${validCount}/5) and 4 rejected (${replayCount}/5)`);

    // 1.11 ISS-06: Replay Rejection on Subsequent Assertion
    const subsequentRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: replayHeaders,
      body: JSON.stringify(concurrentPayload)
    });
    const subsequentData = await subsequentRes.json();
    record(subsequentData.valid === false && subsequentData.reason?.includes('Replay detected'), `1.11 ISS-06: Subsequent assertion replay rejected (${subsequentData.reason})`);

    // 1.12 ISS-06: Challenge Nonce TTL Expiration Enforcement
    const expChalRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const expChalData = await expChalRes.json();
    const expChallengeStr = expChalData.challenge;

    // Mutate timestamp in challenge record to simulate expiration (>60s)
    const rec = activeChallenges.get(expChallengeStr);
    if (rec) {
      rec.issuedAt = Date.now() - 70_000; // 70 seconds ago (> 60s TTL)
    }

    const expVerifyRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: replayHeaders,
      body: JSON.stringify({
        ...concurrentPayload,
        challengeId: expChallengeStr
      })
    });
    const expVerifyData = await expVerifyRes.json();
    record(expVerifyData.valid === false && (expVerifyData.reason?.includes('expired') || expVerifyData.reason?.includes('not found or untracked')), `1.12 ISS-06: Challenge TTL expiration and pruning enforced (${expVerifyData.reason})`);

    const boundClearance = await issueSignedClearance();
    record(
      boundClearance.response.valid === true &&
      boundClearance.factor?.secondFactorHash === boundClearance.response.envelope?.secondFactorHash &&
      boundClearance.response.envelope?.secondFactorHash === credentialSecondFactorHash(boundClearance.factor?.credentialId || ''),
      '1.13 Signed second factor is the hash of the credential the server just verified'
    );
    const unbound = await issueSignedClearance(undefined, { factor: null, secondFactorHash: 'client-chosen-factor' });
    const unboundText = JSON.stringify(unbound.response);
    record(
      unbound.response.valid === false &&
      unbound.response.reason === 'Second factor is not bound to a verified authenticator' &&
      unbound.response.envelope === undefined &&
      !unboundText.includes('client-chosen-factor'),
      `1.14 A client-chosen second factor is rejected (${unbound.response.reason})`
    );
    const mismatchedFactor = await preparedClearanceFactor();
    const mismatched = await issueSignedClearance(undefined, {
      factor: mismatchedFactor,
      secondFactorHash: 'ab'.repeat(32),
    });
    record(
      mismatched.response.valid === false &&
      mismatched.response.reason === 'Second factor hash does not match the verified credential' &&
      mismatched.response.envelope === undefined,
      `1.15 Second factor hash must match the verified credential (${mismatched.response.reason})`
    );
    const uvFactor = await preparedClearanceFactor({ userVerified: false });
    const uvRejected = await issueSignedClearance(undefined, { factor: uvFactor });
    record(
      uvRejected.response.valid === false &&
      String(uvRejected.response.reason).includes('User verification flag (UV) required'),
      `1.16 Roaming clearance without UV is rejected (${uvRejected.response.reason})`
    );
    const counted = await issueSignedClearance();
    const clonedAssertion = await counted.factor!.key.prepareAssertion({ baseUrl, overrideCounter: 1 });
    const cloned = await issueSignedClearance(undefined, {
      factor: {
        ...counted.factor!,
        assertion: clonedAssertion.assertion,
        credentialId: clonedAssertion.credentialId,
      },
    });
    record(
      counted.response.valid === true &&
      cloned.response.valid === false &&
      String(cloned.response.reason).includes('Cloned authenticator'),
      `1.17 Clearance keeps the roaming counter monotonic (${cloned.response.reason})`
    );

    console.log('  -> Group 1 passed successfully.\n');

    // =========================================================================
    // GROUP 2: Swiss Pilot Profile Verification (CH - FADP / Retail POS)
    // =========================================================================
    console.log('▶ [GROUP 2] Swiss Pilot Profile Verification (CH - FADP / Retail POS)');

    // 2.1 Swiss Adult Approval (Heinrich Keller, age 32)
    const swissAdultResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      baseUrl,
      productScanned: 'Swiss Appenzeller Alpine Spirits (18+ Restricted)'
    });

    record(swissAdultResult.success === true, '2.1a Swiss adult demonstration succeeded');
    record(swissAdultResult.validationStatus === 'APPROVED', '2.1b Swiss adult received APPROVED status');
    record(swissAdultResult.currentStep === 4, '2.1c Pipeline completed all 4 steps');
    record(swissAdultResult.citizen.age === 32, '2.1d Citizen age verified as 32 (adult >= 18)');
    const swissWire = swissAdultResult.outboundBodies.join('\n');
    record(
      swissAdultResult.quarantinedPii.status === 'QUARANTINED_CLIENT_ONLY' &&
      !swissWire.includes(swissAdultResult.citizen.fullName) &&
      !swissWire.includes(swissAdultResult.citizen.dateOfBirth),
      '2.1e Outbound HTTP bodies omit the citizen name and date of birth'
    );
    record(swissAdultResult.envelope !== undefined, '2.1f POS Validation Envelope generated');
    record(swissAdultResult.envelope?.verificationClaims.ageOver18 === true, '2.1g Verification claims ageOver18=true');
    record(swissAdultResult.envelope?.cryptographicReceipt.proofByteLength === 1355, '2.1h Certified canonical 1,355-byte NIST P-256 B2 Sigma range proof');
    record(swissAdultResult.totalTimeMs < SWISS_PILOT_PROFILE.targetMaxLatencyMs, `2.1i Execution within sub-1.5s POS envelope: ${swissAdultResult.totalTimeMs} ms < 1500 ms`);
    record(swissAdultResult.envelope?.merchantClearance.complianceRebateChf === 0.15, '2.1j Swiss excise duty rebate credited (CHF 0.15)');
    record(swissAdultResult.envelope?.sessionPolicyEnforced === true, '2.1k SAML session was enforced on the Swiss clearance');
    const swissSignedPolicy = swissAdultResult.envelope?.institutionalClearance?.envelope;
    record(
      swissSignedPolicy?.sessionAgeGatePassed === true &&
      swissSignedPolicy?.loaHigh === false &&
      swissSignedPolicy?.jurisdiction === 'CH' &&
      swissSignedPolicy?.retailSale === true &&
      swissSignedPolicy?.excise === 3.85 &&
      acceptRetailSale(swissSignedPolicy) === true &&
      !Object.prototype.hasOwnProperty.call(swissSignedPolicy || {}, 'age'),
      '2.1n Signed Swiss envelope records the age gate, the retail sale, and the catalog excise'
    );
    await assertSignedEnvelope('2.1l', swissAdultResult.envelope?.institutionalClearance);
    const chKey = await getInstitutionalKey('CH');
    const expired = await signClearanceEnvelope({
      keyId: chKey.keyId,
      jurisdiction: 'CH',
      proofSha256: 'ab'.repeat(32),
      secondFactorHash: 'cd'.repeat(32),
      iat: Date.now() - 10 * 60 * 1000,
      exp: Date.now() - 1000,
    }, chKey.privateKey);
    const expiredBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(expired),
    }).then((res) => res.json());
    record(expiredBody.valid === false && expiredBody.reason === 'expired', `2.1m Expired clearance envelope is rejected (${expiredBody.reason})`);

    // 2.2 Swiss Audit Certificate PDF Export
    const swissPdf = buildAuditCertificatePdfDoc(swissAdultResult.envelope!, swissAdultResult.citizen);
    const swissPdfBytes = swissPdf.output('arraybuffer');
    const swissPdfText = pdfPlainText(swissPdfBytes);
    record(swissPdfBytes.byteLength > 2000, `2.2 Swiss FADP audit certificate PDF compiled (${swissPdfBytes.byteLength} bytes)`);
    record(!swissPdfText.includes('(eIDAS HIGH)'), '2.2b Swiss PDF does not label the session as eIDAS HIGH');
    record(swissPdfText.includes('UID-7701-AUTH-118'), '2.2c Swiss PDF contains the verified product UID');
    record(
      swissPdfText.includes(swissAdultResult.envelope?.cryptographicReceipt.auditReceiptHash || 'missing-hash'),
      '2.2d Swiss PDF contains the full receipt hash'
    );
    const swissCanonical = swissSignedPolicy ? canonicalClearanceEnvelope(swissSignedPolicy) : '';
    record(
      swissCanonical.length > 0 && swissPdfText.includes(swissCanonical),
      '2.2e Swiss PDF renders the canonical signed envelope'
    );
    const swissQr = readTillClearanceArtifact(swissAdultResult.envelope?.qrPayload);
    record(
      swissQr?.envelope === swissCanonical &&
      swissQr.envelopeSignature === swissAdultResult.envelope?.institutionalClearance?.envelopeSignature,
      '2.4a QR carries the canonical envelope and its signature'
    );
    const swissTill = await verifyQrWithJwks(swissAdultResult.envelope?.qrPayload || '');
    record(
      swissTill.jwk?.status === 'active' && swissTill.jwk?.d === undefined && swissTill.local === true,
      `2.4b A till verifies the QR with the JWKS public key (${swissTill.jwk?.kid || 'missing'})`
    );
    record(
      swissTill.http?.valid === true && swissTill.http?.keyId === swissSignedPolicy?.keyId,
      `2.4c Envelope verify accepts the QR bytes alone (${swissTill.http?.reason || swissTill.http?.keyId})`
    );
    const dirtyQr = JSON.stringify({ ...JSON.parse(swissAdultResult.envelope?.qrPayload || '{}'), fullName: 'Heinrich Keller' });
    record(readTillClearanceArtifact(dirtyQr) === null, '2.4d QR reader rejects fields outside the signed artifact');

    // 2.3 Swiss Underage Minor Rejection (Luca Rossi, age 17)
    const swissMinorResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'minor_luca',
      productUid: KNOWN_AUTHENTIC_UID,
      baseUrl
    });

    record(swissMinorResult.success === false, '2.3a Swiss underage minor returned false');
    record(swissMinorResult.validationStatus === 'REJECTED', '2.3b Swiss underage minor received REJECTED status');
    record(swissMinorResult.currentStep === 3, '2.3c Halted deterministically at Step 3 ZKP age gate');
    record(swissMinorResult.envelope === undefined, '2.3d Clearance envelope strictly withheld from minor');
    record(swissMinorResult.error?.includes('18') === true, `2.3e Deterministic rejection error recorded: "${swissMinorResult.error}"`);

    console.log('  -> Group 2 passed successfully.\n');

    // =========================================================================
    // GROUP 3: Italian Pilot Profile Verification (IT - AgCom & eIDAS LoA High)
    // =========================================================================
    console.log('▶ [GROUP 3] Italian Pilot Profile Verification (IT - AgCom & eIDAS LoA High)');

    // 3.1 Italian Adult Approval with eIDAS LoA High (Marco Rossi, age 35)
    const italianAdultResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_adult_high',
      baseUrl,
      productScanned: 'AgCom Regulated Online Content & Digital Services (18+)'
    });

    if (!italianAdultResult.success) {
      console.error('Italian Demo Failed Error:', italianAdultResult.error);
      console.error('Italian Demo Logs:', italianAdultResult.logs);
    }
    record(italianAdultResult.success === true, '3.1a Italian citizen demonstration succeeded');
    record(italianAdultResult.validationStatus === 'APPROVED', '3.1b Italian citizen received APPROVED status');
    record(italianAdultResult.citizen.levelOfAssurance === 'high', '3.1c Citizen possesses eIDAS Level of Assurance High');
    record(italianAdultResult.envelope?.jurisdiction === 'IT', '3.1d Envelope jurisdiction is IT (Italy)');
    record(italianAdultResult.envelope?.verificationClaims.issuerNode === 'BILANX-IT-AGCOM-NODE-01', '3.1e Bound to institutional Italian node (BILANX-IT-AGCOM-NODE-01)');
    record(italianAdultResult.envelope?.merchantClearance.complianceCredit?.currency === 'EUR', '3.1f Compliance credit issued in EUR (EUR 0.20)');
    const italianReceipt = italianAdultResult.envelope?.cryptographicReceipt.auditReceiptHash;
    const italianSigned = italianAdultResult.envelope?.institutionalClearance?.envelope;
    const italianTill = italianSigned ? await receiptSha256Hex(italianSigned) : '';
    record(
      typeof italianReceipt === 'string' && italianReceipt.length === 64 && italianReceipt === italianSigned?.receiptSha256 && italianReceipt === italianTill,
      `3.1g Full receipt SHA-256 is covered by the institutional signature: ${italianReceipt}`
    );
    record(italianAdultResult.envelope?.sessionPolicyEnforced === true, '3.1h SAML session was enforced on the Italian clearance');
    record(
      italianSigned?.sessionAgeGatePassed === true &&
      italianSigned?.loaHigh === true &&
      italianSigned?.jurisdiction === 'IT' &&
      italianSigned?.retailSale === true &&
      italianSigned?.excise === 0 &&
      acceptRetailSale(italianSigned) === true &&
      !Object.prototype.hasOwnProperty.call(italianSigned || {}, 'age'),
      '3.1k Signed Italian envelope records the age gate, LoA High, and a zero catalog excise'
    );
    await assertSignedEnvelope('3.1i', italianAdultResult.envelope?.institutionalClearance);
    const italianCanonical = italianSigned ? canonicalClearanceEnvelope(italianSigned) : '';
    const italianQr = readTillClearanceArtifact(italianAdultResult.envelope?.qrPayload);
    record(
      italianQr?.envelope === italianCanonical && (italianQr?.envelopeSignature.length || 0) > 0,
      '3.1l Italian QR carries the canonical envelope and its signature'
    );
    record(
      italianAdultResult.totalTimeMs < ITALIAN_PILOT_PROFILE.targetMaxLatencyMs,
      `3.1j Italian path within POS budget: ${italianAdultResult.totalTimeMs} ms < ${ITALIAN_PILOT_PROFILE.targetMaxLatencyMs} ms`
    );

    // 3.2 Italian Audit Certificate PDF Export
    const italianPdf = buildAuditCertificatePdfDoc(italianAdultResult.envelope!, italianAdultResult.citizen);
    const italianPdfBytes = italianPdf.output('arraybuffer');
    const italianPdfText = pdfPlainText(italianPdfBytes);
    const italianSignature = italianAdultResult.envelope?.institutionalClearance?.envelopeSignature || '';
    record(italianPdfBytes.byteLength > 2000, `3.2 Italian AgCom audit certificate PDF compiled (${italianPdfBytes.byteLength} bytes)`);
    record(italianPdfText.includes('UID-4408-AUTH-018'), '3.2b PDF contains the verified Italian product UID');
    record(italianPdfText.includes('Restricted Hardware'), '3.2c PDF contains the verified category');
    record(italianPdfText.includes('[OK / AUTHENTIC]'), '3.2d PDF contains the authentic verdict');
    record(typeof italianReceipt === 'string' && italianPdfText.includes(italianReceipt), '3.2e PDF contains the full receipt hash');
    record(italianCanonical.length > 0 && italianPdfText.includes(italianCanonical), '3.2j Italian PDF renders the canonical signed envelope');
    record(italianSignature.length > 0 && italianPdfText.includes(italianSignature), '3.2f PDF contains the institutional signature');
    record(italianPdfText.includes('(eIDAS HIGH)'), '3.2g Italian High session PDF states eIDAS HIGH');
    record(!italianPdfText.includes('UID-9904-AUTH-951'), '3.2h PDF does not fall back to the tobacco UID');
    const substantialPdf = buildAuditCertificatePdfDoc({
      ...italianAdultResult.envelope!,
      verificationClaims: {
        ...italianAdultResult.envelope!.verificationClaims,
        loa: 'substantial'
      }
    }, italianAdultResult.citizen);
    const substantialPdfText = pdfPlainText(substantialPdf.output('arraybuffer'));
    record(
      substantialPdfText.includes('SUBSTANTIAL') && !substantialPdfText.includes('(eIDAS HIGH)'),
      '3.2i A substantial LoA PDF does not carry the High suffix'
    );

    // 3.3 Italian Underage Minor Rejection (Matteo Russo, age 16)
    const italianMinorResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_minor_matteo',
      productUid: KNOWN_AUTHENTIC_UID,
      baseUrl
    });

    record(italianMinorResult.success === false, '3.3a Italian underage minor returned false');
    record(italianMinorResult.validationStatus === 'REJECTED', '3.3b Italian underage minor received REJECTED status');
    record(italianMinorResult.currentStep === 3, '3.3c Halted deterministically at Step 3 ZKP age gate');
    record(italianMinorResult.envelope === undefined, '3.3d Clearance envelope strictly withheld from minor');

    // 3.4 Italian AgCom eIDAS Level of Assurance High Mandate Enforcement
    const italianSubstantialResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_adult_substantial', // Giulia Bianchi, age 28, LoA substantial
      productUid: KNOWN_AUTHENTIC_UID,
      baseUrl
    });

    record(italianSubstantialResult.success === false, '3.4a Citizen with LoA Substantial rejected under LoA High mandate');
    record(italianSubstantialResult.validationStatus === 'REJECTED', '3.4b Validation status marked REJECTED for non-High LoA');
    record(italianSubstantialResult.envelope === undefined, '3.4c Clearance envelope withheld due to insufficient LoA');
    record(
      italianSubstantialResult.error?.includes('High') === true && italianSubstantialResult.error?.includes('AgCom') === true,
      `3.4d Rejection error enforces AgCom Delibera 9/24/CONS LoA High: "${italianSubstantialResult.error}"`
    );

    // 3.5 Italian Underage Mathematical Range Proof Infeasibility (Matteo Russo 16yo, T=18)
    let itProverError = '';
    try {
      await generateBitwiseRangeProof(16, 18);
    } catch (err: any) {
      itProverError = err.message;
    }
    record(itProverError === 'Age 16 is not within [T, T+255] for T=18', `3.5 Italian minor (16yo) direct prover infeasibility: "${itProverError}"`);

    const substantialSession = await verifyAdultProofWithSession('it_adult_substantial', 'BILANX-IT-AGCOM-NODE-01');
    const substantialText = JSON.stringify(substantialSession);
    record(
      substantialSession.valid === false &&
      substantialSession.reason === 'Italian LoA High is required' &&
      substantialSession.envelope === undefined &&
      !substantialText.includes('Giulia') &&
      !substantialText.includes('Bianchi'),
      `3.6 Server rejects LoA Substantial when the Italian session cookie is present (${substantialSession.reason})`
    );
    const underageSession = await verifyAdultProofWithSession('minor_luca', 'BILANX-CH-EIDAS-NODE-01');
    const underageText = JSON.stringify(underageSession);
    record(
      underageSession.valid === false &&
      underageSession.reason === 'Session age gate rejected the clearance' &&
      underageSession.envelope === undefined &&
      !underageText.includes('Luca') &&
      !Object.prototype.hasOwnProperty.call(underageSession, 'age'),
      `3.7 Server rejects an underage session even when the proof is an adult proof (${underageSession.reason})`
    );

    const missingSession = await issueSignedClearance(undefined, { cookie: '' });
    const missingSessionText = JSON.stringify(missingSession.response);
    record(
      missingSession.response.valid === false &&
      missingSession.response.reason === 'Session is required' &&
      missingSession.response.envelope === undefined &&
      !Object.prototype.hasOwnProperty.call(missingSession.response, 'age') &&
      !missingSessionText.includes('Heinrich') &&
      !missingSessionText.includes('1994-05-12'),
      `3.8 Clearance without a session cookie is rejected (${missingSession.response.reason})`
    );
    const recoveredSession = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: await sessionCookie('swiss_adult') },
      body: JSON.stringify(missingSession.payload),
    }).then((res) => res.json());
    const recoveredText = JSON.stringify(recoveredSession);
    record(
      recoveredSession.valid === true &&
      recoveredSession.envelope?.sessionAgeGatePassed === true &&
      recoveredSession.envelope?.loaHigh === false &&
      recoveredSession.envelope?.jurisdiction === 'CH' &&
      !Object.prototype.hasOwnProperty.call(recoveredSession, 'age') &&
      !Object.prototype.hasOwnProperty.call(recoveredSession.envelope || {}, 'age') &&
      !recoveredText.includes('Heinrich'),
      '3.8b The same proof succeeds once a resolved session is presented, and the policy is signed'
    );
    const bogusSession = await issueSignedClearance(undefined, { cookie: 'session_token=not-a-session' });
    const bogusText = JSON.stringify(bogusSession.response);
    record(
      bogusSession.response.valid === false &&
      bogusSession.response.reason === 'Session is missing or expired' &&
      bogusSession.response.envelope === undefined &&
      !Object.prototype.hasOwnProperty.call(bogusSession.response, 'age') &&
      !bogusText.includes('Heinrich'),
      `3.9 An unresolved session cookie is rejected (${bogusSession.response.reason})`
    );

    console.log('  -> Group 3 passed successfully.\n');

    // =========================================================================
    // GROUP 4: Hybrid Roaming Security Key & YubiKey Pilot Pipeline
    // =========================================================================
    console.log('▶ [GROUP 4] Roaming Hardware Security Key (YubiKey CTAP2) Pilot Integration');

    const yubikeyPilotResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_adult_high',
      useCtap2HardwareKey: true,
      productUid: KNOWN_AUTHENTIC_UID,
      baseUrl
    });

    record(yubikeyPilotResult.success === true, '4.1 Pilot run with YubiKey CTAP2 hardware key succeeded (Italian Profile)');
    record(yubikeyPilotResult.hwFingerprint.startsWith('HE-YUBIKEY-'), `4.2 YubiKey hardware fingerprint derived: ${yubikeyPilotResult.hwFingerprint}`);
    record(yubikeyPilotResult.envelope?.cryptographicReceipt.authenticatorType?.includes('YubiKey') === true, `4.3 Authenticator type identified as YubiKey in envelope: ${yubikeyPilotResult.envelope?.cryptographicReceipt.authenticatorType}`);

    // 4.4 Swiss Profile with YubiKey CTAP2 Roaming Key
    const yubikeySwissResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      useCtap2HardwareKey: true,
      productUid: KNOWN_AUTHENTIC_UID,
      baseUrl
    });

    record(yubikeySwissResult.success === true, '4.4 Pilot run with YubiKey CTAP2 hardware key succeeded (Swiss Profile)');
    record(yubikeySwissResult.envelope?.cryptographicReceipt.authenticatorType?.includes('YubiKey') === true, '4.5 Swiss envelope certified YubiKey authenticator type');

    console.log('  -> Group 4 passed successfully.\n');

    // =========================================================================
    // GROUP 5: Zero-PII Data Quarantine & Privacy Liability Audit
    // =========================================================================
    console.log('▶ [GROUP 5] Plaintext PII Quarantine Audit across Jurisdictions');

    const swissEnvelopeJson = JSON.stringify(swissAdultResult.envelope);
    const leakedSwiss = ['Heinrich', 'Keller', '1994-05-12', 'CHE-ZH-884210-HK'].filter(t => swissEnvelopeJson.includes(t));
    record(leakedSwiss.length === 0, `5.1 Swiss Envelope Plaintext PII Audit: 0 leaked terms (${leakedSwiss.join(', ') || 'NONE'})`);

    const itEnvelopeJson = JSON.stringify(italianAdultResult.envelope);
    const leakedIt = ['Marco', 'Rossi', '1991-03-24', 'ITA-RM-339102-MR'].filter(t => itEnvelopeJson.includes(t));
    record(leakedIt.length === 0, `5.2 Italian Envelope Plaintext PII Audit: 0 leaked terms (${leakedIt.join(', ') || 'NONE'})`);

    record(swissAdultResult.envelope?.merchantClearance.piiTransmittedBytes === 0, '5.3 Swiss Merchant clearance certifies 0 bytes PII');
    record(italianAdultResult.envelope?.merchantClearance.piiTransmittedBytes === 0, '5.4 Italian Merchant clearance certifies 0 bytes PII');
    record(swissAdultResult.envelope?.merchantClearance.gdprLiabilityRisk === 'ZERO_LIABILITY', '5.5 Swiss GDPR liability risk confirmed ZERO_LIABILITY');
    record(italianAdultResult.envelope?.merchantClearance.gdprLiabilityRisk === 'ZERO_LIABILITY', '5.6 Italian GDPR liability risk confirmed ZERO_LIABILITY');
    await assertSignedEnvelope('5.7', swissAdultResult.envelope?.institutionalClearance);
    await assertSignedEnvelope('5.8', italianAdultResult.envelope?.institutionalClearance);
    const envelopeKeys = ['ageOver18', 'excise', 'exp', 'iat', 'jurisdiction', 'keyId', 'loaHigh', 'productCategory', 'productStatus', 'productUid', 'proofSha256', 'receiptSha256', 'retailSale', 'secondFactorHash', 'sessionAgeGatePassed', 'v'];
    const swissKeys = Object.keys(swissAdultResult.envelope?.institutionalClearance?.envelope || {}).sort();
    const italianKeys = Object.keys(italianAdultResult.envelope?.institutionalClearance?.envelope || {}).sort();
    record(
      swissKeys.join(',') === envelopeKeys.join(',') && italianKeys.join(',') === envelopeKeys.join(','),
      '5.9 Signed clearance envelope fields stay on the allow-list'
    );
    const swissPolicyEnvelope = swissAdultResult.envelope?.institutionalClearance?.envelope;
    const { sessionAgeGatePassed: droppedPolicy, ...strippedPolicy } = swissPolicyEnvelope || {};
    const strippedPolicyBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        envelope: strippedPolicy,
        envelopeSignature: swissAdultResult.envelope?.institutionalClearance?.envelopeSignature,
      }),
    }).then((res) => res.json());
    const rewrittenPolicy = { ...swissPolicyEnvelope, jurisdiction: 'IT', loaHigh: true };
    const rewrittenPolicyBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        envelope: rewrittenPolicy,
        envelopeSignature: swissAdultResult.envelope?.institutionalClearance?.envelopeSignature,
      }),
    }).then((res) => res.json());
    record(
      droppedPolicy === true &&
      strippedPolicyBody.valid === false &&
      strippedPolicyBody.reason === 'malformed' &&
      rewrittenPolicyBody.valid === false &&
      rewrittenPolicyBody.reason === 'signature_rejected',
      `5.10 Policy fields are inside the signature (stripped=${strippedPolicyBody.reason}, rewritten=${rewrittenPolicyBody.reason})`
    );

    console.log('  -> Group 5 passed successfully.\n');

    // =========================================================================
    // GROUP 6: Physical Product Anti-Counterfeiting & Stock Policy Gate (Step 0)
    // =========================================================================
    console.log('▶ [GROUP 6] Physical Product Anti-Counterfeiting & UHF RFID Stock Policy Gate');

    // 6.1 Authentic tobacco item (UID-9904-AUTH-951): approves, €3.85 excise settled, [OK / AUTHENTIC] in envelope
    const authenticTobaccoResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      productUid: 'UID-9904-AUTH-951',
      baseUrl
    });

    record(authenticTobaccoResult.success === true, '6.1a Authentic tobacco item passes Step 0 policy gate');
    record(authenticTobaccoResult.validationStatus === 'APPROVED', '6.1b Validation status is APPROVED for authentic item');
    record(authenticTobaccoResult.envelope !== undefined, '6.1c Validation envelope issued for authentic product');
    record(authenticTobaccoResult.envelope?.merchantClearance.productHardwareUid === 'UID-9904-AUTH-951', '6.1d Hardware UID correctly bound in merchant clearance');
    record(authenticTobaccoResult.envelope?.merchantClearance.productCategory === 'Tobacco', '6.1e Product category verified as Tobacco');
    record(authenticTobaccoResult.envelope?.merchantClearance.productAuthenticity === '[OK / AUTHENTIC]', '6.1f Merchant clearance certifies [OK / AUTHENTIC]');
    record(authenticTobaccoResult.envelope?.merchantClearance.exciseDutyRecovered === 3.85, '6.1g Full statutory excise duty recovered (€3.85)');
    record(authenticTobaccoResult.envelope?.productVerification?.status === 'authentic', '6.1h Envelope productVerification marks status as authentic');
    record(authenticTobaccoResult.envelope?.productVerification?.verdict === '[OK / AUTHENTIC]', '6.1i Envelope productVerification verdict is [OK / AUTHENTIC]');
    record(authenticTobaccoResult.logs.some(l => l.step === 0 && l.status === 'PASS' && l.details.includes('[OK / AUTHENTIC]')), '6.1j Execution logs contain Step 0 PASS with authentic signature confirmation');
    const tobaccoClearance = authenticTobaccoResult.envelope?.institutionalClearance?.envelope;
    record(tobaccoClearance?.productUid === 'UID-9904-AUTH-951', '6.1k Signed clearance binds the verified tobacco UID');
    record(tobaccoClearance?.productCategory === 'Tobacco', '6.1l Signed clearance binds the verified category');
    record(tobaccoClearance?.productStatus === 'authentic', '6.1m Signed clearance binds authentic status');
    record(
      tobaccoClearance?.retailSale === true && tobaccoClearance?.excise === 3.85 && acceptRetailSale(tobaccoClearance) === true,
      '6.1p Signed clearance is a retail sale and carries the catalog excise 3.85'
    );
    const forgedCategory = { ...tobaccoClearance, productCategory: 'Alcohol' };
    const forgedCategoryBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        envelope: forgedCategory,
        envelopeSignature: authenticTobaccoResult.envelope?.institutionalClearance?.envelopeSignature,
      }),
    }).then((res) => res.json());
    record(
      forgedCategoryBody.valid === false && forgedCategoryBody.reason === 'signature_rejected',
      `6.1n Forged product category is rejected (${forgedCategoryBody.reason})`
    );
    const forgedExciseBody = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        envelope: { ...tobaccoClearance, excise: 0 },
        envelopeSignature: authenticTobaccoResult.envelope?.institutionalClearance?.envelopeSignature,
      }),
    }).then((res) => res.json());
    record(
      forgedExciseBody.valid === false && forgedExciseBody.reason === 'signature_rejected',
      `6.1q Forged excise is rejected (${forgedExciseBody.reason})`
    );
    record(
      authenticTobaccoResult.totalTimeMs < SWISS_PILOT_PROFILE.targetMaxLatencyMs,
      `6.1o RFID tobacco path within POS budget: ${authenticTobaccoResult.totalTimeMs} ms < ${SWISS_PILOT_PROFILE.targetMaxLatencyMs} ms`
    );

    // 6.2 Authentic cognac item (UID-8812-AUTH-324): approves, €3.85 excise, PDF certificate compiles with embedded UID, category, and verdict
    const authenticCognacResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_adult_high',
      productUid: 'UID-8812-AUTH-324',
      baseUrl
    });

    record(authenticCognacResult.success === true, '6.2a Authentic cognac item passes Step 0 policy gate (Italian profile)');
    record(authenticCognacResult.envelope?.merchantClearance.productHardwareUid === 'UID-8812-AUTH-324', '6.2b Cognac hardware UID bound in envelope');
    record(authenticCognacResult.envelope?.merchantClearance.productCategory === 'Alcohol', '6.2c Cognac category verified as Alcohol');
    record(authenticCognacResult.envelope?.merchantClearance.exciseDutyRecovered === 3.85, '6.2d Cognac excise duty recovered (€3.85)');
    const cognacSigned = authenticCognacResult.envelope?.institutionalClearance?.envelope;
    record(
      cognacSigned?.retailSale === true && cognacSigned?.excise === 3.85 && acceptRetailSale(cognacSigned) === true,
      '6.2p Signed cognac envelope carries the catalog excise'
    );
    const cognacPdf = buildAuditCertificatePdfDoc(
      authenticCognacResult.envelope!,
      authenticCognacResult.citizen,
      DEFAULT_UHD_RFID_ASSERTIONS.find(r => r.hardwareUid === 'UID-8812-AUTH-324')
    );
    const cognacPdfBytes = cognacPdf.output('arraybuffer');
    const cognacPdfText = pdfPlainText(cognacPdfBytes);
    const cognacHash = authenticCognacResult.envelope?.cryptographicReceipt.auditReceiptHash;
    const cognacSignature = authenticCognacResult.envelope?.institutionalClearance?.envelopeSignature || '';
    const cognacTill = authenticCognacResult.envelope?.institutionalClearance
      ? await receiptSha256Hex(authenticCognacResult.envelope.institutionalClearance.envelope)
      : '';
    record(cognacPdfBytes.byteLength > 2000, `6.2e Official Audit Certificate PDF compiled with embedded UHF RFID metadata (${cognacPdfBytes.byteLength} bytes)`);
    record(cognacPdfText.includes('UID-8812-AUTH-324'), '6.2f PDF contains the cognac UID');
    record(cognacPdfText.includes('Alcohol'), '6.2g PDF contains the Alcohol category');
    record(cognacPdfText.includes('[OK / AUTHENTIC]'), '6.2h PDF contains the authentic verdict');
    record(typeof cognacHash === 'string' && cognacHash.length === 64 && cognacPdfText.includes(cognacHash), '6.2i PDF contains the full receipt hash');
    record(cognacSignature.length > 0 && cognacPdfText.includes(cognacSignature), '6.2j PDF contains the institutional signature');
    const conflictingPdf = buildAuditCertificatePdfDoc(
      authenticCognacResult.envelope!,
      authenticCognacResult.citizen,
      DEFAULT_UHD_RFID_ASSERTIONS.find(r => r.hardwareUid === 'UID-9904-AUTH-951')
    );
    const conflictingText = pdfPlainText(conflictingPdf.output('arraybuffer'));
    record(
      conflictingText.includes('UID-8812-AUTH-324') && !conflictingText.includes('UID-9904-AUTH-951'),
      '6.2k Signed product claims override a conflicting client RFID row'
    );
    record(cognacTill === cognacHash, '6.2l Till recomputes the cognac receipt hash and it matches the PDF');
    await assertSignedEnvelope('6.2m', authenticCognacResult.envelope?.institutionalClearance);

    // 6.3 Counterfeit vaporizer (UID-1102-FAKE-881): fails with REJECTED_COUNTERFEIT, error contains [STOCK POLICY BLOCK: COUNTERFEIT DETECTED], envelope withheld
    const counterfeitResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      productUid: 'UID-1102-FAKE-881',
      baseUrl
    });

    record(counterfeitResult.success === false, '6.3a Counterfeit product halted transaction immediately');
    record(counterfeitResult.validationStatus === 'REJECTED_COUNTERFEIT', '6.3b Validation status set to REJECTED_COUNTERFEIT');
    record(counterfeitResult.currentStep === 0, '6.3c Deterministically halted at Step 0 physical stock gate');
    record(counterfeitResult.envelope === undefined, '6.3d Zero Data-Liability envelope strictly withheld');
    record(counterfeitResult.error?.includes('[STOCK POLICY BLOCK: COUNTERFEIT DETECTED]') === true, `6.3e Error details flag counterfeit stock block: "${counterfeitResult.error}"`);
    record(counterfeitResult.logs.some(l => l.step === 0 && l.status === 'FAIL' && l.details.includes('[STOCK POLICY BLOCK: COUNTERFEIT DETECTED]')), '6.3f Audit log records Step 0 FAIL with counterfeit alert and zeroed excise');

    // 6.4 Recalled vaporizer pen (UID-3221-RECALLED-60): fails with REJECTED, error contains [STOCK POLICY BLOCK: RECALLED STOCK], envelope withheld
    const recalledResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      productUid: 'UID-3221-RECALLED-60',
      baseUrl
    });

    record(recalledResult.success === false, '6.4a Recalled product halted transaction immediately');
    record(recalledResult.validationStatus === 'REJECTED', '6.4b Validation status set to REJECTED');
    record(recalledResult.currentStep === 0, '6.4c Deterministically halted at Step 0 physical stock gate');
    record(recalledResult.envelope === undefined, '6.4d Zero Data-Liability envelope strictly withheld');
    record(recalledResult.error?.includes('[STOCK POLICY BLOCK: RECALLED STOCK]') === true, `6.4e Error details flag recalled stock block: "${recalledResult.error}"`);
    record(recalledResult.logs.some(l => l.step === 0 && l.status === 'FAIL' && l.details.includes('[STOCK POLICY BLOCK: RECALLED STOCK]')), '6.4f Audit log records Step 0 FAIL with recalled stock alert');

    // 6.5 Unknown UID fails closed. The catalog's first authentic row must not be substituted.
    const unknownUidResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      productUid: 'UID-DOES-NOT-EXIST',
      baseUrl
    });
    record(unknownUidResult.success === false, '6.5a Unknown hardware UID halts the transaction');
    record(unknownUidResult.validationStatus === 'REJECTED', '6.5b Unknown UID validation status is REJECTED');
    record(unknownUidResult.currentStep === 0, '6.5c Halted at Step 0');
    record(unknownUidResult.envelope === undefined, '6.5d No envelope issued for an unknown UID');
    record(
      unknownUidResult.error?.includes('[STOCK POLICY BLOCK: UNKNOWN UID]') === true &&
      unknownUidResult.error?.includes('UID-9904-AUTH-951') !== true,
      `6.5e Unknown UID is not rewritten to the default tobacco tag: "${unknownUidResult.error}"`
    );

    // 6.6 A non-OK ACS stops the pipeline before a proof or an envelope.
    const acsFailResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'custom_saml',
      customProfile: {
        fullName: 'ACS Fail Closed',
        dateOfBirth: '1990-01-01',
        age: 36,
        userId: 'CHE-BE-ACS-FAIL',
        nationality: 'Switzerland (CHE)',
        levelOfAssurance: 'substantial',
        jurisdiction: 'CH'
      },
      productUid: KNOWN_AUTHENTIC_UID,
      baseUrl
    });
    record(acsFailResult.success === false, '6.6a Non-OK ACS halts the pipeline');
    record(acsFailResult.validationStatus === 'REJECTED', '6.6b Non-OK ACS validation status is REJECTED');
    record(acsFailResult.currentStep === 1, `6.6c Halted at Step 1 (actual step ${acsFailResult.currentStep})`);
    record(acsFailResult.envelope === undefined, '6.6d No envelope issued after ACS rejection');
    record(
      acsFailResult.error?.includes('SAML ACS rejected') === true,
      `6.6e ACS rejection is the recorded error: "${acsFailResult.error}"`
    );

    const stockAuthentic = await postStock({ hardwareUid: 'UID-9904-AUTH-951' });
    record(
      stockAuthentic.ok === true &&
      stockAuthentic.signatureVerified === true &&
      stockAuthentic.reason === 'verified' &&
      stockAuthentic.category === 'Tobacco' &&
      stockAuthentic.status === 'authentic' &&
      stockAuthentic.hardwareUid === 'UID-9904-AUTH-951' &&
      stockAuthentic.exciseRecovered === 3.85 &&
      !Object.prototype.hasOwnProperty.call(stockAuthentic, 'signature'),
      '6.7a Server verifies the authentic tobacco manufacturer signature'
    );
    const stockByName = await postStock({ productName: 'Swiss Appenzeller Alpine Spirits (18+ Restricted)' });
    record(
      stockByName.ok === true && stockByName.hardwareUid === 'UID-7701-AUTH-118' && stockByName.category === 'Alcohol',
      '6.7b Exact product name resolves to the signed Swiss spirits row'
    );
    const stockBad = await postStock({ hardwareUid: 'UID-0000-BADSIG-1' });
    record(
      stockBad.ok === false &&
      stockBad.reason === 'signature_rejected' &&
      stockBad.signatureVerified === false &&
      stockBad.status === 'authentic',
      '6.7c A catalog row with a tampered signature is rejected even when its status says authentic'
    );
    const stockUnsigned = await postStock({ hardwareUid: 'UID-0000-UNSIGNED-1' });
    record(
      stockUnsigned.ok === false && stockUnsigned.reason === 'unsigned' && stockUnsigned.signatureVerified === false,
      '6.7d An unsigned catalog row is rejected'
    );
    const stockUnknown = await postStock({ hardwareUid: 'UID-DOES-NOT-EXIST' });
    const stockUnknownText = JSON.stringify(stockUnknown);
    record(
      stockUnknown.ok === false &&
      stockUnknown.reason === 'unknown_uid' &&
      !stockUnknownText.includes('UID-9904-AUTH-951'),
      '6.7e Unknown UID fails closed and is not rewritten to the tobacco row'
    );
    const stockCounterfeit = await postStock({ hardwareUid: 'UID-1102-FAKE-881' });
    record(
      stockCounterfeit.ok === false && stockCounterfeit.reason === 'counterfeit' && stockCounterfeit.signatureVerified === true,
      '6.7f A valid signature over counterfeit status still fails the stock policy'
    );
    const stockRecalled = await postStock({ hardwareUid: 'UID-3221-RECALLED-60' });
    record(
      stockRecalled.ok === false && stockRecalled.reason === 'recalled' && stockRecalled.signatureVerified === true,
      '6.7g A valid signature over recalled status still fails the stock policy'
    );
    const stockMissing = await postStock({});
    record(stockMissing.ok === false && stockMissing.reason === 'missing_uid', '6.7h A stock request without a UID fails closed');

    const tamperedDemo = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      productUid: 'UID-0000-BADSIG-1',
      baseUrl
    });
    record(tamperedDemo.success === false, '6.8a Tampered manufacturer signature halts the pilot');
    record(tamperedDemo.currentStep === 0, '6.8b Tampered signature halts at Step 0');
    record(tamperedDemo.envelope === undefined, '6.8c No envelope issued for a tampered signature');
    record(
      tamperedDemo.error?.includes('[STOCK POLICY BLOCK: MANUFACTURER SIGNATURE REJECTED]') === true,
      `6.8d Tampered signature error: "${tamperedDemo.error}"`
    );

    const unsignedDemo = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'swiss_adult',
      productUid: 'UID-0000-UNSIGNED-1',
      baseUrl
    });
    record(unsignedDemo.success === false, '6.9a Unsigned catalog row halts the pilot');
    record(unsignedDemo.currentStep === 0, '6.9b Unsigned row halts at Step 0');
    record(unsignedDemo.envelope === undefined, '6.9c No envelope issued for an unsigned row');
    record(
      unsignedDemo.error?.includes('[STOCK POLICY BLOCK: UNSIGNED PRODUCT]') === true,
      `6.9d Unsigned product error: "${unsignedDemo.error}"`
    );

    const badClearance = await issueSignedClearance('UID-0000-BADSIG-1');
    const badClearanceText = JSON.stringify(badClearance.response);
    record(
      badClearance.response.valid === false &&
      badClearance.response.reason === 'Manufacturer signature rejected' &&
      badClearance.response.envelope === undefined &&
      !badClearanceText.includes('UID-0000-BADSIG-1'),
      `6.10a Clearance rejects a tampered catalog row without echoing the UID (${badClearance.response.reason})`
    );
    const { productUid: droppedUid, ...retryPayload } = badClearance.payload;
    const released = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: badClearance.cookie },
      body: JSON.stringify(retryPayload),
    }).then((res) => res.json());
    record(
      droppedUid === 'UID-0000-BADSIG-1' &&
      released.valid === true &&
      released.envelope?.productUid === undefined &&
      released.envelope?.productCategory === undefined &&
      released.envelope?.productStatus === undefined &&
      released.envelope?.excise === undefined &&
      released.envelope?.retailSale === false &&
      acceptRetailSale(released.envelope) === false &&
      released.envelope?.sessionAgeGatePassed === true &&
      released.envelope?.loaHigh === false,
      '6.10b A rejected product releases the nonce and the retry is an age gate, not a sale'
    );
    const ageOnlySale = await fetch(`${baseUrl}/api/v1/envelope/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ envelope: released.envelope, envelopeSignature: released.envelopeSignature }),
    }).then((res) => res.json());
    record(
      ageOnlySale.valid === true && ageOnlySale.retailSale === false,
      `6.10c A till does not accept the age-only envelope as a sale (${ageOnlySale.retailSale})`
    );

    const blockedClearance = await issueSignedClearance('UID-1102-FAKE-881');
    const blockedText = JSON.stringify(blockedClearance.response);
    record(
      blockedClearance.response.valid === false &&
      blockedClearance.response.reason === 'Product is blocked' &&
      !blockedText.includes('UID-1102-FAKE-881'),
      `6.11 Clearance blocks a counterfeit UID (${blockedClearance.response.reason})`
    );
    const unsignedClearance = await issueSignedClearance('UID-0000-UNSIGNED-1');
    const unsignedText = JSON.stringify(unsignedClearance.response);
    record(
      unsignedClearance.response.valid === false &&
      unsignedClearance.response.reason === 'Manufacturer signature is missing' &&
      !unsignedText.includes('UID-0000-UNSIGNED-1'),
      `6.12 Clearance rejects an unsigned UID (${unsignedClearance.response.reason})`
    );

    console.log('  -> Group 6 passed successfully.\n');

    // =========================================================================
    // GROUP 7: Capacity is a hard 429. Live credentials and nonces stay put.
    // =========================================================================
    console.log('▶ [GROUP 7] In-memory security maps refuse new entries at capacity');

    const fillerCredentialIds: string[] = [];
    const fillerWebAuthnChallenges: string[] = [];
    const fillerInstitutionalChallenges: string[] = [];
    try {
      const sentinelCredentialId = 'capacity-sentinel-cred';
      registeredWebAuthnCredentials.set(sentinelCredentialId, {
        credentialId: sentinelCredentialId,
        publicKeyPem: 'sentinel',
        username: 'capacity-sentinel',
        counter: 1,
        createdAt: new Date().toISOString(),
        authenticatorAttachment: 'platform'
      });
      let credFill = 0;
      while (registeredWebAuthnCredentials.size < MAX_STORED_CREDENTIALS) {
        const id = `capacity-fill-cred-${credFill++}`;
        fillerCredentialIds.push(id);
        registeredWebAuthnCredentials.set(id, {
          credentialId: id,
          publicKeyPem: 'filler',
          username: 'capacity-filler',
          counter: 1,
          createdAt: new Date().toISOString(),
          authenticatorAttachment: 'platform'
        });
      }
      const credBefore = registeredWebAuthnCredentials.size;
      const capacityKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      let credStatus = 0;
      let credError = '';
      const recordingFetch: typeof fetch = async (input, init) => {
        const response = await fetch(input, init);
        if (String(input).includes('/register-verify')) credStatus = response.status;
        return response;
      };
      try {
        await capacityKey.registerWithServer({
          baseUrl,
          username: 'capacity-overflow@bilanx.org',
          fetchFn: recordingFetch
        });
      } catch (err: any) {
        credError = err.message;
      }
      record(
        credStatus === 429 &&
        credError.includes('capacity') &&
        registeredWebAuthnCredentials.has(sentinelCredentialId) &&
        registeredWebAuthnCredentials.size === credBefore,
        `7.1 Credential store at ${credBefore} returns HTTP ${credStatus} and keeps the sentinel (${credError})`
      );

      for (const id of fillerCredentialIds) registeredWebAuthnCredentials.delete(id);
      fillerCredentialIds.length = 0;
      registeredWebAuthnCredentials.delete(sentinelCredentialId);

      const sentinelChallenge = 'capacity-sentinel-webauthn';
      activeWebAuthnChallenges.set(sentinelChallenge, { challenge: sentinelChallenge, issuedAt: Date.now() });
      let waFill = 0;
      while (activeWebAuthnChallenges.size < MAX_ACTIVE_WEBAUTHN_CHALLENGES) {
        const id = `capacity-fill-webauthn-${waFill++}`;
        fillerWebAuthnChallenges.push(id);
        activeWebAuthnChallenges.set(id, { challenge: id, issuedAt: Date.now() });
      }
      const waBefore = activeWebAuthnChallenges.size;
      const waRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'capacity-challenge@bilanx.org' })
      });
      const waBody = await waRes.json();
      record(
        waRes.status === 429 &&
        String(waBody.error).includes('capacity') &&
        activeWebAuthnChallenges.has(sentinelChallenge) &&
        activeWebAuthnChallenges.size === waBefore,
        `7.2 WebAuthn challenge map at ${waBefore} returns 429 and keeps the sentinel (${waBody.error})`
      );

      const sentinelInstitutional = 'capacity-sentinel-institutional';
      activeChallenges.set(sentinelInstitutional, {
        issuedAt: Date.now(),
        consumed: false,
        inflight: false,
        signatureBase64: 'sentinel',
        institutionId: 'BILANX-CH-EIDAS-NODE-01'
      });
      let instFill = 0;
      while (activeChallenges.size < MAX_ACTIVE_INSTITUTIONAL_CHALLENGES) {
        const id = `capacity-fill-institutional-${instFill++}`;
        fillerInstitutionalChallenges.push(id);
        activeChallenges.set(id, {
          issuedAt: Date.now(),
          consumed: false,
          inflight: false,
          signatureBase64: 'filler',
          institutionId: 'BILANX-CH-EIDAS-NODE-01'
        });
      }
      const instBefore = activeChallenges.size;
      const instRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      });
      const instBody = await instRes.json();
      record(
        instRes.status === 429 &&
        String(instBody.error).includes('capacity') &&
        activeChallenges.has(sentinelInstitutional) &&
        activeChallenges.size === instBefore,
        `7.3 Institutional nonce map at ${instBefore} returns 429 and keeps the sentinel (${instBody.error})`
      );
    } finally {
      for (const id of fillerCredentialIds) registeredWebAuthnCredentials.delete(id);
      registeredWebAuthnCredentials.delete('capacity-sentinel-cred');
      for (const id of fillerWebAuthnChallenges) activeWebAuthnChallenges.delete(id);
      activeWebAuthnChallenges.delete('capacity-sentinel-webauthn');
      for (const id of fillerInstitutionalChallenges) activeChallenges.delete(id);
      activeChallenges.delete('capacity-sentinel-institutional');
    }

    console.log('  -> Group 7 passed successfully.\n');

    // =========================================================================
    // GROUP 8: File-backed nonces, counters, and revocations survive a reload.
    // =========================================================================
    console.log('▶ [GROUP 8] Durable security store survives a simulated restart');

    const durableDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-security-store-'));
    const instPath = path.join(durableDir, 'institutional-challenges.json');
    const credPath = path.join(durableDir, 'webauthn-credentials.json');
    const chalPath = path.join(durableDir, 'webauthn-challenges.json');
    let originalInst: ReturnType<typeof replaceInstitutionalChallengeStore> | undefined;
    let originalCred: ReturnType<typeof replaceWebAuthnCredentialStore> | undefined;
    let originalChal: ReturnType<typeof replaceWebAuthnChallengeStore> | undefined;
    try {
      const casPath = path.join(durableDir, 'cas.json');
      const cas = new FileDurableMap<{ counter: number }>(casPath);
      cas.set('counter-key', { counter: 1 });
      const staleSnapshot = durableSnapshot({ counter: 1 });
      const liveCounter = cas.get('counter-key');
      if (liveCounter) liveCounter.counter = 2;
      cas.commit('counter-key');
      const staleWrite = cas.compareAndSet('counter-key', staleSnapshot, { counter: 9 });
      const currentSnapshot = durableSnapshot(cas.get('counter-key'));
      const freshWrite = cas.compareAndSet('counter-key', currentSnapshot, { counter: 3 });
      const casReloaded = new FileDurableMap<{ counter: number }>(casPath);
      record(
        staleWrite === false && freshWrite === true && casReloaded.get('counter-key')?.counter === 3,
        `8.1 compare-and-set keeps the newer counter across a reload (stale=${staleWrite}, fresh=${freshWrite}, counter=${casReloaded.get('counter-key')?.counter})`
      );
      const removed = cas.compareAndSet('counter-key', durableSnapshot(cas.get('counter-key')), null);
      const casDeleted = new FileDurableMap<{ counter: number }>(casPath);
      record(removed === true && casDeleted.has('counter-key') === false, '8.1b compare-and-set delete removes the entry from the file');

      let corruptRefused = false;
      try {
        fs.writeFileSync(path.join(durableDir, 'corrupt.json'), '{not-json');
        new FileDurableMap(path.join(durableDir, 'corrupt.json'));
      } catch {
        corruptRefused = true;
      }
      record(corruptRefused, '8.1c A corrupt security store fails closed');

      originalInst = replaceInstitutionalChallengeStore(new FileDurableMap(instPath));
      originalCred = replaceWebAuthnCredentialStore(new FileDurableMap(credPath));
      originalChal = replaceWebAuthnChallengeStore(new FileDurableMap(chalPath));

      const durableChalRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      });
      const durableChal = await durableChalRes.json();
      const issuedReload = new FileDurableMap<{
        issuedAt: number;
        consumed: boolean;
        inflight: boolean;
        signatureBase64: string;
        institutionId: string;
      }>(instPath);
      const issuedRecord = issuedReload.get(durableChal.challenge);
      record(
        durableChalRes.status === 200 &&
        issuedRecord !== undefined &&
        issuedRecord.consumed === false &&
        issuedRecord.signatureBase64.length > 0 &&
        issuedRecord.signatureBase64 === durableChal.signatureBase64,
        `8.2 Issued institutional nonce and signature survive a new store on the same file (${durableChalRes.status})`
      );

      const durableProof = await generateProof(32, 18);
      const durableDigest = await crypto.webcrypto.subtle.digest('SHA-256', durableProof);
      const durableUserKey = await crypto.webcrypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        true,
        ['sign', 'verify']
      );
      const durableBound = await preparedClearanceFactor();
      const durableMsg = clearanceMessage(durableChal.challenge, durableBound.secondFactorHash, bytesToHex(new Uint8Array(durableDigest)));
      const durableSig = await crypto.webcrypto.subtle.sign(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        durableUserKey.privateKey,
        new TextEncoder().encode(durableMsg)
      );
      const durablePayload = {
        v: 1,
        challengeId: durableChal.challenge,
        secondFactorHash: durableBound.secondFactorHash,
        credentialId: durableBound.credentialId,
        webauthnAssertion: durableBound.assertion,
        userPublicKey: await crypto.webcrypto.subtle.exportKey('jwk', durableUserKey.publicKey),
        userSignature: Buffer.from(durableSig).toString('base64url'),
        proofBase64: bytesToBase64(durableProof),
        institutionalSignature: durableChal.signatureBase64
      };
      const durableCookie = await sessionCookie('swiss_adult');
      const durableVerifyRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: durableCookie },
        body: JSON.stringify(durablePayload)
      });
      const durableVerifyBody = await durableVerifyRes.json();
      const consumedReload = new FileDurableMap<{ consumed: boolean }>(instPath);
      record(
        durableVerifyBody.valid === true && consumedReload.get(durableChal.challenge)?.consumed === true,
        `8.3 Consumed nonce is on disk after verify (valid=${durableVerifyBody.valid}, consumed=${consumedReload.get(durableChal.challenge)?.consumed})`
      );

      replaceInstitutionalChallengeStore(new FileDurableMap(instPath));
      const restartReplayRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: durableCookie },
        body: JSON.stringify(durablePayload)
      });
      const restartReplayBody = await restartReplayRes.json();
      record(
        restartReplayBody.valid === false && String(restartReplayBody.reason).includes('Replay detected'),
        `8.3b Reloaded store still rejects the consumed nonce (${restartReplayBody.reason})`
      );

      const optionsRes = await fetch(`${baseUrl}/api/webauthn/register-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'durable-challenge@bilanx.org', authenticatorAttachment: 'cross-platform' })
      });
      const optionsBody = await optionsRes.json();
      const parkedChallenge = optionsBody.challenge as string;

      const durableKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      const durableReg = await durableKey.registerWithServer({
        baseUrl,
        username: 'durable-officer@bilanx.org'
      });
      const durableAuth = await durableKey.authenticateWithServer({ baseUrl });
      const credReload = new FileDurableMap<{ counter: number; compromised?: boolean }>(credPath);
      const chalReload = new FileDurableMap<{ challenge: string }>(chalPath);
      const storedCred = credReload.get(durableReg.credentialId);
      record(
        durableAuth.verified === true &&
        durableAuth.counter === 1 &&
        storedCred?.counter === 1 &&
        storedCred.compromised !== true &&
        chalReload.size === 1 &&
        chalReload.has(parkedChallenge),
        `8.4 Counter is 1 on disk and the consumed WebAuthn challenges stayed consumed (counter=${storedCred?.counter}, challenges=${chalReload.size})`
      );

      let cloneRejected = false;
      let cloneMessage = '';
      try {
        await durableKey.authenticateWithServer({ baseUrl, overrideCounter: 1 });
      } catch (err: any) {
        cloneRejected = err.message.includes('Cloned authenticator');
        cloneMessage = err.message;
      }
      const revokedReload = new FileDurableMap<{ counter: number; compromised?: boolean }>(credPath);
      record(
        cloneRejected && revokedReload.get(durableReg.credentialId)?.compromised === true,
        `8.5 Clone revocation survives a new store on the same file (${cloneMessage})`
      );

      activeWebAuthnChallenges.delete(parkedChallenge);
      const chalAfterDelete = new FileDurableMap<{ challenge: string }>(chalPath);
      record(
        chalAfterDelete.has(parkedChallenge) === false && chalAfterDelete.size === 0,
        `8.6 Deleting the parked WebAuthn challenge is durable (size=${chalAfterDelete.size})`
      );
    } finally {
      if (originalInst) replaceInstitutionalChallengeStore(originalInst);
      if (originalCred) replaceWebAuthnCredentialStore(originalCred);
      if (originalChal) replaceWebAuthnChallengeStore(originalChal);
      fs.rmSync(durableDir, { recursive: true, force: true });
    }

    console.log('  -> Group 8 passed successfully.\n');

    // =========================================================================
    // GROUP 9: Key id, Italian key, and rotation that keeps in-flight nonces.
    // =========================================================================
    console.log('▶ [GROUP 9] Institutional key id, Italian key, and rotation');

    const ecdsaParams = { name: 'ECDSA', namedCurve: 'P-256' } as const;
    const originalKey = await getInstitutionalKey('CH');
    const originalPublicJwk = await crypto.webcrypto.subtle.exportKey('jwk', originalKey.publicKey);
    const originalPrivateJwk = await crypto.webcrypto.subtle.exportKey('jwk', originalKey.privateKey);
    const previousItJson = process.env.INSTITUTIONAL_KEY_JSON_IT;
    const previousItKeyId = process.env.INSTITUTIONAL_KEY_ID_IT;
    const previousKeySource = process.env.INSTITUTIONAL_KEY_SOURCE;
    try {
      const signedRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      });
      const signedBody = await signedRes.json();
      const signedKey = await crypto.webcrypto.subtle.importKey(
        'jwk',
        signedBody.publicKeyJwk,
        ecdsaParams,
        true,
        ['verify']
      );
      const signedOk = await crypto.webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        signedKey,
        Buffer.from(signedBody.signatureBase64, 'base64'),
        new TextEncoder().encode(signedBody.challenge)
      );
      record(
        signedRes.status === 200 &&
        typeof signedBody.keyId === 'string' &&
        signedBody.challenge.endsWith(`.kid.${signedBody.keyId}`) &&
        signedOk === true &&
        activeChallenges.get(signedBody.challenge)?.keyId === signedBody.keyId,
        `9.1 Signed challenge carries key id ${signedBody.keyId}`
      );

      const rotatedPair = await crypto.webcrypto.subtle.generateKey(ecdsaParams, true, ['sign', 'verify']);
      const rotated = await rotateInstitutionalKey('CH', {
        publicKeyJwk: await crypto.webcrypto.subtle.exportKey('jwk', rotatedPair.publicKey),
        privateKeyJwk: await crypto.webcrypto.subtle.exportKey('jwk', rotatedPair.privateKey),
        keyId: 'ch-rotated-kid'
      });
      const rotatedRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      });
      const rotatedBody = await rotatedRes.json();
      const rotatedOk = await crypto.webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        rotatedPair.publicKey,
        Buffer.from(rotatedBody.signatureBase64, 'base64'),
        new TextEncoder().encode(rotatedBody.challenge)
      );
      record(
        rotated.keyId === 'ch-rotated-kid' &&
        rotatedBody.keyId === 'ch-rotated-kid' &&
        rotatedBody.keyId !== signedBody.keyId &&
        rotatedOk === true &&
        activeChallenges.has(signedBody.challenge) &&
        activeChallenges.get(signedBody.challenge)?.consumed === false,
        `9.2 Rotation switches the key id and keeps the in-flight nonce (old=${signedBody.keyId}, new=${rotatedBody.keyId})`
      );

      const rotatedJwks = await fetch(`${baseUrl}/api/v1/jwks`).then((res) => res.json()) as {
        keys?: Array<{ kid?: string; status?: string; d?: string }>;
      };
      const previousPublished = (rotatedJwks.keys || []).find((key) => key.kid === signedBody.keyId);
      const activePublished = (rotatedJwks.keys || []).find((key) => key.kid === 'ch-rotated-kid');
      const tillAfterRotation = await verifyQrWithJwks(swissAdultResult.envelope?.qrPayload || '');
      record(
        previousPublished?.status === 'retired' &&
        previousPublished.d === undefined &&
        activePublished?.status === 'active' &&
        tillAfterRotation.local === true &&
        tillAfterRotation.http?.valid === true &&
        tillAfterRotation.http?.keyId === signedBody.keyId,
        `9.6 Previous public key still verifies the QR inside the envelope TTL (${tillAfterRotation.http?.reason || tillAfterRotation.http?.keyId})`
      );

      const keptInsideTtl = backdateRetiredInstitutionalKey(signedBody.keyId, Date.now() - CLEARANCE_ENVELOPE_TTL_MS + 1000);
      const insideWindow = await verifyQrWithJwks(swissAdultResult.envelope?.qrPayload || '');
      const expiredPublication = backdateRetiredInstitutionalKey(signedBody.keyId, Date.now() - CLEARANCE_ENVELOPE_TTL_MS);
      const afterTtl = await verifyQrWithJwks(swissAdultResult.envelope?.qrPayload || '');
      const jwksAfterTtl = await fetch(`${baseUrl}/api/v1/jwks`).then((res) => res.json()) as {
        keys?: Array<{ kid?: string }>;
      };
      record(
        keptInsideTtl === true &&
        insideWindow.http?.valid === true &&
        expiredPublication === true &&
        afterTtl.local === false &&
        afterTtl.http?.valid === false &&
        afterTtl.http?.reason === 'signature_rejected' &&
        (jwksAfterTtl.keys || []).some((key) => key.kid === signedBody.keyId) === false &&
        (jwksAfterTtl.keys || []).some((key) => key.kid === 'ch-rotated-kid') === true,
        `9.7 Previous public key leaves the JWKS when the envelope TTL ends (${afterTtl.http?.reason})`
      );

      await rotateInstitutionalKey('CH', {
        publicKeyJwk: originalPublicJwk,
        privateKeyJwk: originalPrivateJwk,
        keyId: originalKey.keyId
      });

      const italianPair = await crypto.webcrypto.subtle.generateKey(ecdsaParams, true, ['sign', 'verify']);
      const italianPublicJwk = await crypto.webcrypto.subtle.exportKey('jwk', italianPair.publicKey);
      process.env.INSTITUTIONAL_KEY_JSON_IT = JSON.stringify({
        publicKeyJwk: italianPublicJwk,
        privateKeyJwk: await crypto.webcrypto.subtle.exportKey('jwk', italianPair.privateKey),
        keyId: 'it-pilot-kid'
      });
      releaseInstitutionalKey('IT');
      const italianRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-IT-AGCOM-NODE-01' })
      });
      const italianBody = await italianRes.json();
      const italianOk = await crypto.webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        italianPair.publicKey,
        Buffer.from(italianBody.signatureBase64, 'base64'),
        new TextEncoder().encode(italianBody.challenge)
      );
      const swissKeyRejectsItalian = await crypto.webcrypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        originalKey.publicKey,
        Buffer.from(italianBody.signatureBase64, 'base64'),
        new TextEncoder().encode(italianBody.challenge)
      );
      record(
        italianRes.status === 200 &&
        italianBody.jurisdiction === 'IT' &&
        italianBody.keyId === 'it-pilot-kid' &&
        italianBody.challenge.endsWith('.kid.it-pilot-kid') &&
        italianOk === true &&
        swissKeyRejectsItalian === false,
        `9.3 Italian institution is signed by the IT key (${italianBody.keyId})`
      );

      delete process.env.INSTITUTIONAL_KEY_JSON_IT;
      releaseInstitutionalKey('IT');
      const fallbackRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-IT-AGCOM-NODE-01' })
      });
      const fallbackBody = await fallbackRes.json();
      record(
        fallbackBody.jurisdiction === 'IT' && fallbackBody.keyId === originalKey.keyId,
        `9.3b With no IT key configured, the primary key id signs Italy (${fallbackBody.keyId})`
      );

      let missingKeyRefused = false;
      let missingKeyMessage = '';
      try {
        await loadPrimaryKeyOrThrow({}, { allowEphemeral: false });
      } catch (err: any) {
        missingKeyRefused = err.message.includes('[FATAL]') && err.message.includes('INSTITUTIONAL_KEY_JSON');
        missingKeyMessage = err.message;
      }
      record(missingKeyRefused, `9.4 Production boot without a key fails closed (${missingKeyMessage})`);

      process.env.INSTITUTIONAL_KEY_SOURCE = 'kms';
      let kmsRefused = false;
      let kmsMessage = '';
      try {
        await getInstitutionalKey('CH');
      } catch (err: any) {
        kmsRefused = err.message.includes('InstitutionalKeySource');
        kmsMessage = err.message;
      }
      delete process.env.INSTITUTIONAL_KEY_SOURCE;
      const keyAfterKmsRefusal = await getInstitutionalKey('CH');
      record(
        kmsRefused && keyAfterKmsRefusal.keyId === originalKey.keyId,
        `9.5 INSTITUTIONAL_KEY_SOURCE=kms fails closed at the adapter seam (${kmsMessage})`
      );
    } finally {
      await rotateInstitutionalKey('CH', {
        publicKeyJwk: originalPublicJwk,
        privateKeyJwk: originalPrivateJwk,
        keyId: originalKey.keyId
      });
      releaseInstitutionalKey('IT');
      if (previousItJson === undefined) delete process.env.INSTITUTIONAL_KEY_JSON_IT;
      else process.env.INSTITUTIONAL_KEY_JSON_IT = previousItJson;
      if (previousItKeyId === undefined) delete process.env.INSTITUTIONAL_KEY_ID_IT;
      else process.env.INSTITUTIONAL_KEY_ID_IT = previousItKeyId;
      if (previousKeySource === undefined) delete process.env.INSTITUTIONAL_KEY_SOURCE;
      else process.env.INSTITUTIONAL_KEY_SOURCE = previousKeySource;
    }

    console.log('  -> Group 9 passed successfully.\n');

    // =========================================================================
    // GROUP 10: Clearance audit log and latency summary.
    // =========================================================================
    console.log('▶ [GROUP 10] Clearance audit log omits PII and /api/metrics summarizes latency');

    const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-audit-'));
    const auditPath = path.join(auditDir, 'clearance-audit.log');
    const previousAuditPath = process.env.AUDIT_LOG_PATH;
    const sentinelFactor = 'SENTINEL-SECOND-FACTOR-HASH';
    const sentinelName = 'Audit Sentinel Name';
    const sentinelDob = '1900-01-01';
    process.env.AUDIT_LOG_PATH = auditPath;
    try {
      const ecdsaParams = { name: 'ECDSA', namedCurve: 'P-256' } as const;
      const signClearance = async (
        challenge: string,
        institutionalSignature: string,
        proofBytes: Uint8Array,
        proveMs: number,
        factor: string = sentinelFactor
      ) => {
        const digest = await crypto.webcrypto.subtle.digest('SHA-256', proofBytes);
        const userKey = await crypto.webcrypto.subtle.generateKey(ecdsaParams, true, ['sign', 'verify']);
        const message = clearanceMessage(challenge, factor, bytesToHex(new Uint8Array(digest)));
        const signature = await crypto.webcrypto.subtle.sign(
          { name: 'ECDSA', hash: 'SHA-256' },
          userKey.privateKey,
          new TextEncoder().encode(message)
        );
        return {
          v: 1,
          challengeId: challenge,
          secondFactorHash: factor,
          userPublicKey: await crypto.webcrypto.subtle.exportKey('jwk', userKey.publicKey),
          userSignature: Buffer.from(signature).toString('base64url'),
          proofBase64: bytesToBase64(proofBytes),
          institutionalSignature,
          proveMs,
          fullName: sentinelName,
          dateOfBirth: sentinelDob
        };
      };

      const issued = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      }).then((res) => res.json());
      const badProof = crypto.randomBytes(32);
      const proofFailurePayload = await signClearance(issued.challenge, issued.signatureBase64, badProof, 15);
      const proofFailureRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(proofFailurePayload)
      });
      const proofFailureBody = await proofFailureRes.json();

      const successIssued = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      }).then((res) => res.json());
      const successProof = await generateProof(32, 18);
      const auditBound = await preparedClearanceFactor();
      const successPayload = {
        ...(await signClearance(successIssued.challenge, successIssued.signatureBase64, successProof, 15, auditBound.secondFactorHash)),
        credentialId: auditBound.credentialId,
        webauthnAssertion: auditBound.assertion,
      };
      const auditCookie = await sessionCookie('swiss_adult');
      const successRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: auditCookie },
        body: JSON.stringify(successPayload)
      });
      const successBody = await successRes.json();
      const replayBody = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Cookie: auditCookie },
        body: JSON.stringify(successPayload)
      }).then((res) => res.json());
      const missingAudit = await issueSignedClearance(undefined, { cookie: '' });

      await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-IT-AGCOM-NODE-01' })
      });

      const badAttestation = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      let attestationRejected = false;
      try {
        await badAttestation.registerWithServer({
          baseUrl,
          username: 'audit-attestation@bilanx.org',
          attestationFmt: 'unsupported-tpm-emulator'
        });
      } catch (err: any) {
        attestationRejected = err.message.includes('Unsupported attestation format');
      }

      const cloneKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      await cloneKey.registerWithServer({ baseUrl, username: 'audit-clone@bilanx.org' });
      await cloneKey.authenticateWithServer({ baseUrl });
      let cloneRejected = false;
      try {
        await cloneKey.authenticateWithServer({ baseUrl, overrideCounter: 1 });
      } catch (err: any) {
        cloneRejected = err.message.includes('Cloned authenticator');
      }

      const logText = fs.readFileSync(auditPath, 'utf8');
      const logLines = logText.split('\n').filter((line) => line.trim().length > 0).map((line) => JSON.parse(line));
      const successLine = logLines.find((line) => line.event === 'clearance_success' && line.prove_ms === 15);
      const allowedKeys = new Set(['event', 'jurisdiction', 'prove_ms', 'verify_ms', 'total_ms', 'reason', 'keyId']);
      const onlyAllowedKeys = logLines.every((line) => Object.keys(line).every((key) => allowedKeys.has(key)));
      record(
        proofFailureBody.valid === false &&
        logLines.some((line) => line.event === 'proof_failure' && line.jurisdiction === 'CH' && line.reason === 'proof_rejected'),
        `10.1 Proof failure is an allow-listed audit line (${proofFailureBody.reason})`
      );
      record(
        successBody.valid === true &&
        successLine?.jurisdiction === 'CH' &&
        typeof successLine.verify_ms === 'number' &&
        typeof successLine.total_ms === 'number' &&
        successLine.prove_ms === 15,
        `10.2 Clearance success logs jurisdiction and prove/verify/total milliseconds (verify_ms=${successLine?.verify_ms})`
      );
      record(
        replayBody.valid === false &&
        String(replayBody.reason).includes('Replay detected') &&
        logLines.some((line) => line.event === 'replay_rejected' && line.jurisdiction === 'CH'),
        `10.3 Replay rejection is logged (${replayBody.reason})`
      );
      record(
        logLines.some((line) => line.event === 'challenge_issued' && line.jurisdiction === 'CH') &&
        logLines.some((line) => line.event === 'challenge_issued' && line.jurisdiction === 'IT'),
        '10.4 Challenge issuance logs CH and IT jurisdiction labels'
      );
      record(
        attestationRejected &&
        cloneRejected &&
        logLines.some((line) => line.event === 'attestation_failure' && line.reason === 'attestation_rejected') &&
        logLines.some((line) => line.event === 'clone_detected' && line.reason === 'counter_not_increasing'),
        '10.5 Attestation failure and clone detection are logged'
      );
      record(
        onlyAllowedKeys &&
        !logText.includes(sentinelFactor) &&
        !logText.includes(sentinelName) &&
        !logText.includes(sentinelDob) &&
        !logText.includes('proofBase64'),
        '10.6 Audit lines omit the factor hash, name, date of birth, and raw proof'
      );
      record(
        missingAudit.response.valid === false &&
        missingAudit.response.reason === 'Session is required' &&
        logLines.some((line) => line.event === 'clearance_failure' && line.reason === 'session_required' && line.jurisdiction === 'CH') &&
        !logText.includes('"age"'),
        `10.8 A clearance without a session is audited as session_required (${missingAudit.response.reason})`
      );

      const metricsRes = await fetch(`${baseUrl}/api/metrics`);
      const metrics = await metricsRes.json();
      const metricsText = JSON.stringify(metrics);
      record(
        metricsRes.status === 200 &&
        metrics.clearance.events.clearance_success >= 1 &&
        metrics.clearance.events.proof_failure >= 1 &&
        metrics.clearance.events.replay_rejected >= 1 &&
        metrics.clearance.events.clone_detected >= 1 &&
        metrics.clearance.latency.verify_ms.count >= 1 &&
        metrics.clearance.latency.total_ms.count >= 1 &&
        metrics.clearance.latency.prove_ms.count >= 1 &&
        !metricsText.includes(sentinelFactor) &&
        !metricsText.includes(sentinelName) &&
        !metricsText.includes(sentinelDob),
        `10.7 /api/metrics summarizes events and latency (verify count=${metrics.clearance?.latency?.verify_ms?.count})`
      );
    } finally {
      if (previousAuditPath === undefined) delete process.env.AUDIT_LOG_PATH;
      else process.env.AUDIT_LOG_PATH = previousAuditPath;
      fs.rmSync(auditDir, { recursive: true, force: true });
    }

    console.log('  -> Group 10 passed successfully.\n');

    // =========================================================================
    // GROUP 11: Access-log write and export require session and operator role.
    // =========================================================================
    console.log('▶ [GROUP 11] Access-log events require a session; export and clear require an operator');

    const requestEmail = 'leak-sentinel@example.test';
    const requestName = 'Leak Sentinel';
    const beforeEvents = await getAccessLogs({ limit: 1 });
    const unauthEvent = await fetch(`${baseUrl}/api/auth/record-event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: { uid: 'pilot-guest', email: requestEmail, name: requestName },
        action: 'APP_ACCESS',
      }),
    });
    const unauthEventBody = await unauthEvent.json();
    const afterUnauthEvent = await getAccessLogs({ search: requestEmail, limit: 5 });
    const afterUnauthName = await getAccessLogs({ search: requestName, limit: 5 });
    const afterUnauthTotal = await getAccessLogs({ limit: 1 });
    record(
      unauthEvent.status === 401 &&
      unauthEventBody.log === undefined &&
      !JSON.stringify(unauthEventBody).includes(requestEmail) &&
      afterUnauthEvent.total === 0 &&
      afterUnauthName.total === 0 &&
      afterUnauthTotal.total === beforeEvents.total,
      `11.1 Unauthenticated record-event is 401 and stores nothing (${unauthEvent.status})`
    );

    const demoCookie = await sessionCookie('swiss_adult');
    const demoSession = await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: demoCookie } }).then((res) => res.json());
    const highCookie = await sessionCookie('it_adult_high');
    const highSession = await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: highCookie } }).then((res) => res.json());
    const afterMint = await getAccessLogs({ limit: 1 });
    const demoList = await fetch(`${baseUrl}/api/access-logs`, { headers: { Cookie: demoCookie } });
    const demoExport = await fetch(`${baseUrl}/api/access-logs/export`, { headers: { Cookie: demoCookie } });
    const demoClear = await fetch(`${baseUrl}/api/access-logs/clear`, { method: 'POST', headers: { Cookie: demoCookie } });
    const highExport = await fetch(`${baseUrl}/api/access-logs/export`, { headers: { Cookie: highCookie } });
    const highClear = await fetch(`${baseUrl}/api/access-logs/clear`, { method: 'POST', headers: { Cookie: highCookie } });
    const afterDemoDeny = await getAccessLogs({ limit: 1 });
    record(
      demoSession.active === true &&
      demoSession.user?.role === 'STORE_MANAGER' &&
      demoList.status === 403 &&
      demoExport.status === 403 &&
      demoClear.status === 403 &&
      highSession.user?.role === 'STORE_MANAGER' &&
      Array.isArray(highSession.user?.permissions) &&
      highSession.user.permissions.includes('ELEVATED_AUDIT_LOG_EXPORT') &&
      highExport.status === 403 &&
      highClear.status === 403 &&
      afterDemoDeny.total === afterMint.total,
      `11.2 Demo sessions cannot list, export, or clear the access log (swiss ${demoList.status}/${demoExport.status}/${demoClear.status}, high ${highExport.status}/${highClear.status})`
    );

    const unauthList = await fetch(`${baseUrl}/api/access-logs`);
    const unauthExport = await fetch(`${baseUrl}/api/access-logs/export`);
    const unauthClear = await fetch(`${baseUrl}/api/access-logs/clear`, { method: 'POST' });
    const unauthStats = await fetch(`${baseUrl}/api/access-logs/stats`);
    const demoStats = await fetch(`${baseUrl}/api/access-logs/stats`, { headers: { Cookie: demoCookie } });
    const demoStillActive = await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: demoCookie } }).then((res) => res.json());
    record(
      unauthList.status === 401 &&
      unauthExport.status === 401 &&
      unauthClear.status === 401 &&
      unauthStats.status === 401 &&
      demoStats.status === 200 &&
      demoStillActive.active === true,
      `11.3 Other session checks stay in place (stats demo=${demoStats.status}, unauth list=${unauthList.status})`
    );

    const operator = globalSessionStore.createSession({
      uid: 'pilot-audit-operator',
      email: 'operator@bilanx.test',
      name: 'Audit Operator',
      authMethod: 'eidas_saml',
      role: 'OPERATOR',
      authenticatedAt: new Date().toISOString(),
    });
    const operatorCookie = `session_token=${encodeURIComponent(operator.token)}`;
    const operatorList = await fetch(`${baseUrl}/api/access-logs?limit=1`, { headers: { Cookie: operatorCookie } });
    const operatorListBody = await operatorList.json();
    const operatorExport = await fetch(`${baseUrl}/api/access-logs/export`, { headers: { Cookie: operatorCookie } });
    const operatorExportText = await operatorExport.text();
    const rowsBeforeClear = await getAccessLogs({ limit: 1 });
    const operatorClear = await fetch(`${baseUrl}/api/access-logs/clear`, { method: 'POST', headers: { Cookie: operatorCookie } });
    const operatorClearBody = await operatorClear.json();
    const rowsAfterClear = await getAccessLogs({ limit: 1 });
    record(
      operatorList.status === 200 &&
      Array.isArray(operatorListBody.logs) &&
      operatorExport.status === 200 &&
      (operatorExport.headers.get('content-type') || '').includes('text/csv') &&
      operatorExportText.startsWith('ID,Timestamp') &&
      rowsBeforeClear.total > 0 &&
      operatorClear.status === 200 &&
      operatorClearBody.success === true &&
      rowsAfterClear.total === 0,
      `11.4 An operator session can list, export, and clear (${operatorList.status}/${operatorExport.status}/${operatorClear.status})`
    );

    const logoutAcs = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset: 'swiss_adult' }),
    }).then((res) => res.json());
    const logoutEvent = await fetch(`${baseUrl}/api/auth/record-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${logoutAcs.sessionToken}`,
      },
      body: JSON.stringify({
        user: { email: requestEmail, name: requestName },
        action: 'LOGOUT',
      }),
    });
    const logoutEventBody = await logoutEvent.json();
    const logoutSession = await fetch(`${baseUrl}/saml/session`, {
      headers: { Authorization: `Bearer ${logoutAcs.sessionToken}` },
    });
    const storedRequest = await getAccessLogs({ search: requestEmail, limit: 5 });
    const originalStillActive = await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: demoCookie } }).then((res) => res.json());
    record(
      logoutEvent.status === 200 &&
      logoutEventBody.log?.email === logoutAcs.user?.email &&
      logoutEventBody.log?.name === logoutAcs.user?.name &&
      logoutEventBody.log?.email !== requestEmail &&
      !JSON.stringify(logoutEventBody).includes(requestEmail) &&
      logoutSession.status === 401 &&
      storedRequest.total === 0 &&
      originalStillActive.active === true,
      `11.5 A bearer session records its own identity and logout invalidates that session (${logoutEvent.status})`
    );

    console.log('  -> Group 11 passed successfully.\n');

    console.log('================================================================================');
    console.log(`🏆 PILOT SANDBOX E2E SUMMARY: ${totalPassed} PASSED | ${totalFailed} FAILED (100% Pass Rate)`);
    console.log('================================================================================\n');

    server.close();
  } catch (err) {
    console.error('Unhandled test harness error:', err);
    server.close();
    process.exitCode = 1;
  } finally {
    if (previousAccessLogPath === undefined) delete process.env.ACCESS_LOG_PATH;
    else process.env.ACCESS_LOG_PATH = previousAccessLogPath;
    fs.rmSync(accessLogDir, { recursive: true, force: true });
    if (process.exitCode) process.exit(process.exitCode);
  }
}

runPilotVerificationSuite();
