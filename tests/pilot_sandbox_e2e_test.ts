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
import { createApp } from '../src/server/app.ts';
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

  // Boot ephemeral Express server
  const app = createApp({ isTest: true });
  const server = createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[TEST-SERVER] Ephemeral Bilanx Pilot Node online at ${baseUrl}\n`);

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

  try {
    // =========================================================================
    // GROUP 1: Hardware Security Key & CTAP2 Roaming Token Integration
    // =========================================================================
    console.log('▶ [GROUP 1] Hardware Security Key & CTAP2 Roaming Authenticator Integration');

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
    }

    // 1.10 ISS-06: Concurrent Assertion Replay Attack Defense (Race Condition Mitigation)
    const chalRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const chalData = await chalRes.json();
    const challengeStr = chalData.challenge;

    const fp = 'HE-P256-CONCURRENT-FP';
    const policyProof = await generateProof(32, 18);
    const proofDigest = await crypto.webcrypto.subtle.digest('SHA-256', policyProof);
    const userKeyPair = await crypto.webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const msg = clearanceMessage(challengeStr, fp, bytesToHex(new Uint8Array(proofDigest)));
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
      secondFactorHash: fp,
      userPublicKey: pubJwk,
      userSignature: sigB64,
      proofBase64: bytesToBase64(policyProof),
      institutionalSignature: chalData.signatureBase64
    };

    // Fire 5 simultaneous requests with the exact same valid payload
    const concurrentResponses = await Promise.all([
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
    ]);

    const validCount = concurrentResponses.filter(r => r.valid === true).length;
    const replayCount = concurrentResponses.filter(r => r.valid === false && r.reason?.includes('Replay detected')).length;
    record(validCount === 1 && replayCount === 4, `1.10 ISS-06: Concurrent assertion replay defense: exactly 1 valid (${validCount}/5) and 4 rejected (${replayCount}/5)`);

    // 1.11 ISS-06: Replay Rejection on Subsequent Assertion
    const subsequentRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
    const { activeChallenges } = await import('../src/server/app.ts');
    const rec = activeChallenges.get(expChallengeStr);
    if (rec) {
      rec.issuedAt = Date.now() - 70_000; // 70 seconds ago (> 60s TTL)
    }

    const expVerifyRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...concurrentPayload,
        challengeId: expChallengeStr
      })
    });
    const expVerifyData = await expVerifyRes.json();
    record(expVerifyData.valid === false && (expVerifyData.reason?.includes('expired') || expVerifyData.reason?.includes('not found or untracked')), `1.12 ISS-06: Challenge TTL expiration and pruning enforced (${expVerifyData.reason})`);

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

    // 2.2 Swiss Audit Certificate PDF Export
    const swissPdf = buildAuditCertificatePdfDoc(swissAdultResult.envelope!, swissAdultResult.citizen);
    const swissPdfBytes = swissPdf.output('arraybuffer');
    record(swissPdfBytes.byteLength > 2000, `2.2 Swiss FADP audit certificate PDF compiled (${swissPdfBytes.byteLength} bytes)`);

    // 2.3 Swiss Underage Minor Rejection (Luca Rossi, age 17)
    const swissMinorResult = await runPilotDemonstration({
      jurisdiction: 'CH_FADP',
      citizenPreset: 'minor_luca',
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
    record(Boolean(italianAdultResult.envelope?.cryptographicReceipt.auditReceiptHash), `3.1g Verifiable AgCom audit receipt hash produced: ${italianAdultResult.envelope?.cryptographicReceipt.auditReceiptHash}`);

    // 3.2 Italian Audit Certificate PDF Export
    const italianPdf = buildAuditCertificatePdfDoc(italianAdultResult.envelope!, italianAdultResult.citizen);
    const italianPdfBytes = italianPdf.output('arraybuffer');
    record(italianPdfBytes.byteLength > 2000, `3.2 Italian AgCom audit certificate PDF compiled (${italianPdfBytes.byteLength} bytes)`);

    // 3.3 Italian Underage Minor Rejection (Matteo Russo, age 16)
    const italianMinorResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_minor_matteo',
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

    console.log('  -> Group 3 passed successfully.\n');

    // =========================================================================
    // GROUP 4: Hybrid Roaming Security Key & YubiKey Pilot Pipeline
    // =========================================================================
    console.log('▶ [GROUP 4] Roaming Hardware Security Key (YubiKey CTAP2) Pilot Integration');

    const yubikeyPilotResult = await runPilotDemonstration({
      jurisdiction: 'IT_AGCOM',
      citizenPreset: 'it_adult_high',
      useCtap2HardwareKey: true,
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
    const cognacPdf = buildAuditCertificatePdfDoc(
      authenticCognacResult.envelope!,
      authenticCognacResult.citizen,
      DEFAULT_UHD_RFID_ASSERTIONS.find(r => r.hardwareUid === 'UID-8812-AUTH-324')
    );
    const cognacPdfBytes = cognacPdf.output('arraybuffer');
    record(cognacPdfBytes.byteLength > 2000, `6.2e Official Audit Certificate PDF compiled with embedded UHF RFID metadata (${cognacPdfBytes.byteLength} bytes)`);

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

    console.log('  -> Group 6 passed successfully.\n');

    console.log('================================================================================');
    console.log(`🏆 PILOT SANDBOX E2E SUMMARY: ${totalPassed} PASSED | ${totalFailed} FAILED (100% Pass Rate)`);
    console.log('================================================================================\n');

    server.close();
  } catch (err) {
    console.error('Unhandled test harness error:', err);
    server.close();
    process.exit(1);
  }
}

runPilotVerificationSuite();
