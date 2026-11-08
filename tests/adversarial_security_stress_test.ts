/**
 * Bilanx — Dual-Key Sovereign Validation System (DK-SVS)
 * Comprehensive Adversarial Security & Tampering Defense Stress Test Suite
 * Generation 7 Adversarial Audit (Challenger 1 Replacement)
 * 
 * Empirically challenges and stress-tests:
 * - Vector 1: Underage Citizen Bypass Attempts (Minor Luca Rossi 17yo, Mathematical Rejection, Threshold Tampering)
 * - Vector 2: Second-Factor Hardware Fingerprint Tampering (MitM Alteration, Bit-Flip, Anti-Replay)
 * - Vector 3: WebAuthn Origin Spoofing / Untrusted Origin Attacks (Phishing, Subdomain, Null, Fail-Closed)
 * - Vector 4: ZKP Proof Corruption & Signature Tampering (Truncation, Bit-Commitment, Scalar Blinding, Dual-Key Signatures)
 * - Vector 5: PII Quarantine Leakage Check (Envelope, QR Matrix, Wire Payloads, 0 Bytes Guarantee)
 */

import { createServer } from 'http';
import type { AddressInfo } from 'net';
import { createApp } from '../src/server/app.ts';
import { runSwissDemonstration } from '../src/sandbox/lib/e2e/runSwissDemonstration.ts';
import { 
  SoftwareSecureEnclaveSimulator, 
  deriveHardwareFingerprint 
} from '../src/lib/crypto/simulatorEnclave.ts';
import { 
  generateBitwiseRangeProof, 
  verifyBitwiseRangeProof 
} from '../src/lib/crypto/zkp/range_b2.ts';
import { 
  encodeBitwiseRangeProof, 
  decodeBitwiseRangeProof 
} from '../src/lib/crypto/zkp/range_b2_codec.ts';
import { bytesToBase64, base64ToBytes, bytesToHex } from '../src/lib/crypto/encoding.ts';
import { generateProof } from '../src/lib/crypto/zkp/nizkp.ts';
import { clearanceMessage } from '../src/lib/crypto/clearanceMessage.ts';
import { performDualKeyHandshake } from '../src/sandbox/hooks/useBilanxDualKeyValidation.real.ts';

async function proofSha256Hex(proof: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', proof);
  return bytesToHex(new Uint8Array(digest));
}

async function signClearance(
  privateKey: CryptoKey,
  challengeId: string,
  factor: string,
  proof: Uint8Array
): Promise<string> {
  const message = clearanceMessage(challengeId, factor, await proofSha256Hex(proof));
  const sig = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    new TextEncoder().encode(message)
  );
  return Buffer.from(sig).toString('base64url');
}

interface TestSummary {
  vector: string;
  id: string;
  name: string;
  expected: string;
  observed: string;
  verdict: 'PASS' | 'FAIL';
}

async function runAdversarialTestSuite() {
  console.log('================================================================================');
  console.log('🛡️  BILANX DK-SVS ADVERSARIAL SECURITY & TAMPERING DEFENSE STRESS TEST SUITE');
  console.log('    Generation 7 Challenger Audit — Empirical Verification');
  console.log('================================================================================\n');

  // Boot ephemeral Express server with createApp()
  const app = createApp({ isTest: true });
  const server = createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[TEST-ENV] Ephemeral test server active on ${baseUrl}\n`);

  const summary: TestSummary[] = [];

  function record(vector: string, id: string, name: string, expected: string, observed: string, passed: boolean) {
    const verdict = passed ? 'PASS' : 'FAIL';
    summary.push({ vector, id, name, expected, observed, verdict });
    const mark = passed ? '✅' : '❌';
    console.log(`  ${mark} [${id}] ${name}: ${observed}`);
    if (!passed) {
      throw new Error(`Test failed: [${id}] ${name}. Expected ${expected}, got ${observed}`);
    }
  }

  try {
    // =========================================================================
    // ATTACK VECTOR 1: Underage Citizen Bypass Attempts
    // =========================================================================
    console.log('▶ [VECTOR 1] Stress-Testing Underage Citizen Bypass Defense...');

    // 1.1 Complete E2E pipeline execution with Luca Rossi (age 17)
    const minorE2EResult = await runSwissDemonstration({
      citizenPreset: 'minor_luca',
      productUid: 'UID-9904-AUTH-951',
      baseUrl
    });
    record(
      'Vector 1',
      'V1.1',
      'Luca Rossi (17yo) E2E Pipeline Rejection',
      'success=false, validationStatus=REJECTED, envelope=undefined, step=3',
      `success=${minorE2EResult.success}, status=${minorE2EResult.validationStatus}, envelope=${minorE2EResult.envelope ? 'ISSUED' : 'NONE'}, step=${minorE2EResult.currentStep}`,
      minorE2EResult.success === false &&
      minorE2EResult.validationStatus === 'REJECTED' &&
      minorE2EResult.envelope === undefined &&
      minorE2EResult.currentStep === 3 &&
      minorE2EResult.error?.includes('18') === true
    );

    // 1.2 Prover direct call with underage age (17 < 18)
    let proverUnderageError = '';
    try {
      await generateBitwiseRangeProof(17, 18);
    } catch (err: any) {
      proverUnderageError = err.message;
    }
    record(
      'Vector 1',
      'V1.2',
      'Direct Prover Mathematical Infeasibility (age=17, T=18)',
      'Error: Age 17 is not within [T, T+255] for T=18',
      proverUnderageError,
      proverUnderageError === 'Age 17 is not within [T, T+255] for T=18'
    );

    // 1.3 Boundary ages check (ages: 0, 10, 15, 16, 17)
    const boundaryAges = [0, 10, 15, 16, 17];
    let allBoundaryUnderageRejected = true;
    for (const age of boundaryAges) {
      try {
        await generateBitwiseRangeProof(age, 18);
        allBoundaryUnderageRejected = false;
        break;
      } catch (err: any) {
        // Any mathematical rejection (range or invalid scalar) is valid fail-closed behavior
        if (!err.message.includes('not within [T, T+255]') && !err.message.includes('invalid scalar')) {
          allBoundaryUnderageRejected = false;
        }
      }
    }
    record(
      'Vector 1',
      'V1.3',
      'Underage Boundary Sweep (ages 0, 10, 15, 16, 17)',
      'All rejected mathematically',
      allBoundaryUnderageRejected ? 'All 5 boundary ages rejected' : 'Leakage detected',
      allBoundaryUnderageRejected
    );

    // 1.4 Attack: Prover proves age 17 against T=16, then alters threshold byte to T=18
    // Since 17 >= 16, prover can generate valid proof for T=16
    const proofT16 = await generateBitwiseRangeProof(17, 16);
    const serializedT16 = encodeBitwiseRangeProof(proofT16);
    // Mutate threshold byte (offset 1) from 16 to 18
    const tamperedThresholdBytes = new Uint8Array(serializedT16);
    tamperedThresholdBytes[1] = 18; // Attacker pretends proof is for T=18

    const forgeKey = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const forgeJwk = await crypto.subtle.exportKey('jwk', forgeKey.publicKey);
    const forgeChallengeRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const forgeChallenge = await forgeChallengeRes.json();
    const forgeSig = await signClearance(forgeKey.privateKey, forgeChallenge.challenge, 'HE-P256-FORGE', tamperedThresholdBytes);
    const verifyForgeRes = await fetch(`${baseUrl}/api/v1/age-gate/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: forgeChallenge.challenge,
        secondFactorHash: 'HE-P256-FORGE',
        userPublicKey: forgeJwk,
        userSignature: forgeSig,
        proofBase64: bytesToBase64(tamperedThresholdBytes)
      })
    });
    const verifyForgeData = await verifyForgeRes.json();
    record(
      'Vector 1',
      'V1.4',
      'Forged Threshold Byte Attack (T=16 morphed to T=18)',
      'valid=false (Fiat-Shamir challenge discrepancy)',
      `valid=${verifyForgeData.valid}`,
      verifyForgeData.valid === false
    );

    // =========================================================================
    // ATTACK VECTOR 2: Second-Factor Hardware Fingerprint Tampering
    // =========================================================================
    console.log('\n▶ [VECTOR 2] Stress-Testing Second-Factor Hardware Fingerprint Tampering Defense...');

    // 2.1 E2E Pipeline Hardware Fingerprint Tampering flag
    const tamperedFpResult = await runSwissDemonstration({
      citizenPreset: 'swiss_adult',
      productUid: 'UID-9904-AUTH-951',
      baseUrl,
      tamperHardwareFingerprint: true
    });
    record(
      'Vector 2',
      'V2.1',
      'Pipeline In-Transit HW_FINGERPRINT Tampering',
      'success=false, validationStatus=REJECTED, envelope=undefined',
      `success=${tamperedFpResult.success}, status=${tamperedFpResult.validationStatus}, envelope=${tamperedFpResult.envelope ? 'ISSUED' : 'NONE'}`,
      tamperedFpResult.success === false &&
      tamperedFpResult.validationStatus === 'REJECTED' &&
      tamperedFpResult.envelope === undefined &&
      tamperedFpResult.error?.includes('Tampering') === true
    );

    // 2.2 Dual-Key Handshake with genuine institutional challenge but MitM altered second factor
    // Generate valid challenge
    const instChallengeRes = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const instChallengeData = await instChallengeRes.json();
    const challengeStr = instChallengeData.challenge;

    // Generate local user keypair and sign authentic second factor
    const authenticFp = 'HE-P256-AUTHENTIC-FINGERPRINT';
    const policyProof = await generateProof(32, 18);
    const userKeyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    const userSigB64 = await signClearance(userKeyPair.privateKey, challengeStr, authenticFp, policyProof);
    const userPublicKeyJwk = await crypto.subtle.exportKey('jwk', userKeyPair.publicKey);

    // MitM Attack: Attacker substitutes secondFactorHash with tampered value
    const tamperedMitMRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: challengeStr,
        secondFactorHash: 'HE-P256-MALICIOUS-INJECTED-FP',
        userPublicKey: userPublicKeyJwk,
        userSignature: userSigB64,
        proofBase64: bytesToBase64(policyProof),
        institutionalSignature: instChallengeData.signatureBase64
      })
    });
    const tamperedMitMData = await tamperedMitMRes.json();
    record(
      'Vector 2',
      'V2.2',
      'MitM Substituted secondFactorHash in Dual-Key Verification',
      'valid=false, reason="Signature verification failed"',
      `valid=${tamperedMitMData.valid}, reason="${tamperedMitMData.reason}"`,
      tamperedMitMData.valid === false && tamperedMitMData.reason === 'Signature verification failed'
    );

    // 2.3 Bit-flip attack on secondFactorHash
    const instChallengeRes23 = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const instChallengeData23 = await instChallengeRes23.json();
    const challengeStr23 = instChallengeData23.challenge;

    const userSigB6423 = await signClearance(userKeyPair.privateKey, challengeStr23, authenticFp, policyProof);

    const singleBitFlippedFp = authenticFp.slice(0, -1) + (authenticFp.endsWith('A') ? 'B' : 'A');
    const bitFlipRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: challengeStr23,
        secondFactorHash: singleBitFlippedFp,
        userPublicKey: userPublicKeyJwk,
        userSignature: userSigB6423,
        proofBase64: bytesToBase64(policyProof),
        institutionalSignature: instChallengeData23.signatureBase64
      })
    });
    const bitFlipData = await bitFlipRes.json();
    record(
      'Vector 2',
      'V2.3',
      'Single-Character Alteration of secondFactorHash',
      'valid=false, reason="Signature verification failed"',
      `valid=${bitFlipData.valid}, reason="${bitFlipData.reason}"`,
      bitFlipData.valid === false && bitFlipData.reason === 'Signature verification failed'
    );

    // 2.4 Missing / Null secondFactorHash
    const nullFpRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: 'dummy-challenge-id',
        secondFactorHash: '',
        userPublicKey: userPublicKeyJwk,
        userSignature: userSigB64,
        proofBase64: bytesToBase64(policyProof)
      })
    });
    record(
      'Vector 2',
      'V2.4',
      'Empty secondFactorHash Payload Rejection',
      'HTTP 400 Bad Request',
      `HTTP ${nullFpRes.status}`,
      nullFpRes.status === 400
    );

    // 2.5 Concurrent Parallel Assertion Replay Defense (ISS-06)
    const instChallengeRes25 = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    });
    const instChallengeData25 = await instChallengeRes25.json();
    const challengeStr25 = instChallengeData25.challenge;

    const userSigB6425 = await signClearance(userKeyPair.privateKey, challengeStr25, authenticFp, policyProof);

    const concurrentPayload = {
      v: 1,
      challengeId: challengeStr25,
      secondFactorHash: authenticFp,
      userPublicKey: userPublicKeyJwk,
      userSignature: userSigB6425,
      proofBase64: bytesToBase64(policyProof),
      institutionalSignature: instChallengeData25.signatureBase64
    };

    const concurrentResults = await Promise.all([
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
      fetch(`${baseUrl}/api/v1/dual-key/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(concurrentPayload) }).then(r => r.json()),
    ]);
    const validCount = concurrentResults.filter(r => r.valid === true).length;
    const replayCount = concurrentResults.filter(r => r.valid === false && r.reason?.includes('Replay detected')).length;
    record(
      'Vector 2',
      'V2.5',
      'Concurrent Parallel Assertion Replay Defense (5 simultaneous requests)',
      'Exactly 1 valid, 4 replay rejected',
      `valid=${validCount}/5, replayRejected=${replayCount}/5`,
      validCount === 1 && replayCount === 4
    );

    // =========================================================================
    // ATTACK VECTOR 3: WebAuthn Origin Spoofing / Untrusted Origin Attacks
    // =========================================================================
    console.log('\n▶ [VECTOR 3] Stress-Testing WebAuthn Origin Spoofing Defense...');

    const untrustedOrigins = [
      'https://malicious-phishing-eidas.ch',
      'http://attacker-controlled.net',
      'https://bilanx.swiss.evilcorp.com',
      'http://192.168.1.200:3000',
      'null'
    ];

    let allUntrustedOriginsRejected = true;
    for (const origin of untrustedOrigins) {
      // Test register-verify
      const regRes = await fetch(`${baseUrl}/api/auth/webauthn/register-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': origin
        },
        body: JSON.stringify({
          username: 'victim@bilanx.ch',
          credential: {
            id: 'mock-cred-id',
            response: { clientDataJSON: 'e30' }
          }
        })
      });
      const regData = await regRes.json();

      // Test authenticate-verify
      const authRes = await fetch(`${baseUrl}/api/auth/webauthn/authenticate-verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Origin': origin
        },
        body: JSON.stringify({
          credential: {
            id: 'mock-cred-id',
            response: { clientDataJSON: 'e30' }
          }
        })
      });
      const authData = await authRes.json();

      if (regRes.status !== 400 || regData.verified !== false ||
          authRes.status !== 400 || authData.verified !== false) {
        allUntrustedOriginsRejected = false;
        console.error(`Failed on origin: ${origin}, regStatus: ${regRes.status}, authStatus: ${authRes.status}`);
        break;
      }
    }

    record(
      'Vector 3',
      'V3.1',
      'Untrusted Origins Fail-Closed Hardening (5 hostile origins)',
      'All 5 hostile origins rejected with HTTP 400 and verified=false',
      allUntrustedOriginsRejected ? '100% fail-closed rejection across all 5 origins' : 'Leakage detected',
      allUntrustedOriginsRejected
    );

    // 3.2 Verify authorized origin succeeds
    const sim = new SoftwareSecureEnclaveSimulator();
    const regOptRes = await fetch(`${baseUrl}/api/auth/webauthn/register-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'challenger-test@bilanx.ch' })
    });
    const regOpt = await regOptRes.json();
    const att = await sim.createCredential(regOpt);

    const validOriginRegRes = await fetch(`${baseUrl}/api/auth/webauthn/register-verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': baseUrl
      },
      body: JSON.stringify({
        username: 'challenger-test@bilanx.ch',
        credential: {
          id: att.id,
          rawId: att.rawId,
          type: att.type,
          response: att.response
        }
      })
    });
    const validRegData = await validOriginRegRes.json();
    record(
      'Vector 3',
      'V3.2',
      'Whitelisted Origin (127.0.0.1:<port>) Acceptance',
      'HTTP 200 OK, verified=true',
      `HTTP ${validOriginRegRes.status}, verified=${validRegData.verified}`,
      validOriginRegRes.status === 200 && validRegData.verified === true
    );

    // =========================================================================
    // ATTACK VECTOR 4: ZKP Proof Corruption & Signature Tampering
    // =========================================================================
    console.log('\n▶ [VECTOR 4] Stress-Testing ZKP Proof Corruption & Signature Tampering...');

    // Generate authentic 1355-byte proof for adult (age 25, threshold 18)
    const validProofObj = await generateBitwiseRangeProof(25, 18);
    const validProofBytes = encodeBitwiseRangeProof(validProofObj);
    record(
      'Vector 4',
      'V4.0',
      'Canonical Baseline Proof Generation',
      'Exact 1355 bytes',
      `${validProofBytes.length} bytes`,
      validProofBytes.length === 1355
    );

    async function postSignedClearance(proof: Uint8Array, signatureOverride?: string) {
      const issued = await fetch(`${baseUrl}/api/institutional-challenge`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
      }).then(r => r.json());
      const signature = signatureOverride ?? await signClearance(
        userKeyPair.privateKey,
        issued.challenge,
        authenticFp,
        proof
      );
      const res = await fetch(`${baseUrl}/api/v1/age-gate/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          v: 1,
          challengeId: issued.challenge,
          secondFactorHash: authenticFp,
          userPublicKey: userPublicKeyJwk,
          userSignature: signature,
          proofBase64: bytesToBase64(proof),
          institutionalSignature: issued.signatureBase64
        })
      });
      return { res, data: await res.json(), challenge: issued.challenge as string };
    }

    // 4.1 Truncated Proofs (length 0, length 3, length 1354)
    const truncatedLengths = [0, 3, 100, 1354];
    const truncatedNotes: string[] = [];
    let allTruncatedRejected = true;
    for (const len of truncatedLengths) {
      const truncated = validProofBytes.slice(0, len);
      if (len === 0) {
        const emptyRes = await fetch(`${baseUrl}/api/v1/age-gate/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            v: 1,
            challengeId: 'unused-empty-proof',
            secondFactorHash: authenticFp,
            userPublicKey: userPublicKeyJwk,
            userSignature: 'AAAA',
            institutionalSignature: 'AAAA'
          })
        });
        const emptyData = await emptyRes.json();
        truncatedNotes.push(`0:${emptyRes.status}`);
        if (emptyRes.status !== 400 || emptyData.valid !== false) allTruncatedRejected = false;
        continue;
      }
      const { res, data } = await postSignedClearance(truncated);
      truncatedNotes.push(`${len}:${res.status}:${data.reason || data.error}`);
      const codecRejected = data.valid === false && String(data.reason || '').includes('1355');
      if (!codecRejected) allTruncatedRejected = false;
    }
    record(
      'Vector 4',
      'V4.1',
      'Truncated Binary Proofs (lengths 0, 3, 100, 1354)',
      'Empty proof is HTTP 400; other lengths fail the 1355-byte codec',
      truncatedNotes.join(' | '),
      allTruncatedRejected
    );

    // 4.2 Oversized Proof (1356 bytes)
    const oversized = new Uint8Array(1356);
    oversized.set(validProofBytes);
    oversized[1355] = 0xAA;
    const oversizedPosted = await postSignedClearance(oversized);
    record(
      'Vector 4',
      'V4.2',
      'Oversized Proof (1356 bytes with trailing byte)',
      'valid=false, codec length rejection',
      `valid=${oversizedPosted.data.valid}, reason="${oversizedPosted.data.reason}"`,
      oversizedPosted.data.valid === false && String(oversizedPosted.data.reason || '').includes('1355')
    );

    // 4.3 Version Byte Corruption (byte 0)
    const badVersion = new Uint8Array(validProofBytes);
    badVersion[0] = 2;
    const badVersionPosted = await postSignedClearance(badVersion);
    record(
      'Vector 4',
      'V4.3',
      'Unsupported Proof Version (byte 0 = 2)',
      'valid=false, unsupported version',
      `valid=${badVersionPosted.data.valid}, reason="${badVersionPosted.data.reason}"`,
      badVersionPosted.data.valid === false && String(badVersionPosted.data.reason || '').includes('Unsupported proof version')
    );

    // 4.4 Bit Commitment Corruption (tampering byte in C_0)
    const badBitCommitment = new Uint8Array(validProofBytes);
    badBitCommitment[36] ^= 0xFF;
    const badBitPosted = await postSignedClearance(badBitCommitment);
    record(
      'Vector 4',
      'V4.4',
      'Bit Commitment Tampering (C_0 byte corruption)',
      'valid=false, Verification failed',
      `valid=${badBitPosted.data.valid}, reason="${badBitPosted.data.reason}"`,
      badBitPosted.data.valid === false && badBitPosted.data.reason === 'Verification failed'
    );

    // 4.5 Schnorr Response Tampering (s_0 byte in bit 0)
    const badSchnorr = new Uint8Array(validProofBytes);
    badSchnorr[100] ^= 0x42;
    const badSchnorrPosted = await postSignedClearance(badSchnorr);
    record(
      'Vector 4',
      'V4.5',
      'Schnorr Response Tampering (s_0 scalar mutation)',
      'valid=false, Verification failed',
      `valid=${badSchnorrPosted.data.valid}, reason="${badSchnorrPosted.data.reason}"`,
      badSchnorrPosted.data.valid === false && badSchnorrPosted.data.reason === 'Verification failed'
    );

    // 4.6 Scalar Blinding Factor r_diff Tampering (last 32 bytes)
    const badRDiff = new Uint8Array(validProofBytes);
    badRDiff[1340] ^= 0x77;
    const badRDiffPosted = await postSignedClearance(badRDiff);
    record(
      'Vector 4',
      'V4.6',
      'Sum-Check Scalar Tampering (r_diff corruption)',
      'valid=false, Verification failed',
      `valid=${badRDiffPosted.data.valid}, reason="${badRDiffPosted.data.reason}"`,
      badRDiffPosted.data.valid === false && badRDiffPosted.data.reason === 'Verification failed'
    );

    // 4.7 Dual-Key Signature Byte Tampering over a bound proof
    const honestSig = await signClearance(userKeyPair.privateKey, 'placeholder', authenticFp, validProofBytes);
    const tamperedSigB64 = honestSig.slice(0, -4) + 'AAAA';
    const tamperedPosted = await postSignedClearance(validProofBytes, tamperedSigB64);
    record(
      'Vector 4',
      'V4.7',
      'Tampered User ECDSA Signature in Dual-Key Handshake',
      'valid=false, reason="Signature verification failed"',
      `valid=${tamperedPosted.data.valid}, reason="${tamperedPosted.data.reason}"`,
      tamperedPosted.data.valid === false && tamperedPosted.data.reason === 'Signature verification failed'
    );

    // 4.8 Missing proof is rejected before the nonce is touched.
    const missingProofIssued = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    }).then(r => r.json());
    const missingProofRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: missingProofIssued.challenge,
        secondFactorHash: authenticFp,
        userPublicKey: userPublicKeyJwk,
        userSignature: tamperedSigB64,
        institutionalSignature: missingProofIssued.signatureBase64
      })
    });
    const missingProofData = await missingProofRes.json();
    record(
      'Vector 4',
      'V4.8',
      'Clearance without an age proof',
      'HTTP 400, valid=false, missing fields',
      `HTTP ${missingProofRes.status}, valid=${missingProofData.valid}, error="${missingProofData.error}"`,
      missingProofRes.status === 400 && missingProofData.valid === false && String(missingProofData.error || '').includes('Missing')
    );

    // 4.9 Prover-chosen threshold is not policy.
    const underThresholdProof = await generateProof(5, 0);
    const underThresholdPosted = await postSignedClearance(underThresholdProof);
    record(
      'Vector 4',
      'V4.9',
      'Proof threshold 0 rejected by server policy 18',
      'valid=false, Threshold 0 is not the policy threshold 18',
      `valid=${underThresholdPosted.data.valid}, reason="${underThresholdPosted.data.reason}"`,
      underThresholdPosted.data.valid === false &&
      underThresholdPosted.data.reason === 'Threshold 0 is not the policy threshold 18'
    );

    // 4.10 A bad signature releases the nonce. A later valid signature still clears.
    const retryIssued = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId: 'BILANX-CH-EIDAS-NODE-01' })
    }).then(r => r.json());
    const retryProof = validProofBytes;
    const retryGoodSig = await signClearance(userKeyPair.privateKey, retryIssued.challenge, authenticFp, retryProof);
    const retryBadRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: retryIssued.challenge,
        secondFactorHash: authenticFp,
        userPublicKey: userPublicKeyJwk,
        userSignature: tamperedSigB64,
        proofBase64: bytesToBase64(retryProof),
        institutionalSignature: retryIssued.signatureBase64
      })
    });
    const retryBadData = await retryBadRes.json();
    const retryGoodRes = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        v: 1,
        challengeId: retryIssued.challenge,
        secondFactorHash: authenticFp,
        userPublicKey: userPublicKeyJwk,
        userSignature: retryGoodSig,
        proofBase64: bytesToBase64(retryProof),
        institutionalSignature: retryIssued.signatureBase64
      })
    });
    const retryGoodData = await retryGoodRes.json();
    record(
      'Vector 4',
      'V4.10',
      'Bad signature does not consume the nonce',
      'first valid=false Signature verification failed; retry valid=true',
      `first="${retryBadData.reason}", retry valid=${retryGoodData.valid} reason="${retryGoodData.reason || ''}"`,
      retryBadData.valid === false &&
      retryBadData.reason === 'Signature verification failed' &&
      retryGoodData.valid === true
    );

    // =========================================================================
    // ATTACK VECTOR 5: PII Quarantine Leakage Check
    // =========================================================================
    console.log('\n▶ [VECTOR 5] Stress-Testing PII Quarantine Leakage Defenses...');

    // Execute Swiss Adult (Heinrich Keller)
    const swissAdult = await runSwissDemonstration({
      citizenPreset: 'swiss_adult',
      productUid: 'UID-9904-AUTH-951',
      baseUrl
    });
    const swissEnvelopeStr = JSON.stringify(swissAdult.envelope);

    // Execute EU Adult (Dr. Clara Schmidt)
    const euAdult = await runSwissDemonstration({
      citizenPreset: 'eu_adult',
      productUid: 'UID-9904-AUTH-951',
      baseUrl
    });
    const euEnvelopeStr = JSON.stringify(euAdult.envelope);

    // 5.1 Heinrich Keller PII leak check in Envelope
    const leakedSwissPii = [
      'Heinrich', 'Keller', '1994-05-12', 'CHE-ZH-884210-HK', '884210', 'Zurich'
    ].filter(term => swissEnvelopeStr.includes(term));
    record(
      'Vector 5',
      'V5.1',
      'Swiss Adult Envelope Plaintext PII Quarantine Audit',
      '0 leaked terms',
      `${leakedSwissPii.length} leaked terms (${leakedSwissPii.join(', ') || 'NONE'})`,
      leakedSwissPii.length === 0
    );

    // 5.2 Dr. Clara Schmidt PII leak check in Envelope
    const leakedEuPii = [
      'Clara', 'Schmidt', '1988-11-20', 'DEU-BER-991204-CS', '991204', 'Berlin'
    ].filter(term => euEnvelopeStr.includes(term));
    record(
      'Vector 5',
      'V5.2',
      'EU Adult Envelope Plaintext PII Quarantine Audit',
      '0 leaked terms',
      `${leakedEuPii.length} leaked terms (${leakedEuPii.join(', ') || 'NONE'})`,
      leakedEuPii.length === 0
    );

    // 5.3 QR Code payload PII leak check
    const qrPayloadStr = swissAdult.envelope?.qrPayload || '';
    const leakedQrPii = [
      'Heinrich', 'Keller', '1994-05-12', 'CHE-ZH-884210-HK'
    ].filter(term => qrPayloadStr.includes(term));
    record(
      'Vector 5',
      'V5.3',
      'QR Code Matrix Payload Plaintext PII Quarantine Audit',
      '0 leaked terms',
      `${leakedQrPii.length} leaked terms`,
      leakedQrPii.length === 0
    );

    // 5.4 Merchant Clearance Liability & PII Transmitted Bytes confirmation
    const piiBytes = swissAdult.envelope?.merchantClearance.piiTransmittedBytes;
    const liability = swissAdult.envelope?.merchantClearance.gdprLiabilityRisk;
    record(
      'Vector 5',
      'V5.4',
      'Merchant Clearance Zero Data-Liability Guarantees',
      'piiTransmittedBytes=0, gdprLiabilityRisk=ZERO_LIABILITY',
      `piiTransmittedBytes=${piiBytes}, gdprLiabilityRisk=${liability}`,
      piiBytes === 0 && liability === 'ZERO_LIABILITY'
    );

    // 5.5 Outbound HTTP bodies carry neither the preset name nor the date of birth.
    const outboundWire = [...swissAdult.outboundBodies, ...euAdult.outboundBodies].join('\n');
    const leakedWireTerms = [
      swissAdult.citizen.fullName,
      swissAdult.citizen.dateOfBirth,
      euAdult.citizen.fullName,
      euAdult.citizen.dateOfBirth
    ].filter(term => outboundWire.includes(term));
    record(
      'Vector 5',
      'V5.5',
      'Outbound HTTP bodies omit preset name and date of birth',
      'status=QUARANTINED_CLIENT_ONLY, 0 name or birth-date terms on the wire',
      `status=${swissAdult.quarantinedPii.status}, leaked=${leakedWireTerms.join(', ') || 'NONE'}`,
      swissAdult.quarantinedPii.status === 'QUARANTINED_CLIENT_ONLY' &&
      leakedWireTerms.length === 0
    );

    console.log('\n================================================================================');
    console.log(`🏆 ALL ${summary.length}/${summary.length} ADVERSARIAL STRESS TEST CASES PASSED WITH 100% SUCCESS!`);
    console.log('================================================================================\n');

  } finally {
    server.close();
  }
}

runAdversarialTestSuite().catch((err) => {
  console.error('\n❌ ADVERSARIAL SECURITY STRESS TEST RUNNER FAILED:');
  console.error(err);
  process.exit(1);
});
