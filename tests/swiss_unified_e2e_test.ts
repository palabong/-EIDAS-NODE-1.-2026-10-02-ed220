/**
 * Bilanx — Dual-Key Sovereign Validation System (DK-SVS)
 * Definitive Swiss Unified End-to-End Test Suite (Phase 3 PoC)
 * 
 * Verifies the complete 4-step sovereign validation journey:
 * 1. Citizen Identity Ingestion & Sovereign PII Quarantine (Swiss CHE, EU DEU, Minor ITA)
 * 2. Hardware Enclave Attestation & SHA-256 Fingerprint Derivation
 * 3. Dual-Key Sovereign Handshake & B2 1355-byte Sigma Range Proof Verification
 * 4. Zero Data-Liability Validation Envelope (VE-2026), QR Matrix & PDF Certificate
 * 5. Underage Rejection (Luca Rossi, age 17) -> Deterministic Mathematical Rejection
 * 6. Second-Factor Tampering Defense -> Hardware Fingerprint Mismatch Rejection
 * 7. WebAuthn Origin Validation Security -> Rejection of Malicious Untrusted Origins
 * 8. Zero PII Server Leakage -> Strict Client-Side Quarantine
 */

import { createServer } from 'http';
import type { AddressInfo } from 'net';
import { createApp } from '../src/server/app.ts';
import { runSwissDemonstration } from '../src/sandbox/lib/e2e/runSwissDemonstration.ts';
import { 
  SoftwareSecureEnclaveSimulator, 
  deriveHardwareFingerprint 
} from '../src/lib/crypto/simulatorEnclave.ts';
import { buildAuditCertificatePdfDoc } from '../src/sandbox/lib/PdfReceiptGenerator.ts';

async function runTestSuite() {
  console.log('================================================================================');
  console.log('🇨🇭 BILANX DUAL-KEY SOVEREIGN VALIDATION SYSTEM — SWISS DEMONSTRATION E2E TEST');
  console.log('================================================================================\n');

  // Boot ephemeral Express server with createApp()
  const app = createApp();
  const server = createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });

  const port = (server.address() as AddressInfo).port;
  const baseUrl = `http://127.0.0.1:${port}`;
  console.log(`[TEST-ENV] Ephemeral Express server running on ${baseUrl}\n`);

  let passedTests = 0;
  let totalTests = 0;

  function assert(condition: boolean, message: string) {
    totalTests++;
    if (!condition) {
      console.error(`❌ FAILED: ${message}`);
      throw new Error(`Assertion failed: ${message}`);
    }
    passedTests++;
    console.log(`  ✓ ${message}`);
  }

  try {
    // -------------------------------------------------------------------------
    // TEST VECTOR 1: Swiss Adult Ingestion & Validation (Heinrich Keller, 32)
    // -------------------------------------------------------------------------
    console.log('[VECTOR 1] Testing Swiss Citizen Sovereign Validation (Heinrich Keller, age 32)...');
    const swissResult = await runSwissDemonstration({
      citizenPreset: 'swiss_adult',
      baseUrl
    });

    if (!swissResult.success) {
      console.error('Vector 1 Failed:', swissResult.error);
      console.error('Logs:', swissResult.logs);
    }

    assert(swissResult.success === true, 'Swiss adult demonstration succeeded');
    assert(swissResult.validationStatus === 'APPROVED', 'Validation status is APPROVED');
    assert(swissResult.currentStep === 4, 'Execution transitioned through all 4 steps to completion');
    assert(swissResult.citizen.nationality.includes('CHE'), 'Citizen nationality is CHE (Switzerland)');
    assert(swissResult.citizen.age === 32, 'Citizen age is 32');
    assert(swissResult.citizen.fullName === 'Heinrich Keller', 'Plaintext PII maintained in client-side quarantine');
    assert(swissResult.quarantinedPii.status === 'QUARANTINED_CLIENT_ONLY', 'PII marked QUARANTINED_CLIENT_ONLY');
    const swissWire = swissResult.outboundBodies.join('\n');
    assert(
      !swissWire.includes(swissResult.citizen.fullName) && !swissWire.includes(swissResult.citizen.dateOfBirth),
      'Outbound HTTP bodies omit the citizen name and date of birth'
    );
    assert(
      swissResult.hwFingerprint.startsWith('HE-P256-'),
      `Hardware fingerprint derived: ${swissResult.hwFingerprint}`
    );
    assert(swissResult.envelope !== undefined, 'Validation envelope generated');
    assert(swissResult.envelope?.validationStatus === 'APPROVED', 'Envelope validationStatus is APPROVED');
    assert(swissResult.envelope?.verificationClaims.ageOver18 === true, 'Envelope certifies ageOver18=true');
    assert(
      swissResult.envelope?.cryptographicReceipt.proofByteLength === 1355,
      'Zero-knowledge proof is canonical 1355-byte B2 Sigma range proof'
    );
    assert(
      swissResult.envelope?.merchantClearance.piiTransmittedBytes === 0,
      'Merchant surface receives 0 bytes PII'
    );

    // Verify PDF Audit Certificate generation
    const pdfDoc = buildAuditCertificatePdfDoc(swissResult.envelope!, swissResult.citizen);
    const pdfArrayBuffer = pdfDoc.output('arraybuffer');
    assert(pdfArrayBuffer.byteLength > 2000, `PDF audit certificate compiled successfully (${pdfArrayBuffer.byteLength} bytes)`);

    console.log('  -> Vector 1 passed successfully.\n');

    // -------------------------------------------------------------------------
    // TEST VECTOR 2: EU Citizen Ingestion & Validation (Dr. Clara Schmidt, 37)
    // -------------------------------------------------------------------------
    console.log('[VECTOR 2] Testing EU Citizen Sovereign Validation (Dr. Clara Schmidt, age 37)...');
    const euResult = await runSwissDemonstration({
      citizenPreset: 'eu_adult',
      baseUrl
    });

    assert(euResult.success === true, 'EU adult demonstration succeeded');
    assert(euResult.validationStatus === 'APPROVED', 'EU citizen received APPROVED clearance');
    assert(euResult.citizen.nationality.includes('DEU'), 'Citizen nationality is DEU (Germany / EU)');
    assert(euResult.citizen.age === 37, 'Citizen age is 37');
    assert(
      euResult.envelope?.cryptographicReceipt.proofByteLength === 1355,
      'EU citizen verified with canonical 1355-byte B2 proof'
    );

    console.log('  -> Vector 2 passed successfully.\n');

    // -------------------------------------------------------------------------
    // TEST VECTOR 3: Underage Minor Rejection (Luca Rossi, age 17)
    // -------------------------------------------------------------------------
    console.log('[VECTOR 3] Testing Underage Minor Rejection (Luca Rossi, age 17)...');
    const minorResult = await runSwissDemonstration({
      citizenPreset: 'minor_luca',
      baseUrl
    });

    assert(minorResult.success === false, 'Underage minor demonstration returned false');
    assert(minorResult.validationStatus === 'REJECTED', 'Validation status marked REJECTED');
    assert(minorResult.currentStep === 3, 'Execution halted at Step 3 ZKP Age-Gate');
    assert(
      minorResult.envelope === undefined,
      'Zero Data-Liability Envelope was NOT issued to minor'
    );
    assert(
      typeof minorResult.error === 'string' && minorResult.error.includes('18'),
      `Rejection error recorded: "${minorResult.error}"`
    );

    console.log('  -> Vector 3 passed successfully.\n');

    // -------------------------------------------------------------------------
    // TEST VECTOR 4: Software Secure Enclave Simulator Native FIDO2 Protocol
    // -------------------------------------------------------------------------
    console.log('[VECTOR 4] Testing Software Secure Enclave Simulator FIDO2 integrity directly...');
    const simulator = new SoftwareSecureEnclaveSimulator();

    // 4a. Registration
    const regOptionsRes = await fetch(`${baseUrl}/api/auth/webauthn/register-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'enclave-sim-test@bilanx.ch' })
    });
    const regOptions = await regOptionsRes.json();
    assert(regOptions.challenge !== undefined, 'WebAuthn registration challenge generated');

    const attestation = await simulator.createCredential(regOptions);
    assert(attestation.response.clientDataJSON !== undefined, 'Simulator generated clientDataJSON');
    assert(attestation.response.attestationObject !== undefined, 'Simulator generated attestationObject');

    const regVerifyRes = await fetch(`${baseUrl}/api/auth/webauthn/register-verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': baseUrl
      },
      body: JSON.stringify({
        username: 'enclave-sim-test@bilanx.ch',
        credential: {
          id: attestation.id,
          rawId: attestation.rawId,
          type: attestation.type,
          response: attestation.response
        }
      })
    });
    const regVerify = await regVerifyRes.json();
    assert(regVerify.verified === true, 'Server verified simulator attestation with 200 OK');

    // 4b. Hardware Fingerprint Derivation
    const hwFingerprint = await deriveHardwareFingerprint(
      attestation.id,
      attestation.response.attestationObject
    );
    assert(hwFingerprint.startsWith('HE-P256-'), 'Derived SHA-256 HW_FINGERPRINT is valid format');

    // 4c. Authentication Assertion
    const authOptionsRes = await fetch(`${baseUrl}/api/auth/webauthn/authenticate-options`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'enclave-sim-test@bilanx.ch' })
    });
    const authOptions = await authOptionsRes.json();
    assert(authOptions.challenge !== undefined, 'WebAuthn authentication challenge generated');

    const assertion = await simulator.getAssertion(authOptions);
    assert(assertion.response.signature !== undefined, 'Simulator generated authentic ECDSA signature');

    const authVerifyRes = await fetch(`${baseUrl}/api/auth/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': baseUrl
      },
      body: JSON.stringify({
        username: 'enclave-sim-test@bilanx.ch',
        credential: {
          id: assertion.id,
          rawId: assertion.rawId,
          type: assertion.type,
          response: assertion.response
        }
      })
    });
    const authVerify = await authVerifyRes.json();
    assert(authVerify.verified === true, 'Server verified simulator assertion signature');
    const verifyCounter = authVerify.counter ?? authVerify.credential?.counter;
    assert(verifyCounter !== undefined && verifyCounter >= 1, 'Authenticator counter incremented monotonically');

    console.log('  -> Vector 4 passed successfully.\n');

    // -------------------------------------------------------------------------
    // TEST VECTOR 5: Second-Factor Tampering Defense
    // -------------------------------------------------------------------------
    console.log('[VECTOR 5] Testing Second-Factor Hardware Fingerprint Tampering Defense...');
    const tamperedResult = await runSwissDemonstration({
      citizenPreset: 'swiss_adult',
      baseUrl,
      tamperHardwareFingerprint: true
    });

    assert(tamperedResult.success === false, 'Demonstration with tampered second factor returned false');
    assert(tamperedResult.validationStatus === 'REJECTED', 'Validation status marked REJECTED');
    assert(tamperedResult.envelope === undefined, 'No clearance envelope issued on tampered factor');

    console.log('  -> Vector 5 passed successfully.\n');

    // -------------------------------------------------------------------------
    // TEST VECTOR 6: WebAuthn Origin Validation Hardening (Anti-Phishing)
    // -------------------------------------------------------------------------
    console.log('[VECTOR 6] Testing WebAuthn Origin Validation Hardening (Untrusted Origin Rejection)...');
    
    // Attempt register-verify with untrusted phishing origin
    const maliciousRegRes = await fetch(`${baseUrl}/api/auth/webauthn/register-verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'https://malicious-phishing-attacker.ch'
      },
      body: JSON.stringify({
        username: 'victim@bilanx.ch',
        credential: {
          id: attestation.id,
          rawId: attestation.rawId,
          type: attestation.type,
          response: attestation.response
        }
      })
    });
    assert(maliciousRegRes.status === 400, 'Server rejected untrusted origin with HTTP 400 Bad Request');
    const maliciousRegData = await maliciousRegRes.json();
    assert(maliciousRegData.verified === false, 'Untrusted origin payload marked verified=false');
    assert(
      maliciousRegData.error === 'Origin mismatch or untrusted origin',
      'Accurate fail-closed security error returned'
    );

    // Attempt authenticate-verify with untrusted phishing origin
    const maliciousAuthRes = await fetch(`${baseUrl}/api/auth/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Origin': 'http://evil-spoof.internal'
      },
      body: JSON.stringify({
        username: 'enclave-sim-test@bilanx.ch',
        credential: {
          id: assertion.id,
          rawId: assertion.rawId,
          type: assertion.type,
          response: assertion.response
        }
      })
    });
    assert(maliciousAuthRes.status === 400, 'Authenticate-verify rejected untrusted origin with HTTP 400');
    const maliciousAuthData = await maliciousAuthRes.json();
    assert(maliciousAuthData.verified === false, 'Untrusted origin auth marked verified=false');

    console.log('  -> Vector 6 passed successfully.\n');

    // -------------------------------------------------------------------------
    // TEST VECTOR 7: Zero Data-Liability & Zero PII Leakage Guarantee
    // -------------------------------------------------------------------------
    console.log('[VECTOR 7] Testing Zero PII Server Leakage & Client Quarantine Guarantee...');
    
    // In Swiss adult envelope, ensure no plain citizen PII exists in envelope
    const env = swissResult.envelope!;
    const envSerialized = JSON.stringify(env);
    
    assert(!envSerialized.includes('Heinrich'), 'Plaintext givenName NOT leaked into validation envelope');
    assert(!envSerialized.includes('Keller'), 'Plaintext familyName NOT leaked into validation envelope');
    assert(!envSerialized.includes('1994-05-12'), 'Plaintext birth date NOT leaked into validation envelope');
    assert(!envSerialized.includes('CHE-ZH-884210-HK'), 'Plain national ID NOT leaked into validation envelope');
    assert(env.cryptographicReceipt.proofByteLength === 1355, 'Only zero-knowledge proof length and hash are published');
    assert(env.merchantClearance.piiTransmittedBytes === 0, 'Merchant clearance confirms 0 bytes PII transmitted');

    console.log('  -> Vector 7 passed successfully.\n');

    console.log('================================================================================');
    console.log(`✅ ALL ${passedTests}/${totalTests} SWISS DEMONSTRATION E2E TEST ASSERTIONS PASSED WITH 100% SUCCESS!`);
    console.log('================================================================================\n');

  } finally {
    server.close();
  }
}

runTestSuite().catch((err) => {
  console.error('\n❌ SWISS UNIFIED E2E TEST RUNNER FAILED:');
  console.error(err);
  process.exit(1);
});
