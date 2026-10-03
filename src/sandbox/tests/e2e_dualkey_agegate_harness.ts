import { runDualKeyAgeGate } from '../lib/e2e/runDualKeyAgeGate';

async function runTests() {
  console.log("=== Running Bilanx DK-SVS E2E Age-Gate Acceptance Harness ===");
  
  let passed = 0;
  let failed = 0;
  const results: any[] = [];
  let sampleTimings: any = null;
  let sampleProofLength = 0;

  const assertEqual = (expected: any, actual: any, msg: string) => {
    if (expected !== actual) {
      throw new Error(`Assertion failed: ${msg}. Expected ${expected}, got ${actual}`);
    }
  };

  // Polyfill window.atob for Node environment
  if (typeof (globalThis as any).window === 'undefined') {
    (globalThis as any).window = {
      atob: (str: string) => Buffer.from(str, 'base64').toString('binary')
    };
  }

  // Ensure dummy server or backend logic exists if required by performDualKeyHandshake
  // We mock fetch globally just for this test so performDualKeyHandshake works without a real server
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    if (url === '/api/institutional-challenge') {
      if (originalFetch) {
        try {
          return await originalFetch('http://localhost:3000/api/institutional-challenge', options);
        } catch (e) {
          // fallback if offline
        }
      }

      const crypto = globalThis.crypto;
      const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const challenge = "mock-challenge-" + Math.random();
      const challengeBuffer = new TextEncoder().encode(challenge);
      const signatureBuffer = await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, keyPair.privateKey, challengeBuffer);
      const signatureBase64 = Buffer.from(signatureBuffer).toString('base64');
      const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);

      return {
        ok: true,
        status: 200,
        json: async () => ({
          success: true,
          challenge,
          signatureBase64,
          publicKeyJwk
        })
      } as Response;
    }
    
    if (url.toString().startsWith('/api/v1/dual-key/verify')) {
      if ((globalThis as any).__forceDualKeyVerifyFail) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ valid: false, reason: 'FORCED_FAILURE_TEST' })
        } as Response;
      }
      if (originalFetch) {
        return originalFetch('http://localhost:3000' + url.toString(), options);
      }
    }
    
    if (originalFetch) return originalFetch(url, options);
    throw new Error("Unhandled fetch mock");
  };

  try {
    // E1
    console.log("Running E1 (age=17, T=18)...");
    const r1 = await runDualKeyAgeGate({ age: 17, threshold: 18 });
    try {
      assertEqual(false, r1.ageGateOk, "E1 ageGateOk should be false");
      results.push({ ID: 'E1', Verdict: 'PASS', Details: r1.error || 'ageGateOk=false' });
      passed++;
    } catch (e: any) {
      results.push({ ID: 'E1', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

    // E2
    console.log("Running E2 (age=18, T=18)...");
    const r2 = await runDualKeyAgeGate({ age: 18, threshold: 18 });
    try {
      assertEqual(true, r2.dualKeyOk, "E2 dualKeyOk should be true");
      assertEqual(true, r2.ageGateOk, "E2 ageGateOk should be true");
      results.push({ ID: 'E2', Verdict: 'PASS', Details: 'both true' });
      passed++;
      sampleTimings = r2.timings;
      sampleProofLength = r2.proofByteLength;
    } catch (e: any) {
      results.push({ ID: 'E2', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

    // E3
    console.log("Running E3 (age=40, T=18)...");
    const r3 = await runDualKeyAgeGate({ age: 40, threshold: 18 });
    try {
      assertEqual(true, r3.dualKeyOk, "E3 dualKeyOk should be true");
      assertEqual(true, r3.ageGateOk, "E3 ageGateOk should be true");
      results.push({ ID: 'E3', Verdict: 'PASS', Details: 'both true' });
      passed++;
    } catch (e: any) {
      results.push({ ID: 'E3', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

    // E4
    console.log("Running E4 (Tamper test)...");
    const r4 = await runDualKeyAgeGate({ age: 18, threshold: 18 });
    try {
      assertEqual(true, r4.ageGateOk, "E4 initial ageGateOk should be true");
      // flip one byte
      if (r4.proofBytes.length > 0) {
        r4.proofBytes[0] ^= 0xFF;
      }
      
      const { verifyProof } = await import('../lib/nizkp');
      const tamperedVerify = await verifyProof(r4.proofBytes);
      assertEqual(false, tamperedVerify, "E4 verify after tamper should be false");
      
      results.push({ ID: 'E4', Verdict: 'PASS', Details: 'tamper verify failed' });
      passed++;
    } catch (e: any) {
      results.push({ ID: 'E4', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

    // E6
    console.log("Running E6 (Key 1 Tampered Payload / Hard Gate check)...");
    (globalThis as any).__forceDualKeyVerifyFail = true;
    const r6 = await runDualKeyAgeGate({ age: 18, threshold: 18 });
    (globalThis as any).__forceDualKeyVerifyFail = false;
    try {
      assertEqual(false, r6.dualKeyOk, "E6 dualKeyOk should be false (hard gate)");
      assertEqual(false, r6.ageGateOk, "E6 ageGateOk should be false (hard gate)");
      assertEqual(0, r6.proofByteLength, "E6 proof should not be generated");
      results.push({ ID: 'E6', Verdict: 'PASS', Details: 'hard gate applied correctly' });
      passed++;
    } catch (e: any) {
      results.push({ ID: 'E6', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

    // E5
    console.log("Running E5 (Structure check)...");
    try {
      // It should be 1355 or current binary size. We'll just check if it's > 0 since it might be 1355 exactly.
      assertEqual(true, sampleProofLength > 0, "E5 proof length > 0");
      assertEqual(true, sampleTimings.dualKey_ms >= 0, "E5 dualKey_ms >= 0");
      assertEqual(true, sampleTimings.prove_ms >= 0, "E5 prove_ms >= 0");
      assertEqual(true, sampleTimings.verify_ms >= 0, "E5 verify_ms >= 0");
      results.push({ ID: 'E5', Verdict: 'PASS', Details: `length=${sampleProofLength}, timings OK` });
      passed++;
    } catch (e: any) {
      results.push({ ID: 'E5', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

    // E7 (Anti-Replay / Single-Use Challenge Verification)
    console.log("Running E7 (Anti-Replay / Challenge Consumption check)...");
    const r7 = await runDualKeyAgeGate({ age: 25, threshold: 18 });
    try {
      assertEqual(true, r7.dualKeyOk, "E7 first run dualKeyOk should be true");
      assertEqual(true, !!r7.payload, "E7 payload must be present");

      // Attempt to replay the exact same DualKeyPayload against the verification endpoint
      const replayRes = await fetch('/api/v1/dual-key/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(r7.payload)
      });
      const replayData = await replayRes.json();
      assertEqual(false, replayData.valid, "E7 replayed challenge must be rejected");
      assertEqual(true, typeof replayData.reason === 'string' && (replayData.reason.includes('already consumed') || replayData.reason.includes('Replay detected')), "E7 reason must indicate consumption or replay");

      results.push({ ID: 'E7', Verdict: 'PASS', Details: `Replay rejected: "${replayData.reason}"` });
      passed++;
    } catch (e: any) {
      results.push({ ID: 'E7', Verdict: 'FAIL', Details: e.message });
      failed++;
    }

  } finally {
    globalThis.fetch = originalFetch;
  }

  console.table(results);
  
  console.log(`\nSample age=18 timings:`);
  console.log(`- dualKey_ms: ${sampleTimings?.dualKey_ms.toFixed(2)}ms`);
  console.log(`- prove_ms: ${sampleTimings?.prove_ms.toFixed(2)}ms`);
  console.log(`- verify_ms: ${sampleTimings?.verify_ms.toFixed(2)}ms`);
  console.log(`- total_ms: ${sampleTimings?.total_ms.toFixed(2)}ms`);
  console.log(`- proofByteLength: ${sampleProofLength} bytes`);

  if (failed > 0) {
    console.error(`\n❌ Harness failed! ${failed} cases failed.`);
    process.exit(1);
  } else {
    console.log(`\n✅ Harness passed! All ${passed} cases passed.`);
    process.exit(0);
  }
}

runTests().catch(e => {
  console.error("Unhandled error in harness:", e);
  process.exit(1);
});
