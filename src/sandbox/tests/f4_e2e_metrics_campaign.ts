import { runDualKeyAgeGate } from '../lib/e2e/runDualKeyAgeGate';
import fs from 'fs';
import path from 'path';

// Polyfill window.atob for Node environment
if (typeof (globalThis as any).window === 'undefined') {
  (globalThis as any).window = {
    atob: (str: string) => Buffer.from(str, 'base64').toString('binary')
  };
}

const N_TARGET = 30;

function computeStats(arr: number[]) {
  if (arr.length === 0) return { mean: 0, p50: 0, p95: 0, min: 0, max: 0, n: 0 };
  const sorted = [...arr].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  const mean = sum / sorted.length;
  const p50 = sorted[Math.floor(sorted.length * 0.5)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  return { mean, p50, p95, min, max, n: sorted.length };
}

async function runCampaign() {
  console.log(`Starting F4 E2E Metrics Campaign (N=${N_TARGET})...`);

  let serverVerifyAvailable = false;
  
  const originalFetch = globalThis.fetch;
  try {
    const res = await originalFetch('http://localhost:3000/api/health');
    if (res.ok) serverVerifyAvailable = true;
  } catch (e) {
    // server down
  }

  // Mock fetch for institutional challenge if server is offline, otherwise call live server
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
      if (originalFetch) {
        return originalFetch('http://localhost:3000' + url.toString(), options);
      }
    }
    
    if (originalFetch) return originalFetch(url, options);
    throw new Error("Unhandled fetch mock");
  };

  const series = {
    dualKey_ms: [] as number[],
    server_dual_key_verify_ms: [] as number[],
    prove_ms: [] as number[],
    verify_ms: [] as number[],
    total_ms: [] as number[],
    proofByteLength: [] as number[],
    server_verify_ms: [] as number[]
  };

  let successCount = 0;
  let failCount = 0;

  for (let i = 0; i < N_TARGET * 2; i++) {
    if (successCount >= N_TARGET) break;

    try {
      const result = await runDualKeyAgeGate({ age: 18, threshold: 18 });
      if (result.dualKeyOk && result.ageGateOk) {
        series.dualKey_ms.push(result.timings.dualKey_ms);
        if (result.timings.server_dual_key_verify_ms !== undefined) {
          series.server_dual_key_verify_ms.push(result.timings.server_dual_key_verify_ms);
        }
        series.prove_ms.push(result.timings.prove_ms);
        series.verify_ms.push(result.timings.verify_ms);
        series.total_ms.push(result.timings.total_ms);
        series.proofByteLength.push(result.proofByteLength);
        
        if (serverVerifyAvailable) {
          try {
            const res = await originalFetch('http://localhost:3000/api/v1/age-gate/verify', {
              method: 'POST',
              headers: { 'Content-Type': 'application/octet-stream' },
              body: result.proofBytes
            });
            if (res.ok) {
              const data = await res.json();
              if (data.valid) {
                series.server_verify_ms.push(data.verify_ms);
              }
            }
          } catch(err) {
            // ignore server failures
          }
        }
        
        successCount++;
        process.stdout.write('.');
      } else {
        failCount++;
        process.stdout.write('F');
      }
    } catch (e) {
      failCount++;
      process.stdout.write('E');
    }
  }

  console.log(`\nFinished! Success: ${successCount}, Failed: ${failCount}`);
  
  if (successCount < N_TARGET) {
    console.warn(`WARNING: Only got ${successCount} successful runs out of target ${N_TARGET}.`);
  }

  const stats = {
    dualKey_ms: computeStats(series.dualKey_ms),
    server_dual_key_verify_ms: computeStats(series.server_dual_key_verify_ms),
    prove_ms: computeStats(series.prove_ms),
    verify_ms: computeStats(series.verify_ms),
    total_ms: computeStats(series.total_ms),
    proofByteLength: computeStats(series.proofByteLength),
    server_verify_ms: computeStats(series.server_verify_ms)
  };

  console.table(stats);

  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(now.getUTCDate()).padStart(2, '0');
  const HH = String(now.getUTCHours()).padStart(2, '0');
  const MM = String(now.getUTCMinutes()).padStart(2, '0');
  const filename = `BILANX_KPI_BASELINE_F4_e2e_${yyyy}${mm}${dd}_${HH}${MM}.json`;

  const report = {
    campaign: "F4_E2E",
    timestamp: now.toISOString(),
    environment: {
      runtime: `Node.js ${process.version}`,
      hostClass: "desktop",
      cryptoMode: "true",
      networkMode: serverVerifyAvailable ? "local" : "none"
    },
    config: {
      N_target: N_TARGET,
      age: 18,
      threshold: 18,
      expectedProofBytes: 1355
    },
    counts: {
      success: successCount,
      failed: failCount
    },
    series: stats,
    notes: [
      serverVerifyAvailable ? "Server verify endpoint was reachable and measured." : "Server verify endpoint unreachable, skipped.",
      "DualKey metrics use in-memory crypto mock for the institutional node."
    ]
  };

  const outPath = path.join(process.cwd(), filename);
  fs.writeFileSync(outPath, JSON.stringify(report, null, 2), 'utf-8');
  console.log(`\nJSON export saved to: ${outPath}`);
  
  globalThis.fetch = originalFetch;
}

runCampaign().catch(console.error);
