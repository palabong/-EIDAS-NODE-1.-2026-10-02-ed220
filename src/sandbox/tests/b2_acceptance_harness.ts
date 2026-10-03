import { generateProof, verifyProof } from '../lib/nizkp';
import { generateBitwiseRangeProof, verifyBitwiseRangeProof } from '../lib/crypto/range_b2';
import { encodeBitwiseRangeProof, decodeBitwiseRangeProof } from '../lib/crypto/range_b2_codec';
import { performance } from 'node:perf_hooks';

async function runTests() {
  const results: any[] = [];
  let prove_ms = 0;
  let verify_ms = 0;
  let proof_bytes = 0;

  const recordResult = (id: string, name: string, expected: string, observed: string, verdict: string) => {
    results.push({ id, name, expected, observed, verdict });
  };

  // T1: Under age
  try {
    await generateBitwiseRangeProof(17, 18);
    recordResult('T1', 'Under age', 'FAIL', 'PASS', 'FAIL');
  } catch (err: any) {
    recordResult('T1', 'Under age', 'FAIL', 'Error: ' + err.message, 'PASS');
  }

  // T2: Exact threshold
  try {
    const t0 = performance.now();
    const p2_bytes = await generateProof(18); // default is T=18
    prove_ms = performance.now() - t0;
    
    proof_bytes = p2_bytes.byteLength;
    
    const t1 = performance.now();
    const v2 = await verifyProof(p2_bytes);
    verify_ms = performance.now() - t1;

    recordResult('T2', 'Exact threshold', 'PASS', v2 ? 'PASS' : 'FAIL', v2 ? 'PASS' : 'FAIL');
  } catch (err: any) {
    recordResult('T2', 'Exact threshold', 'PASS', 'Error', 'FAIL');
  }

  // T3: Clearly over age
  try {
    const p3_bytes = await generateProof(40);
    const v3 = await verifyProof(p3_bytes);
    recordResult('T3', 'Clearly over age', 'PASS', v3 ? 'PASS' : 'FAIL', v3 ? 'PASS' : 'FAIL');
  } catch (err: any) {
    recordResult('T3', 'Clearly over age', 'PASS', 'Error', 'FAIL');
  }

  // T4: Upper bound edge
  try {
    const p4_bytes = await generateProof(272); // 272 - 18 = 254
    const v4 = await verifyProof(p4_bytes);
    recordResult('T4', 'Upper bound edge', 'PASS', v4 ? 'PASS' : 'FAIL', v4 ? 'PASS' : 'FAIL');
  } catch (err: any) {
    recordResult('T4', 'Upper bound edge', 'PASS', 'Error: ' + err.message, 'FAIL');
  }

  // T5: Upper bound overflow
  try {
    await generateProof(274); // 274 - 18 = 256
    recordResult('T5', 'Upper bound overflow', 'FAIL', 'PASS', 'FAIL');
  } catch (err: any) {
    recordResult('T5', 'Upper bound overflow', 'FAIL', 'Error: ' + err.message, 'PASS');
  }

  // T6: Tamper bit commitment
  try {
    const p6 = await generateBitwiseRangeProof(18, 18);
    // alter a bit string
    const original = p6.bits[0].s_0;
    p6.bits[0].s_0 = original.replace(/[0-9a-f]/i, (c) => c === '0' ? '1' : '0'); 
    const p6_bytes = encodeBitwiseRangeProof(p6);
    const v6 = await verifyProof(p6_bytes);
    recordResult('T6', 'Tamper bit commitment', 'FAIL', v6 ? 'PASS' : 'FAIL', v6 ? 'FAIL' : 'PASS');
  } catch (err: any) {
    recordResult('T6', 'Tamper bit commitment', 'FAIL', 'Error or FAIL', 'PASS');
  }

  // T7: Tamper threshold in proof
  try {
    const p7 = await generateBitwiseRangeProof(18, 18);
    p7.threshold = 21;
    const p7_bytes = encodeBitwiseRangeProof(p7);
    const v7 = await verifyProof(p7_bytes);
    recordResult('T7', 'Tamper threshold in proof', 'FAIL', v7 ? 'PASS' : 'FAIL', v7 ? 'FAIL' : 'PASS');
  } catch (err: any) {
    recordResult('T7', 'Tamper threshold in proof', 'FAIL', 'Error', 'PASS');
  }

  // T8: Tamper commitment bytes
  try {
    const p8_bytes = await generateProof(18);
    // p8_bytes has commitment at index 2..34
    p8_bytes[2] ^= 1; // tamper first byte of commitment
    const v8 = await verifyProof(p8_bytes);
    recordResult('T8', 'Tamper commitment bytes', 'FAIL', v8 ? 'PASS' : 'FAIL', v8 ? 'FAIL' : 'PASS');
  } catch (err: any) {
    recordResult('T8', 'Tamper commitment bytes', 'FAIL', 'Error', 'PASS');
  }

  // T9: Empty / malformed proof
  try {
    const p9_bytes = new Uint8Array([1, 2, 3]);
    const v9 = await verifyProof(p9_bytes);
    recordResult('T9', 'Empty / malformed proof', 'FAIL', v9 ? 'PASS' : 'FAIL', v9 ? 'FAIL' : 'PASS');
  } catch (err: any) {
    recordResult('T9', 'Empty / malformed proof', 'FAIL', 'Error', 'PASS');
  }

  console.table(results);
  console.log(`Proof bytes (age=18): ${proof_bytes}`);
  console.log(`Prove time: ${prove_ms.toFixed(2)} ms`);
  console.log(`Verify time: ${verify_ms.toFixed(2)} ms`);

  const failed = results.some(r => r.verdict === 'FAIL');
  if (failed) {
    console.error("One or more tests failed.");
    process.exit(1);
  } else {
    console.log("All tests passed.");
    process.exit(0);
  }
}

runTests().catch(err => {
  console.error(err);
  process.exit(1);
});
