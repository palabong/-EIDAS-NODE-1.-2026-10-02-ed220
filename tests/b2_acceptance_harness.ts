import { generateProof, verifyProof } from '../src/sandbox/lib/nizkp.ts';
import { generateBitwiseRangeProof, verifyBitwiseRangeProof } from '../src/sandbox/lib/crypto/range_b2.ts';
import { encodeBitwiseRangeProof, decodeBitwiseRangeProof } from '../src/sandbox/lib/crypto/range_b2_codec.ts';
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

  // T10: Fixed vector: age 17, T=18 (reject before proof accepted)
  try {
    const p10 = await generateBitwiseRangeProof(17, 18);
    const p10_bytes = encodeBitwiseRangeProof(p10);
    const v10 = await verifyProof(p10_bytes);
    recordResult('T10', 'Fixed vector: age 17, T=18', 'FAIL', v10 ? 'PASS' : 'FAIL', v10 ? 'FAIL' : 'PASS');
  } catch (err: any) {
    recordResult('T10', 'Fixed vector: age 17, T=18', 'FAIL', 'Error: ' + err.message, 'PASS');
  }

  // T11: Fixed vector: age 18, T=18 (accept, encoded length 1355)
  try {
    const p11 = await generateBitwiseRangeProof(18, 18);
    const p11_bytes = encodeBitwiseRangeProof(p11);
    const len11 = p11_bytes.byteLength;
    const v11 = await verifyProof(p11_bytes);
    const pass11 = v11 && len11 === 1355;
    recordResult(
      'T11',
      'Fixed vector: age 18, T=18',
      'PASS',
      pass11 ? `PASS (len=${len11})` : 'FAIL',
      pass11 ? 'PASS' : 'FAIL'
    );
  } catch (err: any) {
    recordResult('T11', 'Fixed vector: age 18, T=18', 'PASS', 'Error: ' + err.message, 'FAIL');
  }

  // T12: Flip byte inside commitment span [2..34]
  try {
    const p12_bytes = await generateProof(18);
    p12_bytes[18] ^= 0x01; // flip byte inside [2..34]
    const v12 = await verifyProof(p12_bytes);
    recordResult(
      'T12',
      'Flip byte inside commitment [2..34]',
      'FAIL',
      v12 ? 'PASS' : 'FAIL',
      v12 ? 'FAIL' : 'PASS'
    );
  } catch (err: any) {
    recordResult('T12', 'Flip byte inside commitment [2..34]', 'FAIL', 'Error: ' + err.message, 'PASS');
  }

  // T13: Roundtrip decode(encode(proof)) and structure checks
  try {
    const p13 = await generateBitwiseRangeProof(18, 18);
    const p13_encoded = encodeBitwiseRangeProof(p13);
    const is1355 = p13_encoded.byteLength === 1355;
    const versionByte = p13_encoded[0];
    const decoded = decodeBitwiseRangeProof(p13_encoded);
    const bitsCount = decoded.bits.length;
    const p13_reencoded = encodeBitwiseRangeProof(decoded);
    const buffersEqual = p13_encoded.length === p13_reencoded.length &&
      p13_encoded.every((b, i) => b === p13_reencoded[i]);
    const pass13 = is1355 && buffersEqual && (versionByte === 1) && (bitsCount === 8);
    recordResult(
      'T13',
      'Roundtrip codec & 8-bit layout',
      'PASS',
      pass13 ? `PASS (len=${p13_encoded.length}, ver=${versionByte}, bits=${bitsCount})` : 'FAIL',
      pass13 ? 'PASS' : 'FAIL'
    );
  } catch (err: any) {
    recordResult('T13', 'Roundtrip codec & 8-bit layout', 'PASS', 'Error: ' + err.message, 'FAIL');
  }

  // T14: Core and Sandbox codecs produce same 1355-byte length for age 18
  try {
    const { encodeBitwiseRangeProof: encodeCore } = await import('../src/lib/crypto/zkp/range_b2_codec.ts');
    const p14 = await generateBitwiseRangeProof(18, 18);
    const p14_sandbox_encoded = encodeBitwiseRangeProof(p14);
    const p14_core_encoded = encodeCore(p14);
    
    const pass14 = p14_sandbox_encoded.byteLength === 1355 && p14_core_encoded.byteLength === 1355;
    recordResult(
      'T14',
      'Both codecs yield 1355-byte length',
      'PASS',
      pass14 ? 'PASS' : `FAIL (sandbox=${p14_sandbox_encoded.byteLength}, core=${p14_core_encoded.byteLength})`,
      pass14 ? 'PASS' : 'FAIL'
    );
  } catch (err: any) {
    recordResult('T14', 'Both codecs yield 1355-byte length', 'PASS', 'Error: ' + err.message, 'FAIL');
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
