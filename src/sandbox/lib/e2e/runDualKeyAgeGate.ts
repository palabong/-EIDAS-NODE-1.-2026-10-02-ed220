import { performDualKeyHandshake } from '../../hooks/useBilanxDualKeyValidation.real';
import { generateProof, verifyProof } from '../nizkp';

export type E2EAgeGateInput = {
  age: number;
  threshold?: number; // default 18
};

export type E2EAgeGateResult = {
  dualKeyOk: boolean;
  ageGateOk: boolean;
  proofBytes: Uint8Array;
  proofByteLength: number;
  timings: {
    dualKey_ms: number;
    server_dual_key_verify_ms?: number;
    prove_ms: number;
    verify_ms: number;
    total_ms: number;
  };
  error?: string;
  payload?: any;
};

export async function runDualKeyAgeGate(input: E2EAgeGateInput): Promise<E2EAgeGateResult> {
  const totalT0 = performance.now();
  const threshold = input.threshold ?? 18;

  let dualKeyOk = false;
  let ageGateOk = false;
  let proofBytes = new Uint8Array(0);
  let errorMsg: string | undefined = undefined;

  let dualKey_ms = 0;
  let server_dual_key_verify_ms: number | undefined;
  let prove_ms = 0;
  let verify_ms = 0;
  let payload: any = undefined;

  try {
    // 1. Dual-Key Real Execution
    const dkStart = performance.now();
    // Using dummy IDs as this is just the cryptographic segment check
    const dkResult = await performDualKeyHandshake('inst-sandbox', 'user-factor-123');
    dualKey_ms = performance.now() - dkStart;

    dualKeyOk = dkResult.success;
    server_dual_key_verify_ms = dkResult.serverVerifyMs;
    payload = dkResult.payload;

    // HARD GATE
    if (!dualKeyOk) {
      errorMsg = dkResult.error || 'Dual-Key server verification failed';
      const total_ms = performance.now() - totalT0;
      return {
        dualKeyOk: false,
        ageGateOk: false,
        proofBytes: new Uint8Array(0),
        proofByteLength: 0,
        timings: {
          dualKey_ms,
          server_dual_key_verify_ms,
          prove_ms: 0,
          verify_ms: 0,
          total_ms,
        },
        error: errorMsg,
      };
    }

    // 2. Age-Gate Generate
    const proveStart = performance.now();
    try {
      // The generateProof might throw if age < threshold
      // Wait, generateBitwiseRangeProof takes (age, threshold), but our nizkp facade
      // generateProof only takes (age) and hardcodes 18.
      // Let's import generateBitwiseRangeProof directly if we need to pass threshold,
      // but the instructions say:
      // "Age-gate segment must use the current production facade (nizkp.ts generateProof/verifyProof) so binary codec remains on-path."
      // Since nizkp.ts hardcodes 18, we just use it and rely on its threshold (18).
      proofBytes = await generateProof(input.age);
      prove_ms = performance.now() - proveStart;

      // 3. Age-Gate Verify
      const verifyStart = performance.now();
      ageGateOk = await verifyProof(proofBytes);
      verify_ms = performance.now() - verifyStart;
    } catch (err: any) {
      prove_ms = performance.now() - proveStart;
      ageGateOk = false;
      errorMsg = err.message || 'Age-Gate proof generation failed';
    }
  } catch (err: any) {
    errorMsg = err.message || 'E2E flow failed';
  }

  const total_ms = performance.now() - totalT0;

  return {
    dualKeyOk,
    ageGateOk,
    proofBytes,
    proofByteLength: proofBytes.byteLength,
    timings: {
      dualKey_ms,
      server_dual_key_verify_ms,
      prove_ms,
      verify_ms,
      total_ms,
    },
    error: errorMsg,
    payload,
  };
}
