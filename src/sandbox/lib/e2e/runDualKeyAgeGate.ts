import { performDualKeyHandshake } from '../../hooks/useBilanxDualKeyValidation.real';
import { generateProof } from '../../../lib/crypto/zkp/nizkp.ts';
import { AGE_GATE_POLICY_THRESHOLD } from '../../../lib/crypto/clearanceMessage.ts';

export type E2EAgeGateInput = {
  age: number;
  threshold?: number; // server policy is 18; any other value is refused before a POST
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

function failure(
  totalT0: number,
  timings: E2EAgeGateResult['timings'],
  error: string,
  payload?: any
): E2EAgeGateResult {
  return {
    dualKeyOk: false,
    ageGateOk: false,
    proofBytes: new Uint8Array(0),
    proofByteLength: 0,
    timings: { ...timings, total_ms: performance.now() - totalT0 },
    error,
    payload,
  };
}

export async function runDualKeyAgeGate(input: E2EAgeGateInput): Promise<E2EAgeGateResult> {
  const totalT0 = performance.now();
  const threshold = input.threshold ?? AGE_GATE_POLICY_THRESHOLD;
  const timings: E2EAgeGateResult['timings'] = {
    dualKey_ms: 0,
    prove_ms: 0,
    verify_ms: 0,
    total_ms: 0,
  };

  if (threshold !== AGE_GATE_POLICY_THRESHOLD) {
    return failure(
      totalT0,
      timings,
      `Threshold ${threshold} is not the policy threshold ${AGE_GATE_POLICY_THRESHOLD}`
    );
  }

  let proofBytes = new Uint8Array(0);
  const proveStart = performance.now();
  try {
    proofBytes = await generateProof(input.age, AGE_GATE_POLICY_THRESHOLD);
    timings.prove_ms = performance.now() - proveStart;
  } catch (err: any) {
    timings.prove_ms = performance.now() - proveStart;
    return failure(totalT0, timings, err.message || 'Age-gate proof generation failed');
  }

  try {
    const dkStart = performance.now();
    const dkResult = await performDualKeyHandshake('inst-sandbox', 'user-factor-123', {
      proofBytes,
    });
    timings.dualKey_ms = performance.now() - dkStart;
    timings.server_dual_key_verify_ms = dkResult.serverVerifyMs;
    timings.verify_ms = dkResult.serverVerifyMs ?? 0;

    if (!dkResult.success) {
      return failure(
        totalT0,
        timings,
        dkResult.error || 'Clearance rejected by the institutional node',
        dkResult.payload
      );
    }

    return {
      dualKeyOk: true,
      ageGateOk: true,
      proofBytes,
      proofByteLength: proofBytes.byteLength,
      timings: { ...timings, total_ms: performance.now() - totalT0 },
      payload: dkResult.payload,
    };
  } catch (err: any) {
    return failure(totalT0, timings, err.message || 'E2E flow failed');
  }
}
