import { p256 } from '@noble/curves/nist.js';
import { G, H, pedersenCommit } from './pedersen';

async function hashToScalar(...inputs: Uint8Array[]): Promise<bigint> {
  const totalLength = inputs.reduce((acc, val) => acc + val.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const input of inputs) {
    combined.set(input, offset);
    offset += input.length;
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  const hashArray = new Uint8Array(hashBuffer);
  let hex = '';
  for (let i = 0; i < hashArray.length; i++) {
    hex += hashArray[i].toString(16).padStart(2, '0');
  }
  return BigInt('0x' + hex) % p256.Point.Fn.ORDER;
}

function generateRandomScalar(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return BigInt('0x' + hex) % p256.Point.Fn.ORDER;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export type BitCommitmentProof = {
  C_i: string; // hex
  c_0: string; // hex
  c_1: string; // hex
  s_0: string; // hex
  s_1: string; // hex
};

export type BitwiseRangeProof = {
  commitment: Uint8Array;
  threshold: number;
  bits: BitCommitmentProof[];
  r_diff: string; // hex
};

export let B2_PROFILE = false;
export const B2_LAST_PROFILE: any = { prove_stages: {}, verify_stages: {} };

/**
 * Canonical big-endian 2-byte representation of threshold T for Fiat-Shamir transcript.
 * Eliminates IEEE 754 float endianness dependency in cryptographic challenge computation.
 */
function encodeThreshold(T: number): Uint8Array {
  const buf = new Uint8Array(2);
  buf[0] = (T >> 8) & 0xff;
  buf[1] = T & 0xff;
  return buf;
}

/**
 * Generates a real Bit-Decomposition Sigma Range Proof (Disjunctive NIZKP).
 * Statement: The committed secret x satisfies 0 <= x - T < 2^8.
 */
export async function generateBitwiseRangeProof(age: number, threshold: number = 18): Promise<BitwiseRangeProof> {
  const profile: Record<string, number> = {};
  let t_start = 0, t_end = 0;

  if (B2_PROFILE) t_start = performance.now();
  const secret = BigInt(age);
  const { commitment, blindingFactor: r } = pedersenCommit(secret);
  if (B2_PROFILE) { t_end = performance.now(); profile.root_commitment = t_end - t_start; t_start = t_end; }

  const T = threshold;
  const diff = age - T;
  if (diff < 0 || diff >= 256) {
    throw new Error(`Age ${age} is not within [T, T+255] for T=${T}`);
  }

  const Fn = p256.Point.Fn;
  
  // Decompose diff into 8 bits
  const b = [];
  let temp = diff;
  for (let i = 0; i < 8; i++) {
    b.push(temp & 1);
    temp >>= 1;
  }

  // 1. Bit commitments
  const r_i_arr = [];
  const C_i_arr = [];
  const Y_i_0 = [];
  const Y_i_1 = [];

  for (let i = 0; i < 8; i++) {
    const r_i = generateRandomScalar();
    r_i_arr.push(r_i);
    let C_i = H.multiply(r_i);
    if (b[i] === 1) {
      C_i = C_i.add(G);
    }
    C_i_arr.push(C_i);
    Y_i_0.push(C_i);
    Y_i_1.push(C_i.subtract(G));
  }
  if (B2_PROFILE) { t_end = performance.now(); profile.bit_commitments = t_end - t_start; t_start = t_end; }

  // 2. Sum-check
  let r_sum = 0n;
  for (let i = 0; i < 8; i++) {
    r_sum = Fn.add(r_sum, Fn.mul(r_i_arr[i], BigInt(1 << i)));
  }
  const r_diff = Fn.sub(r, r_sum);
  if (B2_PROFILE) { t_end = performance.now(); profile.sum_check = t_end - t_start; t_start = t_end; }

  // 3. Sigma protocol first moves
  const w_arr = [];
  const c_fake = [];
  const s_fake = [];
  const A_0 = [];
  const A_1 = [];

  for (let i = 0; i < 8; i++) {
    const w = generateRandomScalar();
    w_arr.push(w);
    
    if (b[i] === 0) {
      // Real is 0, fake is 1
      const c1 = generateRandomScalar();
      const s1 = generateRandomScalar();
      c_fake.push(c1);
      s_fake.push(s1);
      
      A_0.push(H.multiply(w));
      const A1 = H.multiply(s1).subtract(Y_i_1[i].multiply(c1));
      A_1.push(A1);
    } else {
      // Real is 1, fake is 0
      const c0 = generateRandomScalar();
      const s0 = generateRandomScalar();
      c_fake.push(c0);
      s_fake.push(s0);
      
      const A0 = H.multiply(s0).subtract(Y_i_0[i].multiply(c0));
      A_0.push(A0);
      A_1.push(H.multiply(w));
    }
  }
  if (B2_PROFILE) { t_end = performance.now(); profile.sigma_first_moves = t_end - t_start; t_start = t_end; }

  // 4. Fiat-Shamir hash
  const hashInputs = [
    commitment,
    encodeThreshold(T)
  ];
  for (let i = 0; i < 8; i++) {
    hashInputs.push(C_i_arr[i].toBytes(true));
    hashInputs.push(A_0[i].toBytes(true));
    hashInputs.push(A_1[i].toBytes(true));
  }
  const c = await hashToScalar(...hashInputs);
  if (B2_PROFILE) { t_end = performance.now(); profile.fiat_shamir = t_end - t_start; t_start = t_end; }

  // 5. Sigma protocol responses
  const bits: BitCommitmentProof[] = [];
  for (let i = 0; i < 8; i++) {
    if (b[i] === 0) {
      const c1 = c_fake[i];
      const s1 = s_fake[i];
      const c0 = Fn.sub(c, c1);
      const s0 = Fn.add(w_arr[i], Fn.mul(c0, r_i_arr[i]));
      bits.push({
        C_i: bytesToHex(C_i_arr[i].toBytes(true)),
        c_0: c0.toString(16),
        c_1: c1.toString(16),
        s_0: s0.toString(16),
        s_1: s1.toString(16)
      });
    } else {
      const c0 = c_fake[i];
      const s0 = s_fake[i];
      const c1 = Fn.sub(c, c0);
      const s1 = Fn.add(w_arr[i], Fn.mul(c1, r_i_arr[i]));
      bits.push({
        C_i: bytesToHex(C_i_arr[i].toBytes(true)),
        c_0: c0.toString(16),
        c_1: c1.toString(16),
        s_0: s0.toString(16),
        s_1: s1.toString(16)
      });
    }
  }
  if (B2_PROFILE) { t_end = performance.now(); profile.sigma_responses = t_end - t_start; t_start = t_end; }
  
  if (B2_PROFILE) B2_LAST_PROFILE.prove_stages = profile;

  return {
    commitment,
    threshold: T,
    bits,
    r_diff: r_diff.toString(16)
  };
}

/**
 * Verifies a Bitwise Range Proof.
 */
export async function verifyBitwiseRangeProof(proof: BitwiseRangeProof): Promise<boolean> {
  const profile: Record<string, number> = {};
  let t_start = 0, t_end = 0;
  
  if (B2_PROFILE) t_start = performance.now();

  try {
    const { commitment, threshold: T, bits, r_diff } = proof;
    if (bits.length !== 8) return false;

    const C = p256.Point.fromHex(bytesToHex(commitment));
    const Fn = p256.Point.Fn;
    const rDiff = BigInt('0x' + r_diff);

    // 1. Reconstruct A_0 and A_1, and collect C_i
    const C_i_arr = [];
    const A_0 = [];
    const A_1 = [];

    for (let i = 0; i < 8; i++) {
      const C_i = p256.Point.fromHex(bits[i].C_i);
      C_i_arr.push(C_i);

      const c0 = BigInt('0x' + bits[i].c_0);
      const c1 = BigInt('0x' + bits[i].c_1);
      const s0 = BigInt('0x' + bits[i].s_0);
      const s1 = BigInt('0x' + bits[i].s_1);

      // A0 = s0 * H - c0 * C_i
      const A0 = H.multiply(s0).add(C_i.multiply(Fn.neg(c0)));
      A_0.push(A0);

      // A1 = s1 * H - c1 * (C_i - G)
      const C_i_minus_G = C_i.subtract(G);
      const A1 = H.multiply(s1).add(C_i_minus_G.multiply(Fn.neg(c1)));
      A_1.push(A1);
    }
    if (B2_PROFILE) { t_end = performance.now(); profile.reconstruct_A = t_end - t_start; t_start = t_end; }

    // 2. Recompute Fiat-Shamir challenge
    const hashInputs = [
      commitment,
      encodeThreshold(T)
    ];
    for (let i = 0; i < 8; i++) {
      hashInputs.push(C_i_arr[i].toBytes(true));
      hashInputs.push(A_0[i].toBytes(true));
      hashInputs.push(A_1[i].toBytes(true));
    }
    const c = await hashToScalar(...hashInputs);
    if (B2_PROFILE) { t_end = performance.now(); profile.fiat_shamir = t_end - t_start; t_start = t_end; }

    // 3. Verify OR-proofs
    for (let i = 0; i < 8; i++) {
      const c0 = BigInt('0x' + bits[i].c_0);
      const c1 = BigInt('0x' + bits[i].c_1);
      if (Fn.add(c0, c1) !== c) {
        return false;
      }
    }
    if (B2_PROFILE) { t_end = performance.now(); profile.or_proofs = t_end - t_start; t_start = t_end; }

    // 4. Verify sum-check: C - T*G - sum(C_i * 2^i) == r_diff * H
    let sumC = p256.Point.ZERO;
    for (let i = 0; i < 8; i++) {
      sumC = sumC.add(C_i_arr[i].multiply(BigInt(1 << i)));
    }
    let lhs = C;
    if (T > 0) {
      lhs = lhs.subtract(G.multiply(BigInt(T)));
    }
    lhs = lhs.subtract(sumC);
    const rhs = H.multiply(rDiff);

    if (!lhs.equals(rhs)) {
      return false;
    }
    if (B2_PROFILE) { t_end = performance.now(); profile.sum_check = t_end - t_start; t_start = t_end; }
    if (B2_PROFILE) B2_LAST_PROFILE.verify_stages = profile;

    return true;
  } catch (err) {
    console.error("Verification failed:", err);
    return false;
  }
}

/**
 * Serializes the proof to a byte array for size measurement (KPI-05).
 */
export function serializeBitwiseRangeProof(proof: BitwiseRangeProof): Uint8Array {
  const str = JSON.stringify({
    c: Array.from(proof.commitment),
    t: proof.threshold,
    b: proof.bits,
    r: proof.r_diff
  });
  return new TextEncoder().encode(str);
}
