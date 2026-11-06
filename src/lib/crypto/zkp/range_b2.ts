/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * Base-2 Bitwise Sigma Range Proof (Disjunctive NIZKP)
 * Proves 0 <= x - T < 2^8 using Pedersen commitments over NIST P-256.
 */

import { p256 } from '@noble/curves/nist.js';
import { G, H, pedersenCommit } from './pedersen';
import { bytesToHex } from '../encoding';

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

async function hashToScalar(...inputs: Uint8Array[]): Promise<bigint> {
  const totalLength = inputs.reduce((acc, val) => acc + val.length, 0);
  const combined = new Uint8Array(totalLength);
  let offset = 0;
  for (const input of inputs) {
    combined.set(input, offset);
    offset += input.length;
  }
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  return bytesToBigInt(new Uint8Array(hashBuffer)) % p256.Point.Fn.ORDER;
}

function generateRandomScalar(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBigInt(bytes) % p256.Point.Fn.ORDER;
}

export type BitCommitmentProof = {
  C_i: Uint8Array;
  c_0: bigint;
  c_1: bigint;
  s_0: bigint;
  s_1: bigint;
};

export type BitwiseRangeProof = {
  commitment: Uint8Array;
  threshold: number;
  bits: BitCommitmentProof[];
  r_diff: bigint;
};

/**
 * Canonical big-endian 2-byte representation of threshold T for Fiat-Shamir transcript.
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
  const secret = BigInt(age);
  const { commitment, blindingFactor: r } = pedersenCommit(secret);

  const T = threshold;
  const diff = age - T;
  if (diff < 0 || diff >= 256) {
    throw new Error(`Age ${age} is not within [T, T+255] for T=${T}`);
  }

  const Fn = p256.Point.Fn;

  const b: number[] = [];
  let temp = diff;
  for (let i = 0; i < 8; i++) {
    b.push(temp & 1);
    temp >>= 1;
  }

  const r_i_arr: bigint[] = [];
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

  let r_sum = 0n;
  for (let i = 0; i < 8; i++) {
    r_sum = Fn.add(r_sum, Fn.mul(r_i_arr[i], BigInt(1 << i)));
  }
  const r_diff = Fn.sub(r, r_sum);

  const w_arr: bigint[] = [];
  const c_fake: bigint[] = [];
  const s_fake: bigint[] = [];
  const A_0 = [];
  const A_1 = [];

  for (let i = 0; i < 8; i++) {
    const w = generateRandomScalar();
    w_arr.push(w);

    if (b[i] === 0) {
      const c1 = generateRandomScalar();
      const s1 = generateRandomScalar();
      c_fake.push(c1);
      s_fake.push(s1);
      A_0.push(H.multiply(w));
      A_1.push(H.multiply(s1).subtract(Y_i_1[i].multiply(c1)));
    } else {
      const c0 = generateRandomScalar();
      const s0 = generateRandomScalar();
      c_fake.push(c0);
      s_fake.push(s0);
      A_0.push(H.multiply(s0).subtract(Y_i_0[i].multiply(c0)));
      A_1.push(H.multiply(w));
    }
  }

  const hashInputs: Uint8Array[] = [commitment, encodeThreshold(T)];
  for (let i = 0; i < 8; i++) {
    hashInputs.push(C_i_arr[i].toBytes(true));
    hashInputs.push(A_0[i].toBytes(true));
    hashInputs.push(A_1[i].toBytes(true));
  }
  const c = await hashToScalar(...hashInputs);

  const bits: BitCommitmentProof[] = [];
  for (let i = 0; i < 8; i++) {
    if (b[i] === 0) {
      const c1 = c_fake[i];
      const s1 = s_fake[i];
      const c0 = Fn.sub(c, c1);
      const s0 = Fn.add(w_arr[i], Fn.mul(c0, r_i_arr[i]));
      bits.push({
        C_i: C_i_arr[i].toBytes(true),
        c_0: c0,
        c_1: c1,
        s_0: s0,
        s_1: s1,
      });
    } else {
      const c0 = c_fake[i];
      const s0 = s_fake[i];
      const c1 = Fn.sub(c, c0);
      const s1 = Fn.add(w_arr[i], Fn.mul(c1, r_i_arr[i]));
      bits.push({
        C_i: C_i_arr[i].toBytes(true),
        c_0: c0,
        c_1: c1,
        s_0: s0,
        s_1: s1,
      });
    }
  }

  return { commitment, threshold: T, bits, r_diff };
}

/**
 * Verifies a Bitwise Range Proof.
 */
export async function verifyBitwiseRangeProof(proof: BitwiseRangeProof): Promise<boolean> {
  try {
    const { commitment, threshold: T, bits, r_diff } = proof;
    if (bits.length !== 8) return false;

    const C = p256.Point.fromHex(bytesToHex(commitment));
    const Fn = p256.Point.Fn;

    const C_i_arr = [];
    const A_0 = [];
    const A_1 = [];

    for (let i = 0; i < 8; i++) {
      const C_i = p256.Point.fromHex(bytesToHex(bits[i].C_i));
      C_i_arr.push(C_i);

      const c0 = bits[i].c_0;
      const c1 = bits[i].c_1;
      const s0 = bits[i].s_0;
      const s1 = bits[i].s_1;

      A_0.push(H.multiply(s0).add(C_i.multiply(Fn.neg(c0))));
      const C_i_minus_G = C_i.subtract(G);
      A_1.push(H.multiply(s1).add(C_i_minus_G.multiply(Fn.neg(c1))));
    }

    const hashInputs: Uint8Array[] = [commitment, encodeThreshold(T)];
    for (let i = 0; i < 8; i++) {
      hashInputs.push(C_i_arr[i].toBytes(true));
      hashInputs.push(A_0[i].toBytes(true));
      hashInputs.push(A_1[i].toBytes(true));
    }
    const c = await hashToScalar(...hashInputs);

    for (let i = 0; i < 8; i++) {
      if (Fn.add(bits[i].c_0, bits[i].c_1) !== c) {
        return false;
      }
    }

    let sumC = p256.Point.ZERO;
    for (let i = 0; i < 8; i++) {
      sumC = sumC.add(C_i_arr[i].multiply(BigInt(1 << i)));
    }
    let lhs = C;
    if (T > 0) {
      lhs = lhs.subtract(G.multiply(BigInt(T)));
    }
    lhs = lhs.subtract(sumC);
    const rhs = H.multiply(r_diff);

    return lhs.equals(rhs);
  } catch (err) {
    console.error('Verification failed:', err);
    return false;
  }
}
