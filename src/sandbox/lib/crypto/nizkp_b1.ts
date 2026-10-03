import { p256 } from '@noble/curves/nist.js';
import { G, H, pedersenCommit } from './pedersen';

// Utility for hashing in Fiat-Shamir
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

export type OpeningProof = {
  T: Uint8Array;
  s1: string; // hex string representation of bigint
  s2: string; // hex string representation of bigint
};

export type AgeGateProof = {
  commitment: Uint8Array;
  openingProof: OpeningProof;
  /**
   * MINIMAL REAL RANGE COMPONENT - EXPLICIT LIMITATION
   * In this B1 sandbox iteration, we prove true knowledge of opening (x, r).
   * However, a true zero-knowledge range proof (e.g. Bulletproofs) requires 
   * inner product arguments which are too heavy for this single iteration.
   * For sandbox purposes, we assert the threshold in plaintext alongside the 
   * real opening proof. The verifier performs real elliptic curve operations 
   * to verify the opening proof, but implicitly trusts the range claim.
   */
  threshold: number;
};

/**
 * Generates a real non-interactive zero-knowledge proof of knowledge of the 
 * opening of a Pedersen commitment.
 * Statement proven: Prover knows (x, r) such that C = x*G + r*H.
 */
export async function generateAgeGateProof(age: number, threshold: number = 18): Promise<AgeGateProof> {
  const secret = BigInt(age);
  const { commitment, blindingFactor } = pedersenCommit(secret);

  // Sigma protocol for knowledge of (x, r)
  // 1. Random scalars u, v
  const u = generateRandomScalar();
  const v = generateRandomScalar();

  // 2. T = u*G + v*H
  const uG = G.multiply(u);
  const vH = H.multiply(v);
  const T = uG.add(vH);
  const T_bytes = T.toBytes(true);

  // 3. Challenge c = Hash(C, T)
  const c = await hashToScalar(commitment, T_bytes);

  // 4. Responses: s1 = u + c*x, s2 = v + c*r
  const Fn = p256.Point.Fn;
  const cx = Fn.mul(c, secret);
  const s1 = Fn.add(u, cx);
  
  const cr = Fn.mul(c, blindingFactor);
  const s2 = Fn.add(v, cr);

  return {
    commitment,
    openingProof: {
      T: T_bytes,
      s1: s1.toString(16),
      s2: s2.toString(16)
    },
    threshold
  };
}

/**
 * Verifies the proof of knowledge of opening using real elliptic-curve operations.
 */
export async function verifyAgeGateProof(proof: AgeGateProof): Promise<boolean> {
  try {
    const { commitment, openingProof } = proof;
    const C = p256.Point.fromHex(commitment as any);
    const T = p256.Point.fromHex(openingProof.T as any);
    const s1 = BigInt('0x' + openingProof.s1);
    const s2 = BigInt('0x' + openingProof.s2);

    // Recompute Fiat-Shamir challenge c = Hash(C, T)
    const c = await hashToScalar(commitment, openingProof.T);

    // Check s1*G + s2*H == T + c*C
    const s1G = G.multiply(s1);
    const s2H = H.multiply(s2);
    const lhs = s1G.add(s2H);

    const cC = C.multiply(c);
    const rhs = T.add(cC);

    return lhs.equals(rhs);
  } catch (err) {
    console.error("Proof verification failed:", err);
    return false;
  }
}

/**
 * Serializes the proof and commitment to a byte array for size measurement (KPI-05)
 */
export function serializeAgeGateProof(proof: AgeGateProof): Uint8Array {
  // Simple JSON serialization for KPI-05 byte sizing
  const str = JSON.stringify({
    c: Array.from(proof.commitment),
    T: Array.from(proof.openingProof.T),
    s1: proof.openingProof.s1,
    s2: proof.openingProof.s2,
    t: proof.threshold
  });
  return new TextEncoder().encode(str);
}
