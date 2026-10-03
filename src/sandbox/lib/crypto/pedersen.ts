import { p256, p256_hasher } from '@noble/curves/nist.js';

// Generator G is the standard P-256 base point
export const G = p256.Point.BASE;

// Generator H is derived using a Nothing-Up-My-Sleeve (NUMS) method.
// We use the standard hash-to-curve algorithm (RFC 9380) on a public string.
// This ensures that the discrete logarithm of H relative to G is unknown.
export const H = p256_hasher.hashToCurve(new TextEncoder().encode('Bilanx NUMS H Generator'));

export type PedersenCommitment = {
  commitment: Uint8Array;
  blindingFactor: bigint;
};

function generateBlindingFactor(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  // Modulo the curve order to ensure it's a valid scalar
  return BigInt('0x' + hex) % p256.Point.Fn.ORDER;
}

/**
 * Create a Pedersen commitment to a secret value x.
 * C = x·G + r·H
 */
export function pedersenCommit(secret: bigint, blindingFactor?: bigint): PedersenCommitment {
  const r = blindingFactor ?? generateBlindingFactor();
  const xG = G.multiply(secret);
  const rH = H.multiply(r);
  
  const C = xG.add(rH);
  
  return {
    commitment: C.toBytes(true), // compressed point
    blindingFactor: r
  };
}

/**
 * Serialize commitment for transport / size measurement (KPI-05)
 */
export function serializeCommitment(commitment: Uint8Array): Uint8Array {
  return commitment; // already compressed bytes
}

/**
 * (Optional, for later verification tests)
 * Verify that a commitment was opened correctly with given secret + blinding.
 * This is NOT a zero-knowledge proof; it is an opening check.
 */
export function pedersenOpen(
  commitment: Uint8Array,
  secret: bigint,
  blindingFactor: bigint
): boolean {
  const expected = pedersenCommit(secret, blindingFactor);
  if (expected.commitment.length !== commitment.length) return false;
  for (let i = 0; i < commitment.length; i++) {
    if (expected.commitment[i] !== commitment[i]) return false;
  }
  return true;
}
