/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Pure Non-Interactive Zero-Knowledge Proof (NIZKP) Module
 * Handles generation and verification of B2 Bitwise Range Proofs without telemetry side-effects.
 */

import { generateBitwiseRangeProof, verifyBitwiseRangeProof, BitwiseRangeProof } from './range_b2';
import { encodeBitwiseRangeProof, decodeBitwiseRangeProof } from './range_b2_codec';

export type { BitwiseRangeProof };
export { 
  generateBitwiseRangeProof, 
  verifyBitwiseRangeProof, 
  encodeBitwiseRangeProof, 
  decodeBitwiseRangeProof 
};

/**
 * Generates a serialized Non-Interactive Zero-Knowledge Proof (NIZKP) and Pedersen Commitment.
 */
export async function generateProof(age: number, threshold: number = 18): Promise<Uint8Array> {
  const proofObj = await generateBitwiseRangeProof(age, threshold);
  return encodeBitwiseRangeProof(proofObj);
}

/**
 * Verifies a Non-Interactive Zero-Knowledge Proof (NIZKP) binary payload.
 * Pure cryptographic verification with no client-side metrics side-effects.
 */
export async function verifyProof(proofBytes: Uint8Array): Promise<boolean> {
  try {
    const proofObj = decodeBitwiseRangeProof(proofBytes);
    return await verifyBitwiseRangeProof(proofObj);
  } catch (err) {
    console.error('[ZKP Verifier] Proof parsing or verification failed:', err);
    return false;
  }
}
