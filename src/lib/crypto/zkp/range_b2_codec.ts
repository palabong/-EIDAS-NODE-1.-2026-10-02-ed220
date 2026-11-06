/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * 1,355-byte Binary Layout Codec for Base-2 Bitwise Sigma Range Proof
 */

import { BitwiseRangeProof, BitCommitmentProof } from './range_b2';

// Binary Layout (1355 bytes):
// [0..0]   Version (1 byte)
// [1..1]   Threshold (1 byte)
// [2..34]  Commitment (33 bytes)
// For each of 8 bits (8 * 161 bytes = 1288 bytes):
//   [0..32]  C_i (33 bytes)
//   [33..64] c_0 (32 bytes)
//   [65..96] c_1 (32 bytes)
//   [97..128] s_0 (32 bytes)
//   [129..160] s_1 (32 bytes)
// [1323..1354] r_diff (32 bytes)

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    hex = '0' + hex;
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

function padBytes(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length === length) return bytes;
  const padded = new Uint8Array(length);
  if (bytes.length < length) {
    padded.set(bytes, length - bytes.length); // Big-endian padding
  } else {
    padded.set(bytes.subarray(bytes.length - length));
  }
  return padded;
}

export function encodeBitwiseRangeProof(proof: BitwiseRangeProof): Uint8Array {
  const buffer = new Uint8Array(1355);
  let offset = 0;
  
  // Version
  buffer[offset++] = 1;
  
  // Threshold
  buffer[offset++] = proof.threshold;
  
  // Commitment (33 bytes)
  buffer.set(proof.commitment, offset);
  offset += 33;
  
  // Bits
  for (let i = 0; i < 8; i++) {
    const bit = proof.bits[i];
    buffer.set(hexToBytes(bit.C_i), offset); offset += 33;
    buffer.set(padBytes(hexToBytes(bit.c_0), 32), offset); offset += 32;
    buffer.set(padBytes(hexToBytes(bit.c_1), 32), offset); offset += 32;
    buffer.set(padBytes(hexToBytes(bit.s_0), 32), offset); offset += 32;
    buffer.set(padBytes(hexToBytes(bit.s_1), 32), offset); offset += 32;
  }
  
  // r_diff (32 bytes)
  buffer.set(padBytes(hexToBytes(proof.r_diff), 32), offset);
  
  return buffer;
}

export function decodeBitwiseRangeProof(buffer: Uint8Array): BitwiseRangeProof {
  if (buffer.length !== 1355) {
    throw new Error(`Invalid proof buffer length: expected 1355 bytes, got ${buffer.length}`);
  }
  
  let offset = 0;
  
  const version = buffer[offset++];
  if (version !== 1) {
    throw new Error(`Unsupported proof version: ${version}`);
  }
  
  const threshold = buffer[offset++];
  
  const commitment = buffer.subarray(offset, offset + 33);
  offset += 33;
  
  const bits: BitCommitmentProof[] = [];
  for (let i = 0; i < 8; i++) {
    const C_i = bytesToHex(buffer.subarray(offset, offset + 33)); offset += 33;
    const c_0 = bytesToHex(buffer.subarray(offset, offset + 32)); offset += 32;
    const c_1 = bytesToHex(buffer.subarray(offset, offset + 32)); offset += 32;
    const s_0 = bytesToHex(buffer.subarray(offset, offset + 32)); offset += 32;
    const s_1 = bytesToHex(buffer.subarray(offset, offset + 32)); offset += 32;
    bits.push({ C_i, c_0, c_1, s_0, s_1 });
  }
  
  const r_diff = bytesToHex(buffer.subarray(offset, offset + 32));
  
  return {
    commitment,
    threshold,
    bits,
    r_diff
  };
}
