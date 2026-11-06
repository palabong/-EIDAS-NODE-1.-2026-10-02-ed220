/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 *
 * 1,355-byte Binary Layout Codec for Base-2 Bitwise Sigma Range Proof
 */

import { BitwiseRangeProof, BitCommitmentProof } from './range_b2';

// Binary Layout (1355 bytes):
// [0]      Version (1 byte)
// [1]      Threshold (1 byte)
// [2..34]  Commitment (33 bytes)
// For each of 8 bits (8 * 161 bytes = 1288 bytes):
//   C_i (33) | c_0 (32) | c_1 (32) | s_0 (32) | s_1 (32)
// [1323..1354] r_diff (32 bytes)

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

function bigintToBytes(value: bigint, length: number): Uint8Array {
  const padded = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    padded[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return padded;
}

export function encodeBitwiseRangeProof(proof: BitwiseRangeProof): Uint8Array {
  const buffer = new Uint8Array(1355);
  let offset = 0;

  buffer[offset++] = 1;
  buffer[offset++] = proof.threshold;
  buffer.set(proof.commitment, offset);
  offset += 33;

  for (let i = 0; i < 8; i++) {
    const bit = proof.bits[i];
    buffer.set(bit.C_i, offset); offset += 33;
    buffer.set(bigintToBytes(bit.c_0, 32), offset); offset += 32;
    buffer.set(bigintToBytes(bit.c_1, 32), offset); offset += 32;
    buffer.set(bigintToBytes(bit.s_0, 32), offset); offset += 32;
    buffer.set(bigintToBytes(bit.s_1, 32), offset); offset += 32;
  }

  buffer.set(bigintToBytes(proof.r_diff, 32), offset);
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
  const commitment = buffer.slice(offset, offset + 33);
  offset += 33;

  const bits: BitCommitmentProof[] = [];
  for (let i = 0; i < 8; i++) {
    const C_i = buffer.slice(offset, offset + 33); offset += 33;
    const c_0 = bytesToBigInt(buffer.subarray(offset, offset + 32)); offset += 32;
    const c_1 = bytesToBigInt(buffer.subarray(offset, offset + 32)); offset += 32;
    const s_0 = bytesToBigInt(buffer.subarray(offset, offset + 32)); offset += 32;
    const s_1 = bytesToBigInt(buffer.subarray(offset, offset + 32)); offset += 32;
    bits.push({ C_i, c_0, c_1, s_0, s_1 });
  }

  const r_diff = bytesToBigInt(buffer.subarray(offset, offset + 32));
  return { commitment, threshold, bits, r_diff };
}
