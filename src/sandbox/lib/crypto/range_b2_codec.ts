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
  offset += 32;
  
  return buffer;
}

export function decodeBitwiseRangeProof(bytes: Uint8Array): BitwiseRangeProof {
  if (bytes.length !== 1355) {
    throw new Error(`Invalid binary proof length. Expected 1355, got ${bytes.length}`);
  }
  
  let offset = 0;
  const version = bytes[offset++];
  if (version !== 1) {
    throw new Error('Unsupported proof version');
  }
  
  const threshold = bytes[offset++];
  
  const commitment = bytes.slice(offset, offset + 33);
  offset += 33;
  
  const bits: BitCommitmentProof[] = [];
  for (let i = 0; i < 8; i++) {
    bits.push({
      C_i: bytesToHex(bytes.slice(offset, offset + 33)),
      c_0: bytesToHex(bytes.slice(offset + 33, offset + 65)),
      c_1: bytesToHex(bytes.slice(offset + 65, offset + 97)),
      s_0: bytesToHex(bytes.slice(offset + 97, offset + 129)),
      s_1: bytesToHex(bytes.slice(offset + 129, offset + 161))
    });
    offset += 161;
  }
  
  const r_diff = bytesToHex(bytes.slice(offset, offset + 32));
  offset += 32;
  
  return {
    commitment,
    threshold,
    bits,
    r_diff
  };
}
