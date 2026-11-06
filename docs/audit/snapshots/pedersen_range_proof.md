```typescript
// Path: src/lib/crypto/zkp/range_b2.ts
// Lines: 9-28
import { p256 } from '@noble/curves/nist.js';
import { G, H, pedersenCommit } from './pedersen';
import { bytesToHex } from '../encoding';

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
```

```typescript
// Path: src/lib/crypto/zkp/range_b2_codec.ts
// Lines: 10-20, 52-65
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
```