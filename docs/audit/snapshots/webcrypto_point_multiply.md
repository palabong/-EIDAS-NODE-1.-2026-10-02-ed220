```typescript
// Path: src/lib/crypto/zkp/pedersen.ts
// Lines: 9-17

import { p256, p256_hasher } from '@noble/curves/nist.js';

// Generator G is the standard P-256 base point
export const G = p256.Point.BASE;

// Generator H is derived using a Nothing-Up-My-Sleeve (NUMS) method.
// We use the standard hash-to-curve algorithm (RFC 9380) on a public string.
// This ensures that the discrete logarithm of H relative to G is unknown.
export const H = p256_hasher.hashToCurve(new TextEncoder().encode('Bilanx NUMS H Generator'));
```

```typescript
// Path: src/lib/crypto/zkp/pedersen.ts
// Lines: 39-49

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
```