```typescript
// Path: src/sandbox/hooks/useBilanxDualKeyValidation.real.ts
// Lines: 297-307
// User client side signs canonical message bound to challenge and secondFactorHash
    const boundPayloadStr = `${challengeStr}:${secondFactorHashHex}`;
    const boundPayloadBuffer = new TextEncoder().encode(boundPayloadStr);
    
    logs.push('User: Signing the strongly bound payload...');
    t0 = performance.now();
    const userSignatureBuffer = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      userKeyPair.privateKey,
      boundPayloadBuffer
    );
```

```typescript
// Path: src/server/app.ts
// Lines: 985-987, 1015-1044
// Server consumes the in-memory challenge, then verifies both signatures

      // Atomically consume challenge immediately BEFORE any asynchronous crypto operations
      // to eliminate race conditions and prevent concurrent parallel replay attacks
      challengeRecord.consumed = true;

      // 3. Reconstruct canonical message and verify User Signature
      const canonicalMessage = `${challengeId}:${secondFactorHash}`;
      const messageBuffer = new TextEncoder().encode(canonicalMessage);

      // Convert userSignature from base64url to Buffer (P1363 format)
      const b64 = userSignature.replace(/-/g, '+').replace(/_/g, '/');
      const signatureBuffer = Buffer.from(b64, 'base64');

      // Import the public key
      let importedKey: webcrypto.CryptoKey;
      try {
        importedKey = await webcrypto.subtle.importKey(
          "jwk",
          userPublicKey,
          { name: "ECDSA", namedCurve: "P-256" },
          false,
          ["verify"]
        );
      } catch (err) {
        res.status(400).json({ valid: false, error: "Invalid JWK format" });
        return;
      }

      // Verify the ECDSA P-256 SHA-256 signature
      const isValid = await webcrypto.subtle.verify(
        { name: "ECDSA", hash: { name: "SHA-256" } },
        importedKey,
        signatureBuffer,
        messageBuffer
      );
```