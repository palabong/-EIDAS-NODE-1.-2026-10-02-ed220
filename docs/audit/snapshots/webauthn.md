```typescript
// Path: src/server/webauthnServer.ts
// Lines: 84-95
// Static dictionary of known AAGUID identifiers (not pinned or validated against FIDO MDS)

export const KNOWN_AAGUIDS: Record<string, string> = {
  'ee882879-721c-4916-ad4e-57c7f15f6f19': 'YubiKey 5 Series (NFC / USB)',
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 NFC',
  'cb69481e-8ff7-4039-93ec-0a2729a1e67d': 'YubiKey 5Ci',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5 Series (Lightning / USB-C)',
  'c167093b-01ec-4e5b-b9d9-ae798c874b34': 'Yubico Security Key NFC',
  '08987058-cadc-4b81-b6e1-30c50432bb21': 'Google Titan Security Key',
  '00000000-0000-0000-0000-000000000000': 'Platform Authenticator / Simulator',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Windows Hello Hardware Authenticator',
  '7499aa65-da2d-4530-80ea-311fe5270146': 'Apple Secure Enclave (Touch ID / Face ID)',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'Apple Passkey / iCloud Keychain',
};
```

```typescript
// Path: src/server/webauthnServer.ts
// Lines: 917-943, 991-1009
// Origin check, RP ID SHA-256 hash check, and anti-cloning monotonic counter validation

  // 4. Origin Verification
  if (parsedClientData.origin && (expectedOrigin || expectedRpId)) {
    if (!isOriginAllowed(parsedClientData.origin, expectedOrigin, expectedRpId)) {
      return { verified: false, error: `Origin mismatch: expected ${expectedOrigin || expectedRpId}, got ${parsedClientData.origin}` };
    }
  }

  // 6. RP ID Hash Verification
  if (expectedRpId) {
    const expectedHash = crypto.createHash('sha256').update(expectedRpId).digest();
    const rpIdHash = authDataBuf.subarray(0, 32);
    if (!crypto.timingSafeEqual(rpIdHash, expectedHash)) {
      return { verified: false, error: `RP ID hash mismatch for rpId '${expectedRpId}'` };
    }
  }

  // 10. Signature Counter (Anti-Cloning) Verification
  const signCount = authDataBuf.readUInt32BE(33);
  if ((cred.counter > 0 || signCount > 0) && signCount <= cred.counter) {
    cred.compromised = true;
    return {
      verified: false,
      error: `Cloned authenticator detected: signCount (${signCount}) did not increase past stored counter (${cred.counter})`
    };
  }
  if (cred.authenticatorAttachment === 'cross-platform' && signCount <= cred.counter) {
    cred.compromised = true;
    return {
      verified: false,
      error: `Cloned authenticator detected: roaming hardware key signature counter (${signCount}) must strictly exceed stored counter (${cred.counter})`
    };
  }
  cred.counter = signCount;
```