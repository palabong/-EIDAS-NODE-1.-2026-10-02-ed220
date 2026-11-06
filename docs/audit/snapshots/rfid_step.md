```typescript
// Path: src/data.ts
// Lines: 223-285
// Constant array of mock UHF RFID assertions - no physical reader driver or LLRP library present.
// The array continues through the recalled Chronos UID below. Status is a string field.

// Institutional UHF RFID Physical Product Assertions (Catalog for Step 0)
export const DEFAULT_UHD_RFID_ASSERTIONS: UhdRfidAssertion[] = [
  {
    id: "RFID-SAML-2026-06-23-01",
    timestamp: "2026-06-23T10:15:30.000Z",
    hardwareUid: "UID-9904-AUTH-951",
    productName: "Audentes Mint Tobacco Pods (Pack of 4)",
    category: "Tobacco",
    status: "authentic",
    hmacSha256: "bf89d7fa13cde6a54101bc89a742cd90981b2fcd1054a896d74b96791a82bc1b",
    tagsRead: 12,
    rssi: -32,
    collisions: 1,
    issuer: "http://consortium-rfid-svs.int",
    exciseRecovered: 3.85,
    signature: "SIG-ECDSA-AUDNT-9904A"
  },
  {
    id: "RFID-SAML-2026-06-23-02",
    timestamp: "2026-06-23T11:42:15.000Z",
    hardwareUid: "UID-8812-AUTH-324",
    productName: "Veritas Premium Aged Cognac v2",
    category: "Alcohol",
    status: "authentic",
    hmacSha256: "2d3e5f4c8b9a1e0f6d8c7b9a5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d",
    tagsRead: 8,
    rssi: -28,
    collisions: 0,
    issuer: "http://consortium-rfid-svs.int",
    exciseRecovered: 3.85,
    signature: "SIG-ECDSA-VERT-8812C"
  },
  {
    id: "RFID-SAML-2026-06-23-03",
    timestamp: "2026-06-23T13:05:00.000Z",
    hardwareUid: "UID-1102-FAKE-881",
    productName: "Lumina Grapefruit Ice Disposable",
    category: "Vaporizer",
    status: "counterfeit",
    hmacSha256: "8812739fa8e20cf3a209bc923dd8842bc01a9dfca891efcf004297bcda084e12",
    tagsRead: 24,
    rssi: -48,
    collisions: 5,
    issuer: "http://consortium-rfid-svs.int",
    exciseRecovered: 0,
    signature: "SIG-UNKNOWN-OR-REVOKED"
  },
  {
    id: "RFID-SAML-2026-06-23-04",
    timestamp: "2026-06-23T15:20:10.000Z",
    hardwareUid: "UID-3221-RECALLED-60",
    productName: "Chronos CBD Isolate Vaporizer Pen",
    category: "Cannabinoids",
    status: "recalled",
    hmacSha256: "fe382a938c01d9f0a2cf8b92d04a7c8b201a9bfe8902c3d049f7e8a9bc01a2f4",
    tagsRead: 15,
    rssi: -35,
    collisions: 2,
    issuer: "http://consortium-rfid-svs.int",
    exciseRecovered: 0,
    signature: "SIG-ECDSA-CHRONOS-3221A"
  }
];
```