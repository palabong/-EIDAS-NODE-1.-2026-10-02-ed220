/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { UserProfile, ThemeConfig, PortfolioItem, ScreeningTicket, DKProduct, DKWallet, ZKALogEntry } from './types';

export const DEFAULT_PROFILE: UserProfile = {
  name: "Daniele Palagi",
  role: "Compliance Solutions Director",
  bio: "Specializing in next-generation biometric age-verification and sovereign eID implementations designed to eradicate online underage compliance bypasses.",
  avatar: "https://images.unsplash.com/photo-1534528741775-53994a69daeb?auto=format&fit=crop&w=300&q=80",
  email: "daniele.palagi92@gmail.com",
  company: "TrustGate ID Systems",
  licenseNumber: "EU-ID-8041-A2",
  verificationRate: "99.84%"
};

export const DEFAULT_THEME: ThemeConfig = {
  mode: 'dark',
  primaryColor: '#1E3A8A', // Deep Navy Blue
  highlightColor: '#10B981' // Emerald Green
};

export const DEFAULT_PORTFOLIO: PortfolioItem[] = [
  {
    id: "biometric-trustgate",
    title: "Biometric TrustGate v2",
    description: "Anti-spoofing facial liveness analysis paired with on-device sandbox encryption. Directly addresses distance purchase vulnerabilities by validating physical presence.",
    category: "Age Gate",
    status: "certified",
    efficacyRate: 99.8,
    techStack: ["React", "WebRTC", "TensorFlow.js", "WebAssembly"],
    externalUrl: "https://trustgate.example.com",
    complianceDocLink: "https://health.ec.europa.eu/tobacco/evaluation_report_en",
    lastAudited: "2026-05-12"
  },
  {
    id: "eu-eid-node",
    title: "European eID wallet Node",
    description: "Sovereign European digital identity wallet proxy connector. Integrates with official eIDAS nodes to retrieve legally binding cryptographically signed age assertions.",
    category: "Identification",
    status: "active",
    efficacyRate: 99.9,
    techStack: ["TypeScript", "OAuth2", "ECDSA", "eIDAS Connector"],
    externalUrl: "https://eidas.example.com/node",
    complianceDocLink: "https://ec.europa.eu/digital-single-market/en/discover-eidas",
    lastAudited: "2026-06-01"
  },
  {
    id: "delivery-recipient-match",
    title: "Physical Recipient token Matcher",
    description: "Integrates with postal parcel carriers to coordinate courier eID check on physical hand-off, returning an authenticated delivery token back to the digital store.",
    category: "Compliance Audit",
    status: "under_review",
    efficacyRate: 85.0,
    techStack: ["Node.js", "REST Webhooks", "Geofencing API", "Secure Token Exchange"],
    externalUrl: "https://logistics.example.com/check",
    complianceDocLink: "https://ec.europa.eu/taxation_customs/distance-sales",
    lastAudited: "2026-04-18"
  },
  {
    id: "legacy-self-decl",
    title: "Legacy Self-Declaration Box (Standard Online Method)",
    description: "The baseline 18+ checkbox check. Flagged by the European Commission evaluation report as 80% ineffective because minors can easily click through.",
    category: "Age Gate",
    status: "revoked",
    efficacyRate: 20.0, // 80% ineffective
    techStack: ["HTML5 Forms", "Cookie State"],
    externalUrl: "https://ineffective-baseline.example.com",
    complianceDocLink: "https://ec.europa.eu/health/tobacco/publications",
    lastAudited: "2023-01-10"
  }
];

export const DEFAULT_SCREENING_TICKETS: ScreeningTicket[] = [
  {
    id: "SCR-2026-01",
    name: "Verification #98144",
    submittedAt: "2026-06-05T22:15:00Z",
    userAge: 24,
    assertionType: "tobacco",
    status: "passed",
    documentType: "Biometric Face-Scan",
    selfDeclarationValue: true,
    scannedResultScore: 99.8,
    metadataJson: JSON.stringify({
      "context": "https://schema.org",
      "type": "AgeVerificationCredential",
      "issuer": "di:trustgate:biometrics",
      "credentialSubject": {
        "ageOver": 18,
        "livenessConfidence": 0.998,
        "originCountry": "Italy",
        "timestamp": "2026-06-05T22:14:52Z"
      },
      "evaluationLog": "Liveness analysis successful. 3D projection matches profile scan. No mask or video presentation detected."
    }, null, 2),
    region: "Rome, IT",
    evaluationNotes: "High confidence biometric matches. Cryptographic assertion valid. Auto-approved."
  },
  {
    id: "SCR-2026-02",
    name: "Verification #98145 - Suspicious Checkout",
    submittedAt: "2026-06-05T23:02:10Z",
    userAge: 18, // Claimed
    assertionType: "tobacco",
    status: "failed",
    documentType: "Self-Declaration",
    selfDeclarationValue: true,
    scannedResultScore: 20.0, // Standard Check efficacy
    metadataJson: JSON.stringify({
      "context": "https://schema.org",
      "type": "StandardDistanceCheck",
      "assertion": "User checked standard cookie 18+ popup box",
      "detectedAnomalies": {
        "emailType": "high_school_student_domain",
        "ipGeographicMismatch": true,
        "deviceAgentDiscrepancy": "Automated script markers detected"
      }
    }, null, 2),
    region: "Brussels, BE",
    evaluationNotes: "Standard distance check bypassed. The IP originates from a secondary location and the browser fingerprint is linked to a secondary minor profile."
  },
  {
    id: "SCR-2026-03",
    name: "Verification #98146",
    submittedAt: "2026-06-05T23:45:12Z",
    userAge: 21,
    assertionType: "alcohol",
    status: "passed",
    documentType: "eID",
    selfDeclarationValue: true,
    scannedResultScore: 99.9,
    metadataJson: JSON.stringify({
      "context": "https://schema.org",
      "type": "eIDASWalletAssertion",
      "subject": "did:eidas:FR:passport-proxy",
      "signature": "MEYCIQCc0C0S68N8...",
      "attributes": {
        "legalAgeCheck": "PASSED_18",
        "verifiedDateOfBirth": "2005-01-14"
      }
    }, null, 2),
    region: "Paris, FR",
    evaluationNotes: "eIDAS certified identity signature is cryptographically authentic. Legally watertight verification."
  },
  {
    id: "SCR-2026-04",
    name: "Verification #98147 - Flagged Review",
    submittedAt: "2026-06-06T00:02:00Z",
    userAge: 19,
    assertionType: "adult_goods",
    status: "requires_manual_audit",
    documentType: "Biometric Face-Scan",
    selfDeclarationValue: true,
    scannedResultScore: 61.2,
    metadataJson: JSON.stringify({
      "context": "https://schema.org",
      "type": "AgeVerificationCredential",
      "issuer": "di:trustgate:biometrics",
      "credentialSubject": {
        "ageOver": 18,
        "livenessConfidence": 0.612,
        "originCountry": "Germany"
      },
      "evaluationLog": "Caution: Partial illumination mismatch in facial mesh. Device camera lens exhibits high noise. Liveness confidence borderline."
    }, null, 2),
    region: "Berlin, DE",
    evaluationNotes: "Image quality was low due to poor background illumination, which degraded liveness confidence to 61%. Needs manual operator oversight."
  }
];

// DK-SVS Mock Products
export const DEFAULT_DK_PRODUCTS: DKProduct[] = [
  {
    id: "prod-01",
    name: "Audentes Mint Tobacco Pods (Pack of 4)",
    category: "Tobacco",
    price: 18.50,
    uid: "UID-9904-AUTH-951",
    status: "authentic",
    manufacturerSign: "SIG-ECDSA-AUDNT-9904A"
  },
  {
    id: "prod-02",
    name: "Veritas Premium Aged Cognac v2",
    category: "Alcohol",
    price: 64.00,
    uid: "UID-8812-AUTH-324",
    status: "authentic",
    manufacturerSign: "SIG-ECDSA-VERT-8812C"
  },
  {
    id: "prod-03",
    name: "Lumina Grapefruit Ice Disposable (Counterfeit Serial)",
    category: "Vaporizer",
    price: 12.00,
    uid: "UID-1102-FAKE-881", // This triggers red counterfeit alert!
    status: "counterfeit",
    manufacturerSign: "SIG-UNKNOWN-OR-REVOKED"
  },
  {
    id: "prod-04",
    name: "Nox Haze Premium Nicotine Sticks",
    category: "Tobacco",
    price: 15.90,
    uid: "UID-5590-AUTH-092",
    status: "authentic",
    manufacturerSign: "SIG-ECDSA-NOX-5590T"
  },
  {
    id: "prod-05",
    name: "Chronos CBD Isolate Vaporizer Pen",
    category: "Cannabinoids",
    price: 32.50,
    uid: "UID-3221-RECALLED-60", // Recalled hardware check!
    status: "recalled",
    manufacturerSign: "SIG-ECDSA-CHRONOS-3221A"
  }
];

// DK-SVS Mock wallets (For NFC validation simulation)
export const DEFAULT_DK_WALLETS: DKWallet[] = [
  {
    id: "WAL-FR-8890",
    holderClass: "Adult Verified",
    ageGroup: "Over 18",
    cryptoSignature: "0xec2f937d389a42fbe987019acc91ee44bb938fac271c360fac1b6a71",
    country: "France",
    validAssertion: true
  },
  {
    id: "WAL-DE-1102",
    holderClass: "Minor Detected",
    ageGroup: "Under 18",
    cryptoSignature: "0x981acc77bc94fe8389da4c0a1829e2fbd01a23847cf29a8aef435502",
    country: "Germany",
    validAssertion: false
  },
  {
    id: "WAL-IT-4091",
    holderClass: "Foreign eID",
    ageGroup: "Over 18",
    cryptoSignature: "0x66c88f11add02bb2eef93a4098bdccfa29a1d120938e4aefa34bbb0d",
    country: "Italy",
    validAssertion: true
  },
  {
    id: "WAL-ES-2311",
    holderClass: "Unsigned Local Profile",
    ageGroup: "Under 18",
    cryptoSignature: "0x00000000000000000000000000000000000000000000000000000000",
    country: "Spain",
    validAssertion: false
  }
];

// ZKA Log History Mock
export const DEFAULT_ZKA_LOGS: ZKALogEntry[] = [
  {
    id: "ZKA-508-251",
    timestamp: "2026-06-06T00:45:00Z",
    operation: "CONCURRENT_DUALkey_HANDSHAKE",
    encryptedHash: "0xb3e129fac951eecc38a1dcf982aa41088496facda320f",
    ageVerified: true,
    hardwareUid: "UID-9904-AUTH-951",
    hardwareStatus: "VERIFIED",
    resultStatus: "APPROVED",
    productName: "Audentes Mint Tobacco Pods (Pack of 4)",
    retailerRebate: 1.20
  },
  {
    id: "ZKA-508-252",
    timestamp: "2026-06-06T00:52:12Z",
    operation: "CONCURRENT_DUALkey_HANDSHAKE",
    encryptedHash: "0x88f28faed2212911bca00ad7fa992bcda7f168018e6a4",
    ageVerified: true,
    hardwareUid: "UID-1102-FAKE-881",
    hardwareStatus: "COUNTERFEIT_DETECTED",
    resultStatus: "REJECTED_COUNTERFEIT",
    productName: "Lumina Grapefruit Ice Disposable (Counterfeit Serial)",
    retailerRebate: 0
  },
  {
    id: "ZKA-508-253",
    timestamp: "2026-06-06T01:05:30Z",
    operation: "CONCURRENT_DUALkey_HANDSHAKE",
    encryptedHash: "0xab88dcaad021bdeea99fac4400bccfaccf109ff13d3afb0a6",
    ageVerified: false,
    hardwareUid: "UID-8812-AUTH-324",
    hardwareStatus: "VERIFIED",
    resultStatus: "REJECTED_UNDERAGE",
    productName: "Veritas Premium Aged Cognac v2",
    retailerRebate: 0
  }
];

