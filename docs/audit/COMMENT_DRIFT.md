# Code Comment Drift Record

This document catalogues claims regarding Technology Readiness Level (TRL), compliance, architecture, and security guarantees that appear in code comments, test file banners, or UI strings within `src/` and `tests/`, but are unverified or drift from the empirical baseline established in `docs/audit/GROUNDED_EVIDENCE_PACK.md`.

In accordance with audit directives, the original code comments remain unmodified in the source tree, and their discrepancies are logged below.

---

## 1. TRL Overstatements in Comments

| File Path | Line(s) | Verbatim Comment / Code String | Empirical Reality |
| :--- | :--- | :--- | :--- |
| `src/lib/crypto/ctap2Harness.ts` | 3 | `* Project Bilanx — TRL 6 Operational Pilot Sandbox` | Platform is TRL 4 (lab-integrated on fixtures and emulators). CTAP2 harness is a deterministic headless simulator. |
| `src/lib/webauthnEnclave.ts` | 3 | `* TRL 6 Operational Pilot: Hardware Security Key & Enclave Binding via WebAuthn / FIDO2 / CTAP2` | WebAuthn client wrapper interacts with browser WebAuthn API or simulator; no demonstrated operational pilot environment (TRL 4). |
| `src/sandbox/lib/e2e/runSwissDemonstration.ts` | 3 | `* TRL 6 Operational Pilot Sandbox E2E Pipeline Orchestrator` | Orchestrator runs in-memory pipeline using local presets and mock/simulated enclave. TRL 4. |
| `src/sandbox/lib/pilotProfiles.ts` | 3 | `* Project Bilanx — TRL 6 Operational Pilot Sandbox` | Configuration presets for demo profiles. TRL 4. |
| `src/server/app.ts` | 1057 | `// WebAuthn / Hardware Enclave API Endpoints (TRL 6 Hybrid: Platform & Cross-Platform / YubiKey)` | Express endpoints for WebAuthn ceremony; operates in-memory; no HSM or production hardware bound. |
| `src/server/app.ts` | 1090 | `// Hardened WebAuthn Registration Verification (REM-03 / TRL 6)` | In-memory WebAuthn verification logic. TRL 4. |
| `src/server/webauthnServer.ts` | 6 | `* Project Bilanx Sovereign eIDAS Node (TRL 5 Hardware Enclave Binding)` | Hardware enclave binding is simulated/standard WebAuthn library without certified hardware attestation root validation. Subsystem TRL 4. |
| `tests/pilot_sandbox_e2e_test.ts` | 2, 160 | `* Bilanx — TRL 6 Operational Pilot Sandbox E2E Verification Harness` / `BILANX TRL 6 OPERATIONAL PILOT SANDBOX E2E VERIFICATION SUITE` | Test harness runs against ephemeral local Express server with simulated CTAP2 authenticator. TRL 4. |
| `src/sandbox/lib/generateDkSvsPdf.ts` | 107, 113, 238 | `TRL 6 Operational Pilot`, `achieved Technology Readiness Level (TRL) 6 with operational pilot validation across Swiss and Italian jurisdictions.`, `CLASSIFICATION: CONFIDENTIAL // TRL 6 PILOT` | PDF generator claims TRL 6 operational pilot; no external deployment or live pilot is active. |
| `src/sandbox/SwissUnifiedPoCDemo.tsx` | 104, 109, 172, 489, 632, 823, 881, 1304, 1574, 2096, 2104 | Comments and UI strings: `Dual Pilot Pipeline (TRL 6)`, `TRL 6 Operational Validation Profile`, `Point-of-Sale Pilot (TRL 6)`, `SOVEREIGN PILOT PIPELINE (TRL 6)`, `TRL 6 Cross-Border Gateway`, `Hardware Touch ID / Secure Enclave Assertion Verified (TRL 5)`, `TRL 5 Hardware Enclave` | Demonstrator UI strings hardcoding TRL 5 and TRL 6. The mounted screen is this file, behind `GoogleAuthGate`. |

---

## 2. Zero-Liability, GDPR-Immunized, & PII Quarantine Claims

| File Path | Line(s) | Verbatim Comment / Code String | Empirical Reality |
| :--- | :--- | :--- | :--- |
| `src/sandbox/lib/e2e/runSwissDemonstration.ts` | 8, 282, 661 | `* - Strict zero-PII boolean verification`, `// Quarantined PII Record (Strict 0-byte server leakage)`, `// STEP 4: Zero Data-Liability POS Validation Envelope & Audit Receipt` | PII quarantine is evidenced only as a client-side JavaScript constant object (`quarantinedPii`) in local memory. "Zero data-liability" and "strict 0-byte server leakage" are unproven legal and architectural properties. |
| `src/sandbox/lib/pilotProfiles.ts` | 8, 62, 79, 95, 112 | `Strict zero-PII boolean verification (0 bytes personal data transmitted)`, `legalDisclaimer: 'Plaintext PII is strictly quarantined on user hardware under Swiss FADP Art. 6...'`, `zero data-liability in accordance with Italian AgCom Delibera 9/24/CONS` | Declarative configuration strings and UI disclaimers; not formal legal or technical guarantees. |
| `src/sandbox/lib/PdfReceiptGenerator.ts` | 6, 85, 216 | `1. Swiss Profile (CH - FADP / Retail POS Zero Data-Liability Clearance)`, `Zero Data-Liability Retail Point-of-Sale Clearance Receipt`, `0 BYTES (ZERO DATA-LIABILITY SURFACE)` | Hardcoded text strings printed inside the generated PDF document. |
| `src/sandbox/SwissUnifiedPoCDemo.tsx` | 655, 1489 | `Definitive proof-of-concept demonstrating zero data-liability retail compliance...`, `Zero Data-Liability Validation Envelope` | Hardcoded UI marketing copy. |
| `tests/adversarial_security_stress_test.ts` | 11, 717 | `Vector 5: PII Quarantine Leakage Check (Envelope, QR Matrix, Wire Payloads, 0 Bytes Guarantee)`, `Merchant Clearance Zero Data-Liability Guarantees` | Tests only inspect local mock objects in test memory for substring containment of specific names. |
| `tests/pilot_sandbox_e2e_test.ts` | 673, 688 | `Zero Data-Liability envelope strictly withheld` | Assertion label for negative test cases. |
| `tests/swiss_unified_e2e_test.ts` | 9, 136, 295 | `Zero Data-Liability Validation Envelope`, `Zero Data-Liability & Zero PII Leakage Guarantee` | Test documentation comments and console log banners. |

---

## 3. eIDAS LoA High and Protocol Interoperability Claims

| File Path | Line(s) | Verbatim Comment / Code String | Empirical Reality |
| :--- | :--- | :--- | :--- |
| `src/sandbox/lib/e2e/runSwissDemonstration.ts` | 13, 14 | `* 2. Italian Profile (IT - AgCom & eIDAS LoA High)`, `* - eIDAS Level of Assurance High mapping` | LoA High is a target profile definition, not an achieved state. Assertions are synthesized from local fixtures. |
| `tests/pilot_sandbox_e2e_test.ts` | 520, 550 | `italianAdultResult.citizen.levelOfAssurance === 'high'` and a substantial-LoA preset must return `success === false` | The test checks a local string on a preset (`'high'` / `'substantial'`). It does not check an accredited eIDAS node assertion. |
| `src/server/webauthnServer.ts` | 84–95 | `KNOWN_AAGUIDS: Record<string, string> = { ... }` | Static lookup dictionary mapping AAGUIDs to names, including `00000000-0000-0000-0000-000000000000` (Platform Authenticator / Simulator). Does not validate authenticator attestation certificate chains via FIDO Alliance Metadata Service (MDS). |
| `src/data.ts` | 224–285 | `DEFAULT_UHD_RFID_ASSERTIONS: UhdRfidAssertion[] = [ ... ]` | Static catalog of four tags, including counterfeit and recalled UIDs. No physical RFID reader driver. The stock-policy branch is a string compare. |
| `src/sandbox/lib/generateDkSvsPdf.ts` | 145 | `certified 1355-byte binary proof verified at POST /api/v1/age-gate/verify` | The route verifies the proof bytes. It does not require the threshold byte to be 18. |
| `src/sandbox/README.md` | 9, 19, 32 | `Primary UI (UnifiedLabDemo)` | `UnifiedLabDemo.tsx` is not in this tree. `App.tsx` mounts `SwissUnifiedPoCDemo`. |
