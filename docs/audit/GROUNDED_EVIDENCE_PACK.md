# Grounded Evidence Pack: DK-SVS / eIDAS-NODE-1

**Project Directory:** `/Users/daniele_palagi/antigravity/PROJECT-BILANX-/-EIDAS-NODE-1.-2026-10-02-ed220`  
**Audit Mode:** Empirical grounding, realigned to the working tree and the 6 October 2026 build  
**Scope:** DK-SVS / eIDAS-NODE-1 as it exists in this tree.  
**This pass:** `npm test` (exit 0), `npm run build` (exit 0), `npm run dev` health check recorded in §5.

---

## 1. Inventory

### 1.1 Directory Tree
- `src/`
  - `App.tsx`
  - `data.ts`
  - `index.css`
  - `main.tsx`
  - `types.ts`
  - `components/`: `AccessLogAuditModal.tsx`, `DocumentationMode.tsx`, `GoogleAuthGate.tsx`
  - `hooks/`: `useGoogleAuth.ts`
  - `lib/`: `KpiTelemetry.ts`, `webauthnEnclave.ts`
  - `lib/crypto/`: `ctap2Harness.ts`, `encoding.ts`, `simulatorEnclave.ts`
  - `lib/crypto/zkp/`: `nizkp.ts`, `pedersen.ts`, `range_b2.ts`, `range_b2_codec.ts`
  - `sandbox/`: `BilanxStressTest.tsx`, `LiveItemFeed.tsx`, `RecentlyProcessedItems.tsx`, `SandboxCryptoComparison.tsx`, `SandboxDocumentation.tsx`, `SandboxDossier.tsx`, `SandboxStats.tsx`, `SandboxTabNavigation.tsx`, `SwissUnifiedPoCDemo.tsx`  
    - `EidasNodeLab.tsx` and `UnifiedLabDemo.tsx` are not in this tree. `App.tsx` mounts `SwissUnifiedPoCDemo` behind `GoogleAuthGate`.
  - `sandbox/components/`: `QrCodeSvg.tsx`
  - `sandbox/context/`: `DualKeyResultContext.tsx`
  - `sandbox/hooks/`: `useBilanxDualKeyValidation.real.ts`, `useDualKeyValidation.ts`
  - `sandbox/lib/`: `PdfReceiptGenerator.ts`, `generateDkSvsPdf.ts`, `nizkp.ts`, `pilotProfiles.ts`
  - `sandbox/lib/crypto/`: `pedersen.ts`, `range_b2.ts`, `range_b2_codec.ts` (each file re-exports `src/lib/crypto/zkp/`). `sandbox/lib/nizkp.ts` re-exports the same facade. There is no second proof implementation.
  - `sandbox/lib/e2e/`: `runDualKeyAgeGate.ts`, `runSwissDemonstration.ts`
  - `sandbox/mocks/`: `bilanxMockData.mock.ts`, `useBilanxDualKeyValidation.mock.ts`
  - `server/`: `accessLogDb.ts`, `app.ts`, `samlBridge.ts`, `sessionManager.ts`, `webauthnServer.ts`
  - `server/types/`: `saml.ts`
- `saml_engine/`
  - `__init__.py`
  - `cli.py`
  - `engine.py`
  - `fixtures.py`
  - `mapping.py`
  - `test_engine.py`
  - `certs/`: `idp_ec.crt`, `idp_rsa.crt`
- `tests/`
  - `adversarial_security_stress_test.ts`
  - `b2_acceptance_harness.ts`
  - `e2e_dualkey_agegate_harness.ts`
  - `pilot_sandbox_e2e_test.ts`
  - `saml_e2e_server_test.ts`
  - `swiss_unified_e2e_test.ts`
  - `webauthn_e2e_test.ts`
- `package.json`: Present. Lists scripts (`dev`, `build`, `test`, `test:saml`, `start`) and dependencies (`express`, `react`, `@noble/curves`, `jspdf`, `tsx`, `vite`).
- `requirements.txt` / `pyproject.toml`: **Absent**. Python `saml_engine` relies on standard library (`xml.etree.ElementTree`, `xml.parsers.expat`, `hashlib`, `hmac`, `urllib`, `argparse`).
- CI config (`.github/workflows`, `.gitlab-ci.yml`): **Absent**.
- Deploy config: Present (`Dockerfile`, `fly.toml`, `.dockerignore`).

### 1.2 Runtime Entrypoints

| Entrypoint | How Started | Environment Variables Used | What Is Mock |
| :--- | :--- | :--- | :--- |
| **Full-Stack Node Server** (`server.ts` & `src/server/app.ts`) | `npm run dev` (`tsx server.ts`, Vite middleware) or `npm run start` (`node dist/server.cjs`, static `dist/`) | `PORT` (default 3000), `NODE_ENV`, `GOOGLE_CLIENT_ID`, `APP_ORIGIN`, `INSTITUTIONAL_KEY_JSON`, `INSTITUTIONAL_KEY_PATH`, `PERSIST_DEV_KEYS`, `SAML_ENGINE_URL`, `SAML_SP_ENTITY_ID`, `SAML_SP_ACS_URL`, `SAML_IDP_SSO_URL`, `GEMINI_API_KEY` (startup warning only), `USE_FIRESTORE`, `FIRESTORE_DATABASE_ID`, `GOOGLE_CLOUD_PROJECT`, `K_SERVICE`, `COOKIE_SECURE` | Local access log is `data/access_logs.json`. Firestore write runs only when `K_SERVICE`, `FIRESTORE_DATABASE_ID`, or `USE_FIRESTORE=true`. Sessions and WebAuthn credentials are in-memory `Map`s. Institutional key loads from env JSON, then a key file, then `institutional-key.json`. Production without a key fails closed. |
| **SAML 2.0 Engine CLI** (`saml_engine/cli.py`) | Subprocess spawned by `samlBridge.ts` via `python3 -m saml_engine.cli <command>` using standard I/O (stdin/stdout) | Inherits parent process environment (`process.env`) | SAML response validation and authn requests rely on self-signed fixture certificates (`saml_engine/fixtures.py`) rather than live national federation endpoints. |
| **Vite SPA Frontend** (`src/main.tsx`) | Bundled into Express static route (`dist/`) or served via Vite development middleware in `server.ts` | `VITE_GOOGLE_CLIENT_ID` | Identity inputs derive from preset static profiles (`src/sandbox/lib/pilotProfiles.ts`); UHF RFID tags derive from static object catalog (`src/data.ts`). |

---

## 2. Snapshots

Verbatim excerpts with path and line numbers are saved in `docs/audit/snapshots/`:

- **Pedersen & Range Proof Implementation:** [`docs/audit/snapshots/pedersen_range_proof.md`](snapshots/pedersen_range_proof.md)
  - Layout: 1,355 bytes. Version (1B), Threshold (1B), Master commitment (33B), 8 bit tuples of 161B ($C_i$, $c_0$, $c_1$, $s_0$, $s_1$), and $r_{diff}$ (32B).
  - Lines: `src/lib/crypto/zkp/range_b2.ts:9-28` and `src/lib/crypto/zkp/range_b2_codec.ts:10-20,52-65`.
- **Exact API Used for Point Multiply:** [`docs/audit/snapshots/webcrypto_point_multiply.md`](snapshots/webcrypto_point_multiply.md)
  - Import: `import { p256, p256_hasher } from '@noble/curves/nist.js';`
  - Function: `G.multiply(secret)` and `H.multiply(r)`, then `C.toBytes(true)`. WebCrypto `crypto.subtle` is not used for elliptic curve point multiplication.
  - Lines: `src/lib/crypto/zkp/pedersen.ts:9-17,39-49`.
- **Dual-Key Handshake:** [`docs/audit/snapshots/dual_key_handshake.md`](snapshots/dual_key_handshake.md)
  - Client signs `${challengeStr}:${secondFactorHashHex}` with user ECDSA private key.
  - Server verifies both institutional signature and user signature via `webcrypto.subtle.verify`.
  - Server stores challenge consumption boolean in memory Map (`challengeRecord.consumed = true`).
  - Lines: `src/sandbox/hooks/useBilanxDualKeyValidation.real.ts:297-307` and `src/server/app.ts:985-987,1015-1044`.
  - KPI-01 on this hook is the whole handshake latency. KPI-02 is local WebCrypto time (`coreCryptoTime`), not NIZKP verify time.
- **PII Path:** [`docs/audit/snapshots/pii_path.md`](snapshots/pii_path.md)
  - In the demonstrator (`runSwissDemonstration.ts:282-290`), name, date of birth, and user id sit on `quarantinedPii`. `serverLeakageBytes` is set to `0` in that object. `/api/v1/age-gate/verify` accepts only the proof bytes.
  - `saml_engine/mapping.py` still extracts `PersonIdentifier`, `CurrentFamilyName`, `CurrentGivenName`, and `DateOfBirth` into `pos_context`.
  - The ACS handler (`src/server/app.ts:691-744`) does not copy those name fields into the session, `data/access_logs.json`, or the HTTP body. It does store and return `age`, LoA, role, and the over-age flags. The log is JSON. It is not SQLite.
  - QR payload (`runSwissDemonstration.ts:677-692`) carries `age18`, LoA, and digests. It does not carry the preset name or date of birth.
  - PDF receipt metadata (`PdfReceiptGenerator.ts:122-131`) is envelope id, timestamps, node, LoA, product, and UID. It does not print the citizen name or birthdate.
- **SAML Parser:** [`docs/audit/snapshots/saml_parser.md`](snapshots/saml_parser.md)
  - XXE/DTD Controls: `xml.parsers.expat` with `StartDoctypeDeclHandler`, `EntityDeclHandler`, and `ExternalEntityRefHandler` blocking DTD and external entities before handing bytes to `xml.etree.ElementTree`.
  - XSW Controls: `XMLSignatureVerifier.verify_signature` (`engine.py:320-331`) rejects a second `ds:Signature` on the target or the root, and also a second `SignedInfo`, `SignatureValue`, `KeyInfo`, or `Reference`. Response handling rejects a second direct-child `Assertion` (`engine.py:831-838`). There is no regex DOCTYPE pre-filter.
  - Fixtures vs Live: Self-signed fixture certificates from `saml_engine/fixtures.py`. No live identity provider contacted.
- **WebAuthn Implementation:** [`docs/audit/snapshots/webauthn.md`](snapshots/webauthn.md)
  - Origin / RP Check: Validates `parsedClientData.origin` against `expectedOrigin`/`expectedRpId` and compares `authDataBuf` RP ID hash using `crypto.timingSafeEqual` (`webauthnServer.ts:917-943`).
  - Anti-Cloning Counter: Marks the credential compromised when `signCount <= cred.counter` (`webauthnServer.ts:991-1009`).
  - AAGUID: Static `KNOWN_AAGUIDS` (`webauthnServer.ts:84-95`). No FIDO Metadata Service client. The pilot suite's "YubiKey 5" result is `Ctap2HardwareKeyHarness` writing that AAGUID and this table naming it.
- **RFID Step:** [`docs/audit/snapshots/rfid_step.md`](snapshots/rfid_step.md)
  - Constant array `DEFAULT_UHD_RFID_ASSERTIONS` in `src/data.ts:224-285`, including counterfeit `UID-1102-FAKE-881` and recalled `UID-3221-RECALLED-60`. The gate compares the `status` string. No LLRP or reader driver.
- **Age-gate policy:** `/api/v1/age-gate/verify` calls `verifyProof` and does not read the threshold byte. `verifyProof` checks version `0x01`, length 1,355, and the sum-check against the threshold stored in the proof. `generateProof(5, 0)` verifies. The Swiss and pilot tests refuse minors by reading the preset age before they build a proof. T7 rejects a threshold byte edited in place; it does not pin `T` to 18 at the HTTP boundary.

---

## 3. Tests Actually Present

### 3.1 Test Files and Assertion Lines Matching Scope Criteria

| Criterion | Test File | Matching Line Number and Assertion Code |
| :--- | :--- | :--- |
| **Underage Rejection** | `tests/adversarial_security_stress_test.ts` | `Line 109`: `proverUnderageError === 'Age 17 is not within [T, T+255] for T=18'`<br>`Line 132`: `allBoundaryUnderageRejected ? 'All 5 boundary ages rejected' : 'Leakage detected'` |
| **Underage Rejection** | `tests/b2_acceptance_harness.ts` | `Line 21`: any throw from `generateBitwiseRangeProof(17, 18)` is recorded `PASS`. The exact message check lives in `tests/adversarial_security_stress_test.ts` line 109. |
| **LoA Validation** | `tests/pilot_sandbox_e2e_test.ts` | `Line 520`: `record(italianAdultResult.citizen.levelOfAssurance === 'high', '3.1c Citizen possesses eIDAS Level of Assurance High')`<br>`Line 550`: `record(italianSubstantialResult.success === false, '3.4a Citizen with LoA Substantial rejected under LoA High mandate')` |
| **Replay Defense** | `tests/webauthn_e2e_test.ts` | `Lines 273-276`: status 400, `verified === false`, and `error` includes `Challenge not found` or `replay`. |
| **Replay Defense** | `tests/e2e_dualkey_agegate_harness.ts` | `Line 165-166`: `assertEqual(false, replayData.valid, "E7 replayed challenge must be rejected"); assertEqual(true, replayData.reason.includes('Replay detected'))` |
| **Origin Verification** | `tests/webauthn_e2e_test.ts` | `Line 304-305`: `assert.strictEqual(originData.verified, false); assert.ok(originData.error.includes('Origin mismatch'))` |
| **Origin Verification** | `tests/adversarial_security_stress_test.ts` | `Line 398`: `allUntrustedOriginsRejected ? '100% fail-closed rejection across all 5 origins' : 'Leakage detected'` |
| **Proof Size (1355B)** | `tests/b2_acceptance_harness.ts` | `Line 127`: `const pass11 = v11 && len11 === 1355;`<br>`Line 159`: `const is1355 = p13_encoded.byteLength === 1355;`<br>`Line 185`: T14 requires both the sandbox re-export and `src/lib/crypto/zkp` codec to emit 1,355 bytes. |
| **Proof Size (1355B)** | `tests/adversarial_security_stress_test.ts` | `Line 452`: `validProofBytes.length === 1355` |
| **PII-on-Wire / Leakage** | `tests/adversarial_security_stress_test.ts` | `Line 681`: `leakedSwissPii.length === 0`<br>`Line 694`: `leakedEuPii.length === 0`<br>`Line 708`: `leakedQrPii.length === 0`<br>`Line 718-719`: `piiTransmittedBytes=0, gdprLiabilityRisk=ZERO_LIABILITY` |
| **PII-on-Wire / Leakage** | `tests/swiss_unified_e2e_test.ts` | `Line 78`: `assert(swissResult.quarantinedPii.serverLeakageBytes === 0, 'Quarantined PII server leakage is strictly 0 bytes')`<br>`Line 303-306`: `assert(!envSerialized.includes('Heinrich')); assert(!envSerialized.includes('1994-05-12'))` |

### 3.2 Test Execution Command Outputs

`npm test` on 6 October 2026, in this directory, exit code 0. The script is the eight commands below, in this order. Timings are from that run.

1. **Python SAML Engine Test Suite**
   - Command: `python3 -m unittest saml_engine/test_engine.py`
   - Output: `Ran 32 tests in 1.536s — OK`
   - Pass: 32, Fail: 0. Mock classification: `fixture`.

2. **SAML E2E Server Test Suite**
   - Command: `npx tsx tests/saml_e2e_server_test.ts`
   - Output: `📊 E2E TEST SUMMARY: 16 PASSED | 0 FAILED`
   - Pass: 16, Fail: 0. Mock classification: `fixture`.

3. **ZKP B2 Acceptance Harness**
   - Command: `npx tsx tests/b2_acceptance_harness.ts`
   - Output: `All tests passed.` T1–T14 verdict PASS. `Proof bytes (age=18): 1355`. Prove **204.79 ms**. Verify **235.18 ms**.
   - Pass: 14, Fail: 0. The T9 log line `Invalid proof buffer length: expected 1355 bytes, got 3` is the expected rejection, and that row's verdict is PASS.

4. **Dual-Key Age-Gate E2E Harness**
   - Command: `npx tsx tests/e2e_dualkey_agegate_harness.ts`
   - Output: `✅ Harness passed! All 7 cases passed.`
   - Pass: 7, Fail: 0. Mock classification: `network` (localhost loopback). Outside `NODE_ENV=test`, `/api/institutional-challenge` inserts an 80–250 ms delay. This harness does not set that env, so the delay is present. KPI-01 on the sample cases was 116–226 ms. KPI-02 was about 1–9 ms and is local WebCrypto time.

5. **WebAuthn E2E Server Suite**
   - Command: `npx tsx tests/webauthn_e2e_test.ts`
   - Output: `📊 WEBAUTHN TEST SUMMARY: 11 PASSED | 0 FAILED (100% Pass Rate)`
   - Pass: 11, Fail: 0. Mock classification: software authenticator.

6. **Swiss Unified Demonstration E2E Suite**
   - Command: `npx tsx tests/swiss_unified_e2e_test.ts`
   - Output: `✅ ALL 48/48 SWISS DEMONSTRATION E2E TEST ASSERTIONS PASSED WITH 100% SUCCESS!`
   - Pass: 48, Fail: 0. Mock classification: `fixture`.

7. **Adversarial Security Stress Test Suite**
   - Command: `npx tsx tests/adversarial_security_stress_test.ts`
   - Output: `🏆 ALL 25/25 ADVERSARIAL STRESS TEST CASES PASSED WITH 100% SUCCESS!`
   - Pass: 25, Fail: 0. Mock classification: `fixture`.

8. **Pilot Sandbox E2E Suite**
   - Command: `npx tsx tests/pilot_sandbox_e2e_test.ts`
   - Output: `🏆 PILOT SANDBOX E2E SUMMARY: 95 PASSED | 0 FAILED (100% Pass Rate)`
   - Pass: 95, Fail: 0. The banner says TRL 6. The run uses `Ctap2HardwareKeyHarness` and preset citizens. One Swiss clearance in this run was **1084 ms**. The test server skips the artificial challenge delay (`isTest`).

The suite name "hardware" is not used here. Group 1 and group 4 of the pilot file emulate a roaming authenticator in process.

---

## 4. Boundaries

### 4.1 Claim vs Implementation Matrix

| Claim in Comments / README | File That Implements It | Live External System Contacted |
| :--- | :--- | :--- |
| SAML 2.0 eIDAS Validation (`saml_engine/engine.py:12`) | `saml_engine/engine.py` | **No** (Synthetic test fixtures in `saml_engine/fixtures.py`) |
| WebAuthn FIDO2 Authentic Verification (`src/server/webauthnServer.ts:4`) | `src/server/webauthnServer.ts` | **No** (Local WebCrypto & software CTAP2 emulator) |
| Non-Interactive Zero-Knowledge Proofs (`src/lib/crypto/zkp/range_b2.ts:5`) | `src/lib/crypto/zkp/range_b2.ts` | **No** (In-process JavaScript `@noble/curves`) |
| Zero PII Server Leakage (`src/sandbox/lib/e2e/runSwissDemonstration.ts:282`) | `src/sandbox/lib/e2e/runSwissDemonstration.ts` | **No** (Client in-memory object quarantine) |
| UHF RFID Tag Validation (`src/data.ts:223`) | `src/data.ts` | **No** (Hardcoded array `DEFAULT_UHD_RFID_ASSERTIONS`) |
| Dual-Key Handshake Binding (`src/server/app.ts` `/api/v1/dual-key/verify`) | `src/server/app.ts` | **No** (Node.js in-memory Map and loopback fetch). The signed message is not an input to the range proof. |
| Age threshold pinned at 18 on `/api/v1/age-gate/verify` | `src/lib/crypto/zkp/nizkp.ts` `verifyProof` | **No.** The verifier accepts the threshold byte inside the 1,355-byte buffer. `generateProof(5, 0)` verifies. |
| AgCom Delibera 9/24/CONS Compliance (`src/sandbox/lib/pilotProfiles.ts`) | `src/sandbox/lib/pilotProfiles.ts` | **No** (Hardcoded policy rules). Pilot test line 520 compares `levelOfAssurance === 'high'` on a preset. |

### 4.2 Dead Ends Inventory

- **Hardware Security Module (HSM)**: **Absent** (Keys held in memory / local JSON file).
- **PKCS#11**: **Absent** (No PKCS#11 C-bindings or dynamic library loaders).
- **SPID / CIE (Live Italian Identity Providers)**: **Absent** (No live network connection or TLS federation).
- **POS Device Hardware SDK**: **Absent** (No USB, serial, or PC/SC driver code).
- **Billing / Payment Processing**: **Absent** (No payment gateway or real financial ledger).
- **Deploy Configuration**: **Present** (`Dockerfile`, `fly.toml`, `.dockerignore`). This pass did not call a deployed Fly machine.
- **Production bundle**: **Present** after `npm run build` on 6 October 2026. Vite wrote `dist/index.html`, `dist/assets/index-BJ-PfRDd.js` (1,275.64 kB), and CSS. esbuild wrote `dist/server.cjs` (93.9 kb). The client chunk is over the 500 kB Vite warning. `.dockerignore` excludes `tests/` from the image, so the image cannot run this suite.

---

## 5. Dev server

`npm run dev` starts `tsx server.ts`. In non-production it mounts Vite middleware and listens on `0.0.0.0:3000`.

Checked against the process started for this alignment:

- `GET /api/health` returned HTTP 200. First body `{"status":"healthy","timestamp":"2026-10-06T19:44:30.220Z"}`. A later check at `2026-10-06T19:47:19.718Z` was the same shape.
- `GET /` returned HTTP 200 and the Vite dev shell (React refresh client, `/@vite/client`, `/src/main.tsx`). That is `npm run dev`, not the static files in `dist/`. Vite appends `?t=<ms>` on the module URL, so the HTML length moves with that query: 677 bytes on the first check, 693 bytes at 19:47. The lab UI is behind `GoogleAuthGate`; this check did not complete a Google sign-in.
- The process was left listening on `http://127.0.0.1:3000`.