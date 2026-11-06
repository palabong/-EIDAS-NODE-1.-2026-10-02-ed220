# Architectural Mapping, TRL Assessment & E2E Implementations Report

**Project**: `PROJECT-BILANX / EIDAS-NODE-1`  
**System Designation**: Bilanx Dual-Key Sovereign Validation System (DK-SVS) Lab Sandbox  
**Date**: October 2026  
**Document Type**: Architectural Audit & Technology Readiness Evaluation  

> **Evidence Limits**: This report reflects verified repo facts and code inspection. For verbatim snapshots, exact file line ranges, command outputs, and known boundaries, refer directly to [`docs/audit/GROUNDED_EVIDENCE_PACK.md`](docs/audit/GROUNDED_EVIDENCE_PACK.md). Claims living exclusively in source comments are indexed in [`docs/audit/COMMENT_DRIFT.md`](docs/audit/COMMENT_DRIFT.md).

---

## 1. Architectural System Overview

The Bilanx platform models a privacy-preserving age-gating and credential verification workflow in a laboratory sandbox by decoupling identity assertion from attribute disclosure. In the current implementation:
- Citizen identity attributes are held in local client memory within a JavaScript object (`quarantinedPii` in `src/sandbox/lib/e2e/runSwissDemonstration.ts`).
- Verification is performed using non-interactive zero-knowledge proofs (NIZKP) and an ephemeral dual-key signing handshake between client and server.
- The platform operates as an in-process laboratory prototype using simulated credentials, local mock datasets, and software authenticators. It is not connected to a live operational environment.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                CLIENT / EDGE SANDBOX                                   │
│                                                                                        │
│  [ Step 0: Mock RFID ]  ──►  [ Step 1: Client Ingestion ]  ──►  [ Step 2: Enclave ]    │
│  Static array lookup         Preset profiles / SAML fixture     WebAuthn / Emulator    │
│  (DEFAULT_UHD_RFID_...)      In-memory `quarantinedPii` obj     Software CTAP2 / Sim   │
│                                                                           │            │
│  [ Step 4: PDF Receipt ] ◄──  [ Step 3: Dual-Key Handshake & ZKP ] ◄──────┘            │
│  Client jsPDF generation      1,355-byte Base-2 Sigma Range Proof                      │
│  Simulated clearance envelope @noble/curves (P-256) point multiply                     │
└──────────────────────────────────────────▲─────────────────────────────────────────────┘
                                           │ Ephemeral Challenge & ECDSA Signature Check
┌──────────────────────────────────────────▼─────────────────────────────────────────────┐
│                          LOCAL BACKEND / VERIFIER PROCESS                              │
│                                                                                        │
│  Node.js / Express Server (`src/server/app.ts`)                                        │
│  ├── Ephemeral Session & Challenge State (`sessionManager.ts`)                         │
│  ├── In-Memory WebAuthn Server (`webauthnServer.ts`)                                   │
│  ├── In-Memory SQLite Audit Log (`accessLogDb.ts`)                                     │
│  └── Python SAML 2.0 Subprocess Bridge (`saml_engine/engine.py`)                       │
│      ├── Regex-based DOCTYPE/ENTITY XML Pre-check (No defusedxml)                      │
│      ├── Synthetic Fixture Validation (`saml_engine/fixtures.py`)                      │
│      └── Static eIDAS Minimum Dataset Attribute Mapping (`mapping.py`)                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Core Subsystems

#### 1.1 Edge Presentation & Lab Demonstrators (`src/sandbox/`, `src/components/`)
- **Swiss Demonstration Profile (`CH - FADP / Retail POS`)**: Client-side simulated workflow checking a 18+ threshold against local preset credentials.
- **Italian Demonstration Profile (`IT - AgCom / Target eIDAS LoA High`)**: Demonstrator targeting eIDAS Level of Assurance High as a policy profile goal using mock citizen attributes (`Matteo Russo`, `Marco Rossi`).
- **Mock UHF RFID Inspection (`Step 0`)**: Static in-memory lookup against `DEFAULT_UHD_RFID_ASSERTIONS` in `src/data.ts`. No physical reader driver or hardware interface is present.
- **Client Receipt Generation**: Client-side vector QR matrix rendering (`QrCodeSvg.tsx`) and client-side PDF document generation using `jspdf` (`PdfReceiptGenerator.ts`, `generateDkSvsPdf.ts`).

#### 1.2 Cryptographic & Zero-Knowledge Layer (`src/sandbox/lib/crypto/`)
- **Pedersen Commitments (`pedersen.ts`)**: Implemented over NIST P-256 using the `@noble/curves/nist.js` JavaScript library for elliptic curve point multiplication ($C = x\cdot G + r\cdot H$). WebCrypto `crypto.subtle` is **not** used for point operations.
- **Base-2 Bitwise Sigma Range Proofs (`range_b2.ts`, `range_b2_codec.ts`)**: Proves an 8-bit decomposition ($Age - Threshold \ge 0$, delta up to 255) using Pedersen commitments and Chaum-Pedersen sigma protocols.
- **Proof Codec & Wire Layout**: Fixed **1,355 bytes** serialized via `range_b2_codec.ts`:
  - `[0..0]` Version (1 byte)
  - `[1..1]` Threshold (1 byte)
  - `[2..34]` Master Commitment $C$ (33 bytes compressed point)
  - For each of 8 bits ($8 \times 161\text{ bytes} = 1,288\text{ bytes}$):
    - `[0..32]` Bit Commitment $C_i$ (33 bytes)
    - `[33..64]` Challenge $c_0$ (32 bytes)
    - `[65..96]` Challenge $c_1$ (32 bytes)
    - `[97..128]` Response $s_0$ (32 bytes)
    - `[129..160]` Response $s_1$ (32 bytes)
  - `[1323..1354]` Blinding factor difference $r_{diff}$ (32 bytes)

#### 1.3 Hardware Enclave & WebAuthn Layer (`src/lib/`, `src/server/webauthnServer.ts`)
- **WebAuthn Emulation & Registration**: Implements W3C WebAuthn ceremony endpoints in Node.js.
- **AAGUID Lookup Table**: `KNOWN_AAGUIDS` in `webauthnServer.ts` is a static dictionary mapping AAGUID strings to descriptive names, including the all-zero simulator ID (`00000000-0000-0000-0000-000000000000`). It does not validate attestation trust chains against the FIDO Alliance Metadata Service (MDS).
- **Headless CTAP2 Simulator**: Automated tests use a software-based emulator (`Ctap2HardwareKeyHarness` in `ctap2Harness.ts` and `SoftwareSecureEnclaveSimulator` in `simulatorEnclave.ts`).

#### 1.4 Verifier Backend & SAML Engine (`src/server/`, `saml_engine/`)
- **Python SAML 2.0 Engine (`engine.py`)**: Subprocess executed via Python standard library.
- **XXE Controls**: Enforces XML security via a regular expression pre-check (`_DTD_REGEX = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)`) before calling Python's standard `xml.etree.ElementTree`. Does not use hardened XML parsing libraries (such as `defusedxml`).
- **Fixture-Based Verification**: SAML responses are generated and verified against synthetic local fixtures (`saml_engine/fixtures.py`). No connection to live eIDAS networks or national Identity Providers (SPID/CIE) exists.
- **Dual-Key Verification**: Verification of ECDSA signatures in `src/server/app.ts` is performed via Node.js `webcrypto.subtle.verify`.

---

## 2. Technology Readiness Level (TRL) Assessment

The overall platform and its subsystems are assessed according to standard European Commission / ISO TRL definitions based strictly on grounded repository evidence:

| Subsystem | Assessed TRL | Empirical Justification & Limitations |
| :--- | :---: | :--- |
| **Overall Platform** | **TRL 4** | **Component validation in laboratory environment.** The system integrates cryptographic proofs, local mock identity ingestion, and an Express verifier running against local fixtures and emulators. Not demonstrated in a relevant operational environment. |
| **ZK-NIZKP Range Proofs** | **TRL 4** | Mathematical 8-bit decomposition and sigma proof validated in test harnesses using `@noble/curves`. Prover runs in browser/Node.js; no hardware acceleration or formal zero-knowledge security audit. |
| **Dual-Key Handshake** | **TRL 3** | Experimental proof-of-concept. Server generates ephemeral keys and verifies signature via WebCrypto; basic challenge check without complete multi-party session lifecycle or HSM key protection. |
| **WebAuthn / Enclave Binding** | **TRL 4** | Software-implemented WebAuthn ceremony tested against browser WebCrypto and headless CTAP2 simulators. Relies on a static AAGUID label map without FIDO MDS chain validation. |
| **eIDAS SAML Bridge** | **TRL 4** | Protocol parser tested against synthetic local XML fixtures. Relies on regex pre-filtering for XXE. No live national federation or identity provider testing. |
| **UHF RFID Verification** | **TRL 2** | Conceptual technology formulation. Implemented exclusively as a hardcoded static array (`DEFAULT_UHD_RFID_ASSERTIONS`). No hardware driver or reader interface present. |

### Gaps to TRL 5 and TRL 6
Advancing the platform beyond laboratory validation requires addressing the following incomplete boundaries:
1. **Live National eIDAS / IdP Integration (Gap to TRL 5–6)**:
   - Replace synthetic test fixtures with real metadata exchange and assertion validation against live testbeds (e.g., Italian SPID/CIE federation or European eIDAS testing proxies).
2. **Hardware Security Module (HSM) Binding (Gap to TRL 5–6)**:
   - Institutional private keys are currently stored in application memory or local environment configuration. Production keys require PKCS#11 or cloud HSM integration.
3. **Physical Retail POS SDK & Reader Drivers (Gap to TRL 5–6)**:
   - Step 0 (RFID) requires physical UHF RFID reader drivers and serial/USB protocols. Step 3/4 requires integration into physical merchant terminal environments.
4. **Third-Party Security & Cryptographic Auditing (Gap to TRL 5–6)**:
   - Independent formal review of the Sigma protocol implementation, side-channel resilience of `@noble/curves` in this context, and XML parser security.

---

## 3. Test Suites & Verification Status

### Executed Tests
- **`saml_engine/test_engine.py`**: Executed directly via `python3 -m unittest`.
  - **Result**: `Ran 30 tests in 1.746s. OK` (30 passed, 0 failed).
  - **Scope**: Verifies XML generation, canonicalization, regex DTD rejection, signature verification, and fixture validation against local certificates.
- **`npm run test:all`**: Executed via shell.
  - **Result**: Execution halted after the Python suite with `Error: listen EPERM: operation not permitted` on a `tsx` IPC socket pipe (`/var/folders/.../tsx-.../....pipe`).
  - **Status**: The seven TypeScript test suites did **not** complete execution in this test environment. They cannot be reported as passed test runs.

### Test Harness Inventory in Repository

| Test File | Execution Type | Description & Intent |
| :--- | :--- | :--- |
| `tests/saml_e2e_server_test.ts` | **Fixture** | Tests HTTP endpoints (`/saml/*`) using assertions generated by Python `fixtures.py`. |
| `tests/b2_acceptance_harness.ts` | **Mock** | Tests mathematical boundary conditions (e.g. 17 vs 18) and proof byte size. |
| `tests/e2e_dualkey_agegate_harness.ts` | **Network (Localhost)** | Tests HTTP handshake and age-gate verification against ephemeral local Express server. |
| `tests/webauthn_e2e_test.ts` | **Hardware (Emulated)** | Tests WebAuthn endpoints using ECDSA key generation in Node.js test harness. |
| `tests/swiss_unified_e2e_test.ts` | **Fixture** | Tests sequential execution of Swiss workflow steps using mock citizen profiles. |
| `tests/adversarial_security_stress_test.ts` | **Fixture** | Tests simulated attack vectors (bit flips, proof mutation, origin mismatch) against local server. |
| `tests/pilot_sandbox_e2e_test.ts` | **Hardware (Emulated)** | Comprehensive test script using the headless CTAP2 harness and local mock profiles. |

---

## 4. Architectural Boundaries & System Status

| Feature / Subsystem | Repository Implementation File | Live External System Contacted |
| :--- | :--- | :---: |
| **SAML 2.0 Ingestion** | `saml_engine/engine.py` | **No** (Local fixtures only) |
| **WebAuthn Attestation** | `src/server/webauthnServer.ts` | **No** (Software emulation / local WebAuthn) |
| **PII Quarantine** | `src/sandbox/lib/e2e/runSwissDemonstration.ts` | **No** (Local JS object in client memory) |
| **ZKP Range Proof** | `src/sandbox/lib/crypto/range_b2.ts` | **No** (Local `@noble/curves` execution) |
| **RFID Tag Verification** | `src/data.ts` | **No** (Static mock data array) |

### Dead Ends & Absent Components
- **CI / Automated Pipeline**: **Absent** (No `.github/workflows` or `.gitlab-ci.yml` found in repository).
- **Hardware Security Module (HSM) / PKCS#11**: **Absent** (Institutional keys generated/loaded in process memory).
- **Live SPID / CIE / eIDAS Federation**: **Absent** (No live network endpoints configured).
- **Physical POS Terminal SDK**: **Absent** (Web browser demo interface only).
- **Billing / Metering Engine**: **Absent**.
- **Deployment Artifacts**: **Present** (`Dockerfile`, `fly.toml`). A container deployment specification does not constitute an operational pilot.
- **eIDAS LoA High**: **Target Profile Only** (Simulated via local mock metadata; not an accredited operational status).
