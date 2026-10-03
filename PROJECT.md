# Project: Bilanx / eIDAS Node (Remediation & TRL Hardening)

## Overview
Remediation of Project Bilanx / eIDAS Node addressing findings REM-01 through REM-11 from `AUDIT_REPORT.md`.
Transitioning from insecure stubs and vulnerabilities to authentic cryptographic verification, secure credential management, dependency hygiene, and a unified automated test suite.

## Architecture & Code Layout
- `server.ts`: Express API server hosting SAML bridge, Google Auth, and WebAuthn endpoints.
- `src/server/webauthnServer.ts`: Server-side FIDO2 / WebAuthn registration and authentication verification logic.
- `src/server/samlBridge.ts`: TypeScript bridge interfacing with Python SAML engine.
- `saml_engine/engine.py`: Core Python SAML 2.0 validation and metadata engine.
- `src/lib/KpiTelemetry.ts`: Telemetry library (must be CJS/ESM dual-safe).
- `src/sandbox/`: Dual-Key and ZKP B2 Age-Gate cryptosystem.
- `tests/`: Automated test suites (SAML E2E, WebAuthn E2E, sandbox acceptance harnesses).
- `.gitignore`: Secret and key exclusion rules.
- `package.json`: NPM dependencies, build scripts, and unified test runner.

## Milestones
| # | Milestone Name | Scope | Dependencies | Status |
|---|----------------|-------|--------------|--------|
| M1 | Multi-Agent Exploration | 3 Explorers analyze REM-01 to REM-11 | None | IN_PROGRESS |
| M2 | Implementation | Worker executes full code, config & test remediations | M1 | PLANNED |
| M3 | Dual Review & Adversarial Verification | 2 Reviewers + 2 Challengers empirically test changes | M2 | PLANNED |
| M4 | Forensic Integrity Audit | teamwork_preview_auditor integrity audit | M3 | PLANNED |
| M5 | Gate & Reporting | Final verification synthesis and report to Sentinel/Caller | M4 | PLANNED |

## Interface Contracts & Remediation Targets
### Key Protection (REM-01, REM-04)
- `institutional-key.json` and `*.key.json` added to `.gitignore`.
- No private key files or unencrypted secret keys committed to version control.
- `server.ts` loads institutional key from environment or local path with fallback safeguards.

### Google Auth Hardening (REM-02)
- `/api/auth/verify-google` strictly uses `googleOAuthClient.verifyIdToken`.
- Unverified JWT fallback (`parts.length === 3`) eliminated completely.
- Failures unconditionally return HTTP 401 Unauthorized.

### Authentic WebAuthn / FIDO2 Verification (REM-03)
- `/api/webauthn/register-options` & `/api/webauthn/register-verify`: Generates genuine cryptographically random challenge, stores in memory with TTL, decodes attestation / credential public key, registers credential.
- `/api/webauthn/authenticate-options` & `/api/webauthn/authenticate-verify`: Issues genuine challenge; decodes `authenticatorData` and `clientDataJSON`; verifies challenge match and origin (`rpId`); verifies ECDSA P-256 signature using the registered public key; increments counter to prevent replay/cloning.
- Eliminates stub constant `'HARDWARE_ENCLAVE_ECDSA_P256_PUBLIC_KEY'` and unverified `{ verified: true }`.

### Dependency & Build Hygiene (REM-05, REM-10, REM-11)
- `npm audit` resolved to 0 high/critical vulnerabilities.
- Unused dependencies (`@google/genai`, `motion`) removed from `package.json`.
- `import.meta` warning in `src/lib/KpiTelemetry.ts` resolved for CJS bundle.

### Test Expansion & Dossier Alignment (REM-06, REM-07, REM-08, REM-09)
- `tests/webauthn_e2e_test.ts` added covering happy path and adversarial attacks (tampered signatures, invalid challenges, replay).
- `package.json` `"test"` script executes all test suites: `test:saml`, ZKP B2 harness, Dual-Key harness, and WebAuthn E2E.
- `saml_engine/engine.py` decoupled from `fixtures.py` in production imports.
- Latency claims in `TECHNICAL_DOSSIER_v2.1.md` and `TECHNICAL_DOSSIER_v2.4.md` aligned to empirical ~816ms.
