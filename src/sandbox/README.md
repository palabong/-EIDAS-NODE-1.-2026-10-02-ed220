# Bilanx DK-SVS Cryptographic Lab Sandbox

**TRL 4 (Lab Validated)** — This is a technical sandbox for the Dual-Key + B2 age-gate architecture. It is **not** production-ready and is **not** a national eIDAS Node.

## What Runs (Real Path)
- **ECDSA P-256 Dual-Key:** Real cryptographic validation (`useBilanxDualKeyValidation.real` + server challenge/verify).
- **Pedersen + B2 8-bit Range Proof:** Functional cryptographic implementation (`lib/crypto/*`, facade `nizkp.ts`).
- **E2E Orchestration:** Driven by `runDualKeyAgeGate` (Dual-Key hard gate → prove/verify).
- **Primary UI (`UnifiedLabDemo`):** POS ticket, live `dkProducts`/`dkWallets` resolution, policy banner (non-crypto), with compliance rebate applied **only** on crypto `APPROVED`.
- **Harnesses:** B2 T1–T9, E2E, F4 metrics campaign.
- **Proof Size:** 1355 bytes (when age ≥ 18 on facade threshold 18).

## App Navigation
- **Lab Demo (Real Path):** Default runtime (stresstest mode). Real E2E cryptographic execution loop.
- **Advanced / Dossier:** (showcase mode). Contains a mock batch UI, Key-1 validation lab (`SandboxCryptoComparison`), and technical dossier.
- **Directives:** (documentation mode).

## What is Mock / Out of Scope
- **Advanced Batch Tab:** This is purely a UI load mock. It is **not** a real E2E loop. Real E2E stress testing happens in `UnifiedLabDemo` (N≤30).
- **Target Integrations:** Full eIDAS-Node, EUDI Wallet, and OpenID4VP are target architectural endpoints, but are **not** embedded in this runtime.
- **SAML Engine:** `saml_engine` is a reference/separate track and not part of the core age-gate path.
- **Hardware/ERP:** RFID hardware and live ERP inventory sync are out of scope.
- **Removed UI:** Showcase, Screening, Editor, and Agent UIs have been removed from the runtime for architectural honesty.

## Performance Honesty
In this Node.js / pure JS lab environment, prove and verify operations take hundreds of milliseconds. Full E2E total timing is often ~680–850 ms. 
*We do not claim sub-150 ms full path execution in this pure JS lab.*

## Folder Map
```text
src/sandbox/
  UnifiedLabDemo.tsx          # primary real-path POS lab UI
  BilanxStressTest.tsx        # Advanced shell
  SandboxCryptoComparison.tsx # Key-1 mock vs real
  SandboxDossier.tsx          # Dossier renderer
  lib/crypto/                 # B2/Pedersen primitives
  lib/e2e/                    # runDualKeyAgeGate orchestration
  lib/nizkp.ts                # Facade
  hooks/                      # Lab React hooks
  mocks/                      # Mocks (e.g., for Advanced batch)
  tests/                      # Test harnesses (T1-T9, F4)
```

## KPI Baselines
- **Canonical Baseline:** Kept at the repository root as `BILANX_KPI_BASELINE_F4_e2e_20260824_1950.json`.
- **Older Baselines:** Archived under `_archive/kpi_baselines/` when present.
