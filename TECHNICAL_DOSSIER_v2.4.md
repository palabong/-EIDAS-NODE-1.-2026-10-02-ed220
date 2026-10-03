# Technical Position Paper — Dual-Key Sovereign Validation System (DK-SVS)
**Version 2.4 (Implementation-Accurate) | July 2026**

## 1. Executive Summary
This paper documents the implemented fundament of the Dual-Key Sovereign Validation System (DK-SVS) covering Phases F1 through F3. It details the precise cryptographic architecture, runtime orchestration, and empirical performance metrics of the system. The sandbox lab demonstrates that a bounded ZK age-gate on P-256 is computationally practical at current pure-JS cost.

## 2. Problem Statement
Current age verification mechanisms frequently require users to transmit plaintext dates of birth or raw Personally Identifiable Information (PII) to relying parties, violating data minimization principles and increasing breach risks. A zero-knowledge alternative is required that cryptographically guarantees an individual meets a threshold age without exposing their exact age, while simultaneously establishing a strongly bound session between the user and an institutional authority.

## 3. System Overview — Dual-Key Model
The DK-SVS operates on a Dual-Key validation schema:
- **Key 1 (Institutional):** Represents the authoritative eIDAS/SVS node issuing verifiable challenges.
- **Key 2 (User/Wallet):** Represents the user's local cryptographic context (e.g., Secure Enclave or browser IndexedDB).
The system enforces a strict cryptographic handshake (ECDSA P-256) binding the institutional challenge to the user's second factor, establishing a secure perimeter before zero-knowledge proofs are transmitted.

## 4. Cryptographic Architecture (Implementation-Accurate)
The cryptographic core relies on standard elliptic curve operations over the NIST P-256 curve (implemented via `@noble/curves`):
- **Pedersen Commitments:** Utilized for age commitments.
- **NUMS Generator (H):** A Nothing-Up-My-Sleeve (NUMS) generator `H` is implemented via standard hash-to-curve methods, ensuring computational hiding and binding without a trusted setup.
- **B2 Bit-Decomposition Range Proof:** The system implements an 8-bit decomposition range proof. For a default threshold $T=18$, the proof cryptographically asserts that the age $x$ falls within the bounded range $18 \le x < 274$.
- **Binary Encoding:** The resulting B2 proofs are serialized into a deterministic, fixed-layout binary format measuring exactly **1355 bytes**.

## 5. Runtime Architecture
The DK-SVS sandbox is structured into three primary runtime components:
- **Client E2E Orchestration:** Orchestrates the Dual-Key ECDSA payload signing and subsequent B2 zero-knowledge proof generation in a single pipeline.
- **Server Verify Endpoint:** A thin verification endpoint (`POST /api/v1/age-gate/verify`) accepts proofs via `application/octet-stream` (raw binary) or `application/json` (Base64 wrapper), decoding and verifying them against the cryptographic baseline.
- **KPI Instrumentation:** KPI-03/04/05 (prove/verify/size) are stable on the Node path. Dual-Key key persistence may emit IndexedDB warnings outside the browser; Dual-Key crypto still runs.

## 6. Security Properties — Honest Assessment
| Property | Status | Notes |
|----------|--------|-------|
| Zero-Knowledge | Achieved | Age is hidden perfectly within the Pedersen commitment. |
| Non-Interactive | Achieved | Fiat-Shamir heuristic applied for NIZKP. |
| Bounded Range | Achieved | Strictly bounded to an 8-bit decomposition (256 values above threshold). |
| Tamper-Evident | Achieved | Verification fails on any byte mutation or length anomaly. |

## 7. Performance & Measurement
Measurements were taken in a Node.js laboratory environment. The institutional challenge HTTP mock may inject artificial 80–250 ms latency; however, the Dual-Key crypto-only segment remains ~5–17 ms when measured excluding that mock delay.
- **Dual-Key Segment:** ~5–17 ms (crypto-only path).
- **B2 Prove:** ~300–400 ms class.
- **B2 Verify:** ~350–450 ms class (consistent across both client and server).
- **E2E Total:** ~680–850 ms class (~816 ms measured laboratory average in pure-JS Node.js software implementation).
- **Proof Size:** strictly **1355 bytes**.
- *Historical Baseline:* Commitment-only paths run at ~10.6 ms with 33 bytes payload.

## 8. eIDAS / EUDI Positioning
- **eIDAS-Node 3.1.0:** The official eIDAS-Node connector and proxy configurations serve as architectural references (e.g., ECDSA-SHA512, metadata modeling). A production eIDAS runtime is **not** embedded in the sandbox.
- **EUDI Wallet / OpenID4VP:** These remain target architectures for future lifecycle phases and are not part of the current live integration.

## 9. Implementation Status & TRL
- **System Sandbox Overall:** TRL 4 (Component and/or breadboard validation in laboratory environment).
- **Crypto Core Key 2 (Pedersen + B2):** TRL 4–5 (Local laboratory environment).

## 10. Risks & Limitations
- **JavaScript Runtime Constraints:** Pure JavaScript/TypeScript environments impose performance ceilings and limit protections against sophisticated side-channel attacks compared to native enclaves.
- **Performance Bound:** We do not claim sub-150 ms execution times for the full age-gate path in pure JS.
- **Proof Limitations:** The implementation strictly uses fixed 8-bit bit-decomposition. Bulletproofs or arbitrary-width range proofs are not implemented.

## 11. Roadmap
- **Phase F4:** Statistical E2E metrics campaign (N≥30) plus honest baseline export.
- **Future Phases:** Formalize the attributes catalog, integrate live EUDI Wallet / OpenID4VP flows, and explore optional WebAssembly (WASM) modules to accelerate cryptographic operations.

## 12. Conclusion
The sandbox lab demonstrates that a bounded ZK age-gate on P-256 is computationally practical at current pure-JS cost. While sub-150 ms end-to-end execution remains out of reach without native acceleration, the 1355-byte binary format and reliable 400ms verification window provide a solid foundation for sovereign validation.

## 13. Compliance Checklist
- [x] B2 range proof marked implemented (8-bit bound)
- [x] Binary size 1355 B stated
- [x] E2E Dual-Key + B2 and server verify marked achieved in sandbox
- [x] No full-path sub-150 ms claim
- [x] eIDAS-Node marked reference / not embedded runtime
- [x] EUDI marked target
- [x] TRL system = 4 (not 6/7)
- [x] Generator H NUMS disclosed as implemented in sandbox
