# Bilanx DK-SVS Lab Sandbox

**TRL 4 Cryptographic Lab (Dual-Key + B2 Age-Gate)**

> **Evidence Limits**: This project is evaluated at TRL 4 (lab-integrated components on fixtures and emulators). For grounded repo facts, snapshots, test execution outputs, and boundary matrices, see [`docs/audit/GROUNDED_EVIDENCE_PACK.md`](docs/audit/GROUNDED_EVIDENCE_PACK.md). Discrepancies in source comments are recorded in [`docs/audit/COMMENT_DRIFT.md`](docs/audit/COMMENT_DRIFT.md).

The lab UI is `SwissUnifiedPoCDemo`. A clearance is one server check: the user signs `challengeId:secondFactorHash:proofSha256Hex`, and the server accepts the range proof only when its threshold byte is 18. 
For detailed architecture, status, and performance characteristics, please see [src/sandbox/README.md](src/sandbox/README.md).

## Running Locally

To run this project locally:

```bash
npm install
npm run dev
```
