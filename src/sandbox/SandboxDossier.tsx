import React, { useState } from 'react';
import { FileText, Download, Printer, Shield, Key, FileCheck, CheckCircle2, ChevronRight, BookOpen, Layers, Cpu, Server, Lock, Loader2 } from 'lucide-react';
import { generateDkSvsTechnicalPositionPaperPdf } from './lib/generateDkSvsPdf';

export function SandboxDossier() {
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [downloadPDFSuccess, setDownloadPDFSuccess] = useState(false);
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false);

  // Markdown content representing the complete Technical Position Paper
    const dossierMarkdown = `# Technical Position Paper — Dual-Key Sovereign Validation System (DK-SVS)
**v2.5 Implementation-Accurate | 20 July 2026 | TRL 4**

---

## 1. Executive Summary
The Dual-Key Sovereign Validation System (DK-SVS) is an architectural model for privacy-preserving regulatory enforcement at the retail edge. As of July 2026, the Project Bilanx DK-SVS sandbox has achieved **Technology Readiness Level (TRL) 4 (lab validation)**. 

The current environment demonstrates one clearance. The user signs \`challengeId:secondFactorHash:proofSha256Hex\` with a P-256 key. The server checks that signature and accepts the 1,355-byte range proof only when its threshold byte is 18. \`POST /api/v1/dual-key/verify\` and \`POST /api/v1/age-gate/verify\` are the same handler.

This document serves as an implementation-accurate representation of the current sandbox state. It explicitly supersedes previous versions that framed Key 1 as a local-only handshake and removes unevidenced performance or semantic claims.

---

## 2. Problem Statement
Traditional regulatory checks at the retail edge (e.g., age verification for restricted goods) require the exchange of Personally Identifiable Information (PII) or rely on visual inspection. This introduces GDPR liabilities, operational friction, and vulnerability to circumvention.

DK-SVS aims to decouple the proof of eligibility from the identity of the citizen, providing a Zero-PII validation path suitable for high-volume transactions, acting as a potential downstream consumer of eIDAS/EUDI identity assertions.

---

## 3. System Overview — Dual-Key Model
The core of the system is the Dual-Key orchestrator. Both keys must be validated for a transaction to proceed.

### 3.1 Key 1: Institutional Binding
Key 1 represents the user's registered device or credential binding.
- **Mechanism:** ECDSA P-256 signature over a specific challenge.
- **Validation Path:** The client transmits one clearance body to \`POST /api/v1/dual-key/verify\` (alias \`POST /api/v1/age-gate/verify\`). The server checks the user signature over the bound message.
- **Orchestration Constraint:** The range proof is built before that POST. A rejected signature or proof fails the clearance, and the orchestrator discards the proof bytes. A bad signature does not consume the nonce.

### 3.2 Key 2: Age-Gate NIZKP
Key 2 represents the specific semantic predicate (e.g., "Over 18").
- **Mechanism:** A Non-Interactive Zero-Knowledge Proof (NIZKP). Uses Pedersen commitments on NIST P-256 with a NUMS (Nothing Up My Sleeve) generator H, performing a B2 8-bit bit-decomposition range proof.
- **Validation Path:** The same clearance body carries the 1,355-byte proof. Server policy accepts threshold 18 only. \`verifyProof\` stays a math check and honors the threshold byte inside the proof.

---

## 4. Cryptographic Architecture

### 4.1 Key 1 (ECDSA)
- **Curve:** NIST P-256
- **Algorithm:** ECDSA with SHA-256
- **Format:** Raw IEEE P1363 (r‖s) signature encoding.

### 4.2 Key 2 (NIZKP Range Proof)
- **Curve:** NIST P-256 (\`@noble/curves\` implementation)
- **Commitment Scheme:** Pedersen commitments.
- **Range Proof Scheme:** B2 bit-decomposition (8-bit).
- **Proof Size:** Exactly 1355 bytes.

---

## 5. Runtime Architecture
1. **Initiation:** The client receives an institutional challenge (\`challengeId\`) and checks the institutional signature locally.
2. **Proof:** The client builds the 1,355-byte range proof at threshold 18.
3. **User signature:** The client signs \`challengeId:secondFactorHash:proofSha256Hex\`.
4. **Clearance:** One POST carries the signature and \`proofBase64\`. The server sets the nonce in flight before the first await, then checks the signature and the policy threshold.
5. **Decision:** Both flags follow that single response. A rejection discards the proof. The nonce is consumed only after both checks succeed.

---

## 6. Wire Formats

### 6.1 DualKeyPayload (Key 1)
\`\`\`ts
interface DualKeyPayload {
  v: 1;
  challengeId: string;
  secondFactorHash: string;      // hex lowercase SHA-256
  userPublicKey: JsonWebKey;     // EC P-256 public only (no d)
  userSignature: string;         // base64url, no padding, raw P1363
  clientTs?: string;             // optional, NOT signed
}
\`\`\`
**Canonical Signed Message (UTF-8):** \`challengeId + ":" + secondFactorHash\`

### 6.2 B2 Binary Proof (Key 2)
- **Format:** Binary encoded payload.
- **Size:** Exactly 1355 bytes.

---

## 7. Security Properties — Honest Assessment

| Property | Status in Sandbox | Notes |
| :--- | :--- | :--- |
| **Zero-PII Transmission** | Verified | The server receives only public keys, hashes, signatures, and ZK proofs. No personal data is transmitted. |
| **Server-Side Authorization** | Verified | Both Key 1 and Key 2 require explicit cryptographic verification by the server endpoints. |
| **Fail-Closed Design** | Verified | The orchestrator terminates if Key 1 fails; invalid Key 1 payloads are caught (lab-validated via tamper test E6). |
| **Replay Protection** | Partial | \`challengeId\` prevents basic replay, but comprehensive nonce management and expiration are scope for higher TRLs. |
| **Hardware Security** | Not Evidenced | Keys are currently stored in browser software (IndexedDB/CryptoKey). No secure enclave or HSM integration is present. |

---

## 8. Performance & Measurement
Performance metrics are derived from the latest F4-class measurement campaign (N=30, 0 failures) running in the sandbox environment.

| Metric | Mean (approx) | Description |
| :--- | :--- | :--- |
| \`dualKey_ms\` | ~12 ms | Client-side Dual-Key (Key 1) execution time. |
| \`server_dual_key_verify_ms\`| ~6 ms | Server-side Key 1 ECDSA verification time. |
| \`prove_ms\` (B2) | ~285–300 ms | Client-side Key 2 (B2) proof generation time. |
| \`verify_ms\` / \`server_verify_ms\` | ~350 / ~344 ms | Server-side Key 2 (B2) proof verification time. |
| \`total_ms\` | ~650–680 ms | Full end-to-end orchestrated execution time. |
| \`proofByteLength\` | 1355 bytes | Fixed size of the Key 2 binary proof. |

*Note: Total validation time is currently ~650-680ms. The project makes no claim of sub-150ms full-path execution.*

---

## 9. Implementation Status & TRL

The sandbox operates at **TRL 4 (Technology validated in lab)**.

| Component | Status | TRL |
| :--- | :--- | :--- |
| Key 1 (Institutional Binding) | Lab-Validated (Client & Server) | 4 |
| Key 2 (Age-Gate ZKP) | Lab-Validated (Client & Server) | 4 |
| Orchestrator (Fail-Closed) | Lab-Validated | 4 |
| E2E Acceptance Harness | Passing (E1-E6) | 4 |
| eIDAS-Node / SAML 2.0 | Reference Architecture Only | 2 |
| EUDI Wallet / OpenID4VP | Target Architecture Only | 1 |
| Product Legitimacy / EMCS | Not Implemented | 1 |
| WASM / Native Acceleration | Not Implemented | 1 |

---

## 10. eIDAS / EUDI Positioning
The current sandbox **does not** integrate with a live eIDAS-Node or an EUDI Wallet.
- **eIDAS-Node 3.1.0** is considered a reference architecture for ingestion, but is not embedded in the runtime.
- **EUDI Wallet (OpenID4VP)** is the strategic target for the credential source, but no implementation currently exists in the lab.

---

## 11. Risks & Limitations
1. **Performance Overhead:** JavaScript-based proof generation and verification (~650ms total) is functional for labs but may be too slow for high-throughput physical POS environments.
2. **Software Key Storage:** Browser-based key storage is vulnerable to extraction if the host device is compromised.
3. **Missing Semantic Predicates:** The system only demonstrates an age-gate. Complex predicates (e.g., AEO, EMVS, DPP) are researched but not implemented.

---

## 12. Explicit Non-Claims
To maintain transparency and auditability, the project explicitly disclaims the following:
- We **do not** claim TRL 6 or 7.
- We **do not** claim full-path execution under 150ms.
- We **do not** claim implementation of product-legitimacy, fiscal-stamp, or EMCS validation logic.
- We **do not** claim production-ready integration with European digital identity infrastructure (eIDAS/EUDI).
- We **do not** claim national-scale or POS production deployment readiness.

---

## 13. Roadmap
- **Near-term:** Solidify lab metrics, document error conditions, and optimize Javascript cryptographic overhead where possible.
- **Deferred:** Implementation of semantic predicates (AEO, DPP, etc.), EUDI Wallet / OpenID4VP integration, and WASM native acceleration.

---

## 14. Compliance Checklist
- [x] Dual-Key orchestration enforces a fail-closed constraint.
- [x] Key 1 is server-verified via ECDSA P-256.
- [x] Key 2 is server-verified via B2 Range Proof (1355 bytes).
- [x] TRL 4 boundaries strictly observed.
- [x] Zero-PII transmission confirmed in payloads.
- [x] Performance baseline documented (N=30, ~650ms E2E).

---
*End of Technical Position Paper v2.5*
`;


  const handleDownload = () => {
    try {
      const blob = new Blob([dossierMarkdown], { type: 'text/markdown;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'Project_Bilanx_DK-SVS_Technical_Position_Paper_v2.5.md');
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 3000);
    } catch (e) {
      console.error('Failed to export dossier', e);
    }
  };

  const handleDownloadPDF = async () => {
    setIsGeneratingPDF(true);
    try {
      await generateDkSvsTechnicalPositionPaperPdf();
      setDownloadPDFSuccess(true);
      setTimeout(() => setDownloadPDFSuccess(false), 3500);
    } catch (err) {
      console.error('Failed to generate PDF:', err);
    } finally {
      setIsGeneratingPDF(false);
    }
  };

  return (
    <div className="space-y-8 animate-fadeIn font-sans pb-12 print:bg-white print:text-black">
      {/* 📘 PROSECUTION & STRATEGIC COMMAND HUB HEADER */}
      <div className="bg-[#0c1930] border border-[#1b3461] rounded-xl p-8 relative overflow-hidden shadow-lg print:border-none print:bg-transparent print:p-0">
        <div className="absolute -top-12 -right-12 text-[#1b3461]/25 opacity-20 pointer-events-none print:hidden">
          <BookOpen size={240} />
        </div>
        
        <div className="flex flex-wrap items-center gap-2 mb-4 relative z-10 print:hidden">
          <span className="bg-blue-900/80 text-blue-200 px-2.5 py-1 text-[10px] font-mono font-bold uppercase tracking-widest rounded border border-blue-700/50">
            SPECIFICATION v2.5
          </span>
          <span className="bg-slate-900/80 text-slate-400 px-2.5 py-1 text-[10px] font-mono tracking-widest rounded border border-slate-800">
            CLASSIFICATION: CONFIDENTIAL
          </span>
          <span className="bg-emerald-950/80 text-emerald-400 px-2.5 py-1 text-[10px] font-mono font-bold tracking-widest rounded border border-emerald-900/50">
            TRL 4: LAB VALIDATED
          </span>
        </div>

        <h1 className="text-2xl md:text-3xl font-extrabold text-white uppercase tracking-tight font-mono mb-3 relative z-10 print:text-black print:text-2xl">
          Technical Position Paper: Project Bilanx DK-SVS
        </h1>
        <p className="text-sm text-slate-300 leading-relaxed max-w-4xl relative z-10 print:text-slate-700 print:text-xs">
          Comprehensive implementation-accurate specification for the Dual-Key Sovereign Validation System (DK-SVS) sandbox. This document serves as the official technical position paper reflecting the current lab-validated state (post Key-1 closure).
        </p>

        {/* Action Buttons */}
        <div className="mt-6 flex flex-wrap gap-4 relative z-10 print:hidden">
          <button
            onClick={handleDownload}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-bold text-xs uppercase tracking-wider transition-all inline-flex items-center gap-2 cursor-pointer shadow-md animate-none"
          >
            <Download size={14} />
            {downloadSuccess ? 'Dossier Downloaded!' : 'Download Markdown (.md)'}
          </button>
          <button
            onClick={handleDownloadPDF}
            disabled={isGeneratingPDF}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded font-bold text-xs uppercase tracking-wider transition-all inline-flex items-center gap-2 cursor-pointer shadow-md disabled:opacity-70 disabled:cursor-not-allowed"
          >
            {isGeneratingPDF ? (
              <Loader2 size={14} className="animate-spin" />
            ) : downloadPDFSuccess ? (
              <CheckCircle2 size={14} className="text-emerald-400" />
            ) : (
              <Printer size={14} />
            )}
            {isGeneratingPDF ? 'Generating PDF...' : downloadPDFSuccess ? 'PDF Downloaded!' : 'Print Dossier / Save PDF'}
          </button>
        </div>
      </div>

      {/* 📰 DOSSIER BODY */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        
        {/* Left Column: Outline/TOC (Hidden on mobile and print) */}
        <div className="lg:col-span-3 space-y-4 print:hidden sticky top-24 h-fit max-h-[80vh] overflow-y-auto pr-4 hidden lg:block border-r border-slate-200">
          <h3 className="text-xs font-black uppercase tracking-widest text-[#0B3B60] mb-4">Dossier Sections</h3>
          <nav className="space-y-1 font-mono text-xs">
            <a href="#executive-summary" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 1. Executive Summary
            </a>
            <a href="#problem-statement" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 2. Problem Statement
            </a>
            <a href="#system-overview" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 3. System Overview
            </a>
            <a href="#crypto-arch" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 4. Cryptographic Architecture
            </a>
            <a href="#security-properties" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 5. Security Properties
            </a>
            <a href="#performance" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 6. Performance
            </a>
            <a href="#non-claims" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 7. Non-Claims
            </a>
            <a href="#checklist" className="flex items-center gap-2 py-1.5 text-slate-600 hover:text-[#0B3B60] transition-colors">
              <ChevronRight size={12} /> 8. Compliance Checklist
            </a>
          </nav>
        </div>

        {/* Right Column: Actual Dossier Content */}
        <div className="lg:col-span-9 space-y-12">
          
          <section id="executive-summary" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">1</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">1. Executive Summary</h2>
            </div>
            <p className="text-slate-700 leading-relaxed text-sm">
              The Dual-Key Sovereign Validation System (DK-SVS) is an architectural model for privacy-preserving regulatory enforcement at the retail edge. As of July 2026, the Project Bilanx DK-SVS sandbox has achieved <strong className="text-slate-900">Technology Readiness Level (TRL) 4 (lab validation)</strong>.
            </p>
            <p className="text-slate-700 leading-relaxed text-sm">
              The current environment demonstrates a functional, dual-key cryptographic path where both keys undergo explicit server-side verification:
            </p>
            <ul className="list-disc ml-5 text-sm text-slate-700 space-y-2">
              <li><strong>Key 1 (Institutional Binding):</strong> Validated via ECDSA P-256 over a strict payload structure.</li>
              <li><strong>Key 2 (Age-Gate NIZKP):</strong> Validated via Non-Interactive Zero-Knowledge Proofs (NIZKP) using Pedersen commitments and an 8-bit range proof (B2).</li>
            </ul>
            <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4 rounded text-sm text-yellow-800">
              <strong>Notice:</strong> This document serves as an implementation-accurate representation of the current sandbox state. It explicitly supersedes previous versions that framed Key 1 as a local-only handshake and removes unevidenced performance or semantic claims.
            </div>
          </section>

          <section id="problem-statement" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">2</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">2. Problem Statement</h2>
            </div>
            <p className="text-slate-700 leading-relaxed text-sm">
              Traditional regulatory checks at the retail edge (e.g., age verification for restricted goods) require the exchange of Personally Identifiable Information (PII) or rely on visual inspection. This introduces GDPR liabilities, operational friction, and vulnerability to circumvention.
            </p>
            <p className="text-slate-700 leading-relaxed text-sm">
              DK-SVS aims to decouple the proof of eligibility from the identity of the citizen, providing a Zero-PII validation path suitable for high-volume transactions, acting as a potential downstream consumer of eIDAS/EUDI identity assertions.
            </p>
          </section>

          <section id="system-overview" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">3</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">3. System Overview — Dual-Key Model</h2>
            </div>
            <p className="text-slate-700 leading-relaxed text-sm">
              The core of the system is the Dual-Key orchestrator. Both keys must be validated for a transaction to proceed.
            </p>
            
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-5 grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="text-sm font-black uppercase text-[#0B3B60] mb-2 font-mono">3.1 Key 1: Institutional Binding</h4>
                <p className="text-xs text-slate-600 leading-relaxed mb-2">
                  Key 1 represents the user's registered device or credential binding.
                </p>
                <ul className="text-xs text-slate-600 space-y-1 ml-4 list-disc">
                  <li><strong>Mechanism:</strong> ECDSA P-256 signature over a specific challenge.</li>
                  <li><strong>Validation Path:</strong> One clearance body goes to <code>POST /api/v1/dual-key/verify</code>, which is the same handler as <code>POST /api/v1/age-gate/verify</code>. The server checks the user signature over <code>challengeId:secondFactorHash:proofSha256Hex</code>.</li>
                  <li><strong>Orchestration Constraint:</strong> The range proof is built before that POST. A rejected signature or proof fails the clearance and the orchestrator discards the proof bytes. A bad signature does not consume the nonce.</li>
                </ul>
              </div>
              <div>
                <h4 className="text-sm font-black uppercase text-[#0B3B60] mb-2 font-mono">3.2 Key 2: Age-Gate NIZKP</h4>
                <p className="text-xs text-slate-600 leading-relaxed mb-2">
                  Key 2 represents the specific semantic predicate (e.g., "Over 18").
                </p>
                <ul className="text-xs text-slate-600 space-y-1 ml-4 list-disc">
                  <li><strong>Mechanism:</strong> A Non-Interactive Zero-Knowledge Proof (NIZKP). Uses Pedersen commitments on NIST P-256 with a NUMS (Nothing Up My Sleeve) generator H, performing a B2 8-bit bit-decomposition range proof.</li>
                  <li><strong>Validation Path:</strong> The same clearance body carries the 1,355-byte proof. Server policy accepts threshold 18 only. <code>verifyProof</code> stays a math check and honors the threshold byte inside the proof.</li>
                </ul>
              </div>
            </div>
          </section>

          <section id="crypto-arch" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">4</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">4. Cryptographic Architecture & Wire Formats</h2>
            </div>
            
            <div className="space-y-4">
              <h3 className="text-md font-bold text-slate-800">4.1 Key 1 (ECDSA) & Payload</h3>
              <ul className="text-sm text-slate-700 list-disc ml-5 mb-2">
                <li><strong>Curve:</strong> NIST P-256, <strong>Algorithm:</strong> ECDSA with SHA-256</li>
                <li><strong>Format:</strong> Raw IEEE P1363 (r‖s) signature encoding.</li>
              </ul>
              <div className="bg-[#1e1e1e] p-4 rounded-lg font-mono text-xs text-[#d4d4d4] space-y-1 shadow-inner overflow-x-auto">
                <div className="text-[#569cd6]">interface <span className="text-[#4ec9b0]">DualKeyPayload</span> {'{'}</div>
                <div className="ml-4"><span className="text-[#9cdcfe]">v</span>: <span className="text-[#b5cea8]">1</span>;</div>
                <div className="ml-4"><span className="text-[#9cdcfe]">challengeId</span>: <span className="text-[#4ec9b0]">string</span>;</div>
                <div className="ml-4"><span className="text-[#9cdcfe]">secondFactorHash</span>: <span className="text-[#4ec9b0]">string</span>; <span className="text-[#6a9955]">// hex lowercase SHA-256</span></div>
                <div className="ml-4"><span className="text-[#9cdcfe]">userPublicKey</span>: <span className="text-[#4ec9b0]">JsonWebKey</span>; <span className="text-[#6a9955]">// EC P-256 public only (no d)</span></div>
                <div className="ml-4"><span className="text-[#9cdcfe]">userSignature</span>: <span className="text-[#4ec9b0]">string</span>; <span className="text-[#6a9955]">// base64url, no padding, raw P1363</span></div>
                <div className="ml-4"><span className="text-[#9cdcfe]">clientTs</span>?: <span className="text-[#4ec9b0]">string</span>; <span className="text-[#6a9955]">// optional, NOT signed</span></div>
                <div>{'}'}</div>
              </div>
              <p className="text-xs text-slate-500">Canonical Signed Message (UTF-8): <code>challengeId + ":" + secondFactorHash</code></p>
            </div>

            <div className="space-y-4 mt-6">
              <h3 className="text-md font-bold text-slate-800">4.2 Key 2 (NIZKP Range Proof)</h3>
              <ul className="text-sm text-slate-700 list-disc ml-5">
                <li><strong>Curve:</strong> NIST P-256 (<code>@noble/curves</code> implementation)</li>
                <li><strong>Commitment Scheme:</strong> Pedersen commitments.</li>
                <li><strong>Range Proof Scheme:</strong> B2 bit-decomposition (8-bit).</li>
                <li><strong>Proof Size:</strong> Exactly 1355 bytes.</li>
              </ul>
            </div>
          </section>

          <section id="security-properties" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">5</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">5. Security Properties — Honest Assessment</h2>
            </div>
            
            <div className="overflow-x-auto rounded-lg border border-slate-200">
              <table className="w-full text-sm text-left">
                <thead className="bg-slate-50 border-b border-slate-200">
                  <tr>
                    <th className="px-4 py-3 font-semibold text-slate-800 w-1/4">Property</th>
                    <th className="px-4 py-3 font-semibold text-slate-800 w-1/4">Status in Sandbox</th>
                    <th className="px-4 py-3 font-semibold text-slate-800">Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100 text-slate-600">
                  <tr>
                    <td className="px-4 py-3 font-mono text-xs text-slate-900">Zero-PII Transmission</td>
                    <td className="px-4 py-3"><span className="bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded text-xs font-bold uppercase">Verified</span></td>
                    <td className="px-4 py-3 text-xs">The server receives only public keys, hashes, signatures, and ZK proofs. No personal data is transmitted.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-mono text-xs text-slate-900">Server-Side Authorization</td>
                    <td className="px-4 py-3"><span className="bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded text-xs font-bold uppercase">Verified</span></td>
                    <td className="px-4 py-3 text-xs">Both Key 1 and Key 2 require explicit cryptographic verification by the server endpoints.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-mono text-xs text-slate-900">Fail-Closed Design</td>
                    <td className="px-4 py-3"><span className="bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded text-xs font-bold uppercase">Verified</span></td>
                    <td className="px-4 py-3 text-xs">The orchestrator terminates if Key 1 fails; invalid Key 1 payloads are caught (lab-validated via tamper test E6).</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-mono text-xs text-slate-900">Replay Protection</td>
                    <td className="px-4 py-3"><span className="bg-amber-100 text-amber-800 px-2 py-0.5 rounded text-xs font-bold uppercase">Partial</span></td>
                    <td className="px-4 py-3 text-xs"><code>challengeId</code> prevents basic replay, but comprehensive nonce management and expiration are scope for higher TRLs.</td>
                  </tr>
                  <tr>
                    <td className="px-4 py-3 font-mono text-xs text-slate-900">Hardware Security</td>
                    <td className="px-4 py-3"><span className="bg-slate-200 text-slate-600 px-2 py-0.5 rounded text-xs font-bold uppercase">Not Evidenced</span></td>
                    <td className="px-4 py-3 text-xs">Keys are currently stored in browser software (IndexedDB/CryptoKey). No secure enclave or HSM integration is present.</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </section>

          <section id="performance" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">6</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">6. Performance & Measurement</h2>
            </div>
            
            <p className="text-sm text-slate-700">Performance metrics are derived from the latest F4-class measurement campaign (N=30, 0 failures) running in the sandbox environment.</p>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mt-4">
              <div className="bg-white border border-slate-200 p-4 rounded shadow-sm">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">dualKey_ms</div>
                <div className="text-xl font-mono text-slate-800">~12 ms</div>
                <div className="text-[10px] text-slate-500 mt-1">Client Key 1 exec</div>
              </div>
              <div className="bg-white border border-slate-200 p-4 rounded shadow-sm">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">server_dual_key_verify_ms</div>
                <div className="text-xl font-mono text-slate-800">~6 ms</div>
                <div className="text-[10px] text-slate-500 mt-1">Server Key 1 verify</div>
              </div>
              <div className="bg-white border border-slate-200 p-4 rounded shadow-sm">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">prove_ms</div>
                <div className="text-xl font-mono text-slate-800">~285-300 ms</div>
                <div className="text-[10px] text-slate-500 mt-1">Client Key 2 (B2) prove</div>
              </div>
              <div className="bg-white border border-slate-200 p-4 rounded shadow-sm">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">verify_ms</div>
                <div className="text-xl font-mono text-slate-800">~350 / ~344 ms</div>
                <div className="text-[10px] text-slate-500 mt-1">Server Key 2 (B2) verify</div>
              </div>
              <div className="bg-white border border-slate-200 p-4 rounded shadow-sm">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">total_ms</div>
                <div className="text-xl font-mono text-blue-600 font-bold">~650-680 ms</div>
                <div className="text-[10px] text-slate-500 mt-1">Full End-to-End Orchestrated</div>
              </div>
              <div className="bg-white border border-slate-200 p-4 rounded shadow-sm">
                <div className="text-[10px] text-slate-500 font-bold uppercase tracking-wider mb-1">proofByteLength</div>
                <div className="text-xl font-mono text-slate-800">1355 B</div>
                <div className="text-[10px] text-slate-500 mt-1">Fixed size</div>
              </div>
            </div>
          </section>

          <section id="non-claims" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">7</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">7. Explicit Non-Claims & Limits</h2>
            </div>
            
            <div className="bg-rose-50 border-l-4 border-rose-500 p-4 rounded-r-lg">
              <h4 className="text-sm font-bold text-rose-900 mb-2">To maintain transparency and auditability, the project explicitly disclaims the following:</h4>
              <ul className="list-disc ml-5 text-sm text-rose-800 space-y-1">
                <li>We <strong>do not</strong> claim TRL 6 or 7.</li>
                <li>We <strong>do not</strong> claim full-path execution under 150ms.</li>
                <li>We <strong>do not</strong> claim implementation of product-legitimacy, fiscal-stamp, or EMCS validation logic.</li>
                <li>We <strong>do not</strong> claim production-ready integration with European digital identity infrastructure (eIDAS/EUDI). eIDAS-Node 3.1.0 is a reference architecture only; EUDI is a target only.</li>
                <li>We <strong>do not</strong> claim national-scale or POS production deployment readiness.</li>
              </ul>
            </div>
          </section>

          <section id="checklist" className="space-y-4 scroll-mt-24">
            <div className="flex items-center gap-2.5 border-b border-slate-100 pb-3">
              <span className="w-6 h-6 rounded bg-blue-100 text-blue-800 flex items-center justify-center font-mono text-xs font-bold">8</span>
              <h2 className="text-xl font-black text-slate-900 uppercase tracking-tight font-mono">8. Compliance Checklist</h2>
            </div>
            
            <div className="space-y-2">
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">Dual-Key orchestration enforces a fail-closed constraint.</span>
              </div>
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">Key 1 is server-verified via ECDSA P-256.</span>
              </div>
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">Key 2 is server-verified via B2 Range Proof (1355 bytes).</span>
              </div>
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">TRL 4 boundaries strictly observed.</span>
              </div>
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">Zero-PII transmission confirmed in payloads & no tracking/linkability across sessions.</span>
              </div>
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">eIDAS Constraint Pack v0.4 & ARF v3.0.0 rules enforced (LoA High, ISO 18013-5 / SD-JWT VC format compatibility, zero server retrieval).</span>
              </div>
              <div className="flex items-center gap-3 bg-white p-3 border border-slate-200 rounded">
                <CheckCircle2 size={18} className="text-emerald-500 flex-shrink-0" />
                <span className="text-sm text-slate-700">Performance baseline documented (N=30, ~650ms E2E).</span>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}