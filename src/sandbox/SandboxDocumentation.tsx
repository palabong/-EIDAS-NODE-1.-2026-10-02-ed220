import { FC } from 'react';

interface SandboxDocumentationProps {
  showDocumentation: boolean;
}

export const SandboxDocumentation: FC<SandboxDocumentationProps> = ({ showDocumentation }) => {
  if (!showDocumentation) return null;

  return (
    <section className="mb-8 p-6 bg-slate-50 border border-slate-200 rounded-lg shadow-sm text-sm text-slate-800">
      <div className="flex items-center justify-between mb-4 border-b border-slate-200 pb-3">
        <h2 className="text-lg font-semibold text-slate-900">Project Overview & Architecture Documentation</h2>
        <span className="text-[10px] font-bold tracking-wider px-2 py-0.5 rounded border uppercase text-emerald-700 bg-emerald-50 border-emerald-200">
          TRL 6 Operational Pilot Status
        </span>
      </div>
      
      <div className="space-y-5">
        <div>
          <h3 className="font-medium text-slate-900 mb-1">Project BILANX DK-SVS & eIDAS 2.0 Sovereign Architecture</h3>
          <p className="text-slate-600">
            An operational pilot environment for privacy-preserving Point-of-Sale (POS) authentication, hardware-bound CTAP2 credentials, and authentic eIDAS 2.0 integration. The system enforces zero PII transmission at checkout while guaranteeing strict regulatory compliance (Swiss FADP / Italian AgCom Resolution 9/24/CONS).
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div>
            <h3 className="font-medium text-slate-900 mb-1">Cryptographic & Regulatory Pipeline (Production-Adjacent)</h3>
            <ul className="list-disc pl-5 text-slate-600 space-y-1">
              <li><strong>eIDAS 2.0 SAML Engine:</strong> Full SAML SP with Python validation engine supporting RSA-SHA256, ECDSA P-256, anti-replay, and XSW protection.</li>
              <li><strong>Dual-Key Sovereign Validation:</strong> Key 1 ECDSA P-256 hardware/institutional binding and Key 2 certified 1,355-byte NIST P-256 B2 Sigma range proof (sub-1.5s POS envelope).</li>
              <li><strong>Roaming Hardware Enclave:</strong> W3C WebAuthn Level 2/3 and CTAP2 YubiKey 5 Series attestation with anti-cloning counter verification.</li>
            </ul>
          </div>

          <div>
            <h3 className="font-medium text-slate-900 mb-1">Architecture & Performance Invariants</h3>
            <ul className="list-disc pl-5 text-slate-600 space-y-1">
              <li>Built with <strong>React 19</strong> concurrent features (<code className="bg-slate-200 px-1 rounded text-slate-700">useTransition</code>, <code className="bg-slate-200 px-1 rounded text-slate-700">useActionState</code>).</li>
              <li>Optimized for <strong>Interaction to Next Paint (INP)</strong>, maintaining high-frame-rate UI during heavy cryptographic operations.</li>
              <li><strong>Zero PII Transmission:</strong> Strict plaintext PII quarantine guaranteeing 0 bytes server leakage and zero GDPR/FADP data liability.</li>
            </ul>
          </div>
        </div>

        <div>
          <h3 className="font-medium text-slate-900 mb-1">Interoperability & Standards Compliance</h3>
          <p className="text-slate-600">
            Full compliance with European Union eIDAS 2.0 architecture and reference frameworks (ARF), Italian AgCom Delibera 9/24/CONS LoA High mandates, and Swiss Federal Act on Data Protection (FADP) retail POS age-verification standards.
          </p>
        </div>
      </div>
    </section>
  );
};
