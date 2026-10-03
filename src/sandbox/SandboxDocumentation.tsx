import { FC } from 'react';

interface SandboxDocumentationProps {
  showDocumentation: boolean;
}

export const SandboxDocumentation: FC<SandboxDocumentationProps> = ({ showDocumentation }) => {
  if (!showDocumentation) return null;

  return (
    <section className="mb-8 p-6 bg-slate-50 border border-slate-200 rounded-lg shadow-sm text-sm text-slate-800">
      <div className="flex items-center justify-between mb-4 border-b border-slate-200 pb-3">
        <h2 className="text-lg font-semibold text-slate-900">Project Overview & Documentation</h2>
        <span className="text-[10px] font-bold tracking-wider px-2 py-0.5 rounded border uppercase text-indigo-700 bg-indigo-50 border-indigo-200">
          For Development & Partner Review
        </span>
      </div>
      
      <div className="space-y-5">
        <div>
          <h3 className="font-medium text-slate-900 mb-1">Project BILANX DK-SVS</h3>
          <p className="text-slate-600">
            A proof-of-concept environment focusing on privacy-preserving Point-of-Sale (POS) authentication and eIDAS integration. The primary goal is validating the frontend architecture's ability to handle high-volume, concurrent validation workflows without compromising interface responsiveness.
          </p>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div>
            <h3 className="font-medium text-slate-900 mb-1">Current State (Mocked)</h3>
            <ul className="list-disc pl-5 text-slate-600 space-y-1">
              <li><strong>eIDAS Validation:</strong> Simulated with 300-1200ms latency and ~5% failure rate. Occurs first.</li>
              <li><strong>Dual-Key Validation:</strong> Simulated asynchronous handshake. Occurs second.</li>
              <li><strong>Limitations:</strong> All validations are simulated (no real cryptography or eIDAS Node involved). 100% client-side memory based.</li>
            </ul>
          </div>

          <div>
            <h3 className="font-medium text-slate-900 mb-1">Architecture & Performance</h3>
            <ul className="list-disc pl-5 text-slate-600 space-y-1">
              <li>Built with <strong>React 19</strong> concurrent features (<code className="bg-slate-200 px-1 rounded text-slate-700">useTransition</code>, <code className="bg-slate-200 px-1 rounded text-slate-700">useFormStatus</code>).</li>
              <li>Optimized for <strong>Interaction to Next Paint (INP)</strong>. Keeps the main thread unblocked during massive data updates.</li>
              <li>Strict isolation strategy (everything lives under <code className="bg-slate-200 px-1 rounded text-slate-700">src/sandbox/</code>).</li>
            </ul>
          </div>
        </div>

        <div>
          <h3 className="font-medium text-slate-900 mb-1">Expectations from Hastega (Real eIDAS 3.1.0)</h3>
          <p className="text-slate-600">
            Integration of genuine eIDAS validation flows with clear separation between this performance sandbox and production-grade logic. Cryptographic operations and eIDAS Node communication must be handled securely on the backend. The frontend will orchestrate the asynchronous flow and display UI states, maintaining the established responsive React 19 patterns.
          </p>
        </div>
      </div>
    </section>
  );
};
