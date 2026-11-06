/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { FileText, Download, Loader2, CheckCircle2 } from 'lucide-react';
import { SandboxDossier } from '../sandbox/SandboxDossier';
import { generateDkSvsTechnicalPositionPaperPdf } from '../sandbox/lib/generateDkSvsPdf';

/**
 * DocumentationMode
 * 
 * Institutional regulatory documentation and DK-SVS Technical Position Paper.
 * Merges high-level directive summaries with the comprehensive SandboxDossier.
 */
export default function DocumentationMode() {
  const [isGeneratingPDF, setIsGeneratingPDF] = useState(false);
  const [downloadPDFSuccess, setDownloadPDFSuccess] = useState(false);

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
    <div className="space-y-8 max-w-5xl mx-auto font-sans pb-12 animate-fadeIn">
      {/* 🏛️ INSTITUTIONAL DIRECTIVE HEADER */}
      <div className="bg-[#0e1424] border border-slate-800 rounded p-8 md:p-12 relative overflow-hidden shadow-md">
        <div className="absolute top-0 right-0 p-8 opacity-10">
          <FileText size={160} />
        </div>
        <div className="flex flex-wrap items-center gap-2 mb-6 relative z-10">
          <span className="bg-blue-900 text-blue-300 px-3 py-1 text-[10px] font-mono font-bold uppercase tracking-wider rounded border border-blue-700">
            Directive SWD(2026) 111
          </span>
          <span className="bg-slate-900 text-slate-400 px-3 py-1 text-[10px] font-mono tracking-wider rounded border border-slate-800">
            Public Reference Documentation
          </span>
          <span className="bg-emerald-950 text-emerald-400 px-3 py-1 text-[10px] font-mono font-bold tracking-wider rounded border border-emerald-900">
            GDPR COMPLIANT STATUS: SECURED
          </span>
        </div>
        <h1 className="text-3xl md:text-4xl font-black text-white uppercase tracking-tight font-mono mb-4 relative z-10">
          Sovereign Data Privacy Framework
        </h1>
        <p className="text-sm text-slate-400 leading-relaxed max-w-3xl relative z-10">
          Statutory guidelines detailing the cryptographic collection, processing, and protection of transactions within the Dual-Key Sovereign Validation System (DK-SVS). This framework establishes unquestionable compliance with GDPR and sets the standard for frictionless, anonymous distance transactions.
        </p>

        {/* 📥 PDF DOWNLOAD COMPONENT */}
        <div className="mt-8 flex flex-wrap gap-3 relative z-10">
          <button
            onClick={handleDownloadPDF}
            disabled={isGeneratingPDF}
            className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-75 disabled:cursor-not-allowed text-white rounded font-bold text-xs uppercase tracking-wider transition-all inline-flex items-center gap-2 shadow-lg cursor-pointer"
          >
            {isGeneratingPDF ? (
              <Loader2 size={14} className="animate-spin text-white" />
            ) : downloadPDFSuccess ? (
              <CheckCircle2 size={14} className="text-emerald-400" />
            ) : (
              <Download size={14} />
            )}
            {isGeneratingPDF ? 'Generating Technical Position Paper PDF...' : downloadPDFSuccess ? 'Technical Position Paper Downloaded!' : 'Download Technical Position Paper (PDF)'}
          </button>
        </div>
      </div>

      {/* Comprehensive Technical Position Paper & Dossier */}
      <SandboxDossier />
    </div>
  );
}
