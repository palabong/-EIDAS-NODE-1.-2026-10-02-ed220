import React, { useState, useCallback } from 'react';
import { 
  Shield, 
  Key, 
  Cpu, 
  FileCheck, 
  Download, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  Lock, 
  AlertTriangle, 
  Store, 
  Clock,
  Sparkles,
  Smartphone,
  Check,
  UserCheck
} from 'lucide-react';
import { 
  runSwissDemonstration, 
  CITIZEN_PRESETS, 
  type CitizenPresetKey, 
  type CitizenIngestionProfile,
  type BilanxValidationEnvelope,
  type StepLogEntry
} from './lib/e2e/runSwissDemonstration.ts';
import { QrCodeSvg } from './components/QrCodeSvg.tsx';
import { generateAuditCertificatePdf } from './lib/PdfReceiptGenerator.ts';

interface SwissUnifiedPoCDemoProps {
  currentUser?: any;
}

export const SwissUnifiedPoCDemo: React.FC<SwissUnifiedPoCDemoProps> = ({ currentUser }) => {
  const [selectedPreset, setSelectedPreset] = useState<CitizenPresetKey>('swiss_adult');
  const [useHardwareBiometrics, setUseHardwareBiometrics] = useState<boolean>(false);
  const [productScanned, setProductScanned] = useState<string>('Swiss Appenzeller Alpine Spirits (18+ Restricted)');
  
  // Pipeline Execution State
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activeStep, setActiveStep] = useState<1 | 2 | 3 | 4>(1);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const [hwFingerprint, setHwFingerprint] = useState<string>('');
  const [envelope, setEnvelope] = useState<BilanxValidationEnvelope | null>(null);
  const [logs, setLogs] = useState<StepLogEntry[]>([]);
  const [validationStatus, setValidationStatus] = useState<'IDLE' | 'APPROVED' | 'REJECTED'>('IDLE');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [posScanned, setPosScanned] = useState<boolean>(false);

  const citizen: CitizenIngestionProfile = CITIZEN_PRESETS[selectedPreset] || {
    presetKey: 'custom_saml',
    fullName: currentUser?.name || 'Authenticated Citizen',
    dateOfBirth: '1992-05-14',
    age: 32,
    userId: currentUser?.uid || 'CHE-USER-CURRENT',
    nationality: 'Switzerland (CHE)',
    levelOfAssurance: 'high'
  };

  const handleReset = useCallback(() => {
    setIsRunning(false);
    setActiveStep(1);
    setCompletedSteps(new Set());
    setHwFingerprint('');
    setEnvelope(null);
    setLogs([]);
    setValidationStatus('IDLE');
    setErrorMessage(null);
    setPosScanned(false);
  }, []);

  const handleRunFullDemo = async () => {
    setIsRunning(true);
    setErrorMessage(null);
    setPosScanned(false);

    try {
      const result = await runSwissDemonstration({
        citizenPreset: selectedPreset,
        useHardwareBiometrics,
        productScanned
      });

      setLogs(result.logs);
      setHwFingerprint(result.hwFingerprint);
      setValidationStatus(result.validationStatus);

      if (result.success && result.envelope) {
        setEnvelope(result.envelope);
        setCompletedSteps(new Set([1, 2, 3, 4]));
        setActiveStep(4);
      } else {
        setErrorMessage(result.error || 'Demonstration halted due to validation failure.');
        setActiveStep(result.currentStep);
        const stepsDone = new Set<number>();
        for (let i = 1; i < result.currentStep; i++) stepsDone.add(i);
        setCompletedSteps(stepsDone);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Unexpected execution error.');
      setValidationStatus('REJECTED');
    } finally {
      setIsRunning(false);
    }
  };

  const handleDownloadPdf = () => {
    if (envelope) {
      generateAuditCertificatePdf(envelope, citizen);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8 font-sans">
      {/* 🇨🇭 Header Section */}
      <div className="bg-gradient-to-r from-slate-900 via-blue-950 to-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="text-2xl">🇨🇭</span>
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-red-600/20 text-red-400 border border-red-500/30 tracking-wide">
                SWISS TRUST INFRASTRUCTURE DEMONSTRATOR
              </span>
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-400 border border-blue-500/30">
                eIDAS 2.0 HIGH ASSURANCE
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Bilanx — Dual-Key Sovereign Validation System (DK-SVS)
            </h1>
            <p className="text-sm sm:text-base text-slate-400 mt-2 max-w-3xl leading-relaxed">
              Definitive proof-of-concept demonstrating genuine zero data-liability retail compliance: 
              merchants verify that citizens are statutory legal adults (18+) via a 1355-byte zero-knowledge range proof 
              and FIDO2 hardware enclave attestation without ever seeing, storing, or handling personal identity data.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleReset}
              disabled={isRunning}
              className="px-4 py-2.5 rounded-xl border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 font-medium text-sm transition-all flex items-center gap-2 shadow-sm disabled:opacity-50"
            >
              <RefreshCw className="w-4 h-4" />
              Reset Demo
            </button>
            <button
              onClick={handleRunFullDemo}
              disabled={isRunning}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold text-sm transition-all flex items-center gap-2 shadow-lg shadow-red-600/25 disabled:opacity-50"
            >
              {isRunning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Running Cryptographic Pipeline...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Run Sovereign E2E Demo
                </>
              )}
            </button>
          </div>
        </div>

        {/* 4-Step Interactive Stepper */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-8 pt-6 border-t border-slate-800/80">
          {[
            { step: 1, title: '1. Identity Ingestion', sub: 'Sovereign PII Quarantine', icon: UserCheck },
            { step: 2, title: '2. Enclave Attestation', sub: 'FIDO2 / Hardware Fingerprint', icon: Cpu },
            { step: 3, title: '3. Dual-Key & ZKP', sub: '1355B Sigma Range Proof', icon: Shield },
            { step: 4, title: '4. POS Envelope', sub: 'Zero Data-Liability Clearance', icon: Store }
          ].map(({ step, title, sub, icon: Icon }) => {
            const isCompleted = completedSteps.has(step);
            const isCurrent = activeStep === step && !isCompleted;
            const isRejected = validationStatus === 'REJECTED' && activeStep === step;

            return (
              <div
                key={step}
                className={`p-4 rounded-xl border transition-all ${
                  isRejected
                    ? 'bg-red-950/30 border-red-800/60 text-red-300'
                    : isCompleted
                    ? 'bg-emerald-950/20 border-emerald-800/50 text-emerald-300'
                    : isCurrent
                    ? 'bg-blue-950/40 border-blue-600 text-blue-200 ring-2 ring-blue-500/20'
                    : 'bg-slate-900/40 border-slate-800/60 text-slate-400 opacity-70'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Icon className="w-4 h-4" />
                    <span className="font-bold text-sm">{title}</span>
                  </div>
                  {isRejected ? (
                    <XCircle className="w-4 h-4 text-red-400" />
                  ) : isCompleted ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : isCurrent ? (
                    <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
                  ) : null}
                </div>
                <div className="text-xs text-slate-400">{sub}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Configuration & Citizen Selection Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
        <h2 className="text-lg font-bold text-white mb-4 flex items-center gap-2">
          <Lock className="w-5 h-5 text-blue-400" />
          Demonstration Control & Citizen Scenario Selection
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
              Citizen Profile Scenario
            </label>
            <select
              value={selectedPreset}
              onChange={(e) => {
                setSelectedPreset(e.target.value as CitizenPresetKey);
                handleReset();
              }}
              disabled={isRunning}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            >
              <option value="swiss_adult">🇨🇭 Heinrich Keller (Age 32 — Zurich, Adult PASS)</option>
              <option value="eu_adult">🇩🇪 Dr. Clara Schmidt (Age 37 — Berlin, Adult PASS)</option>
              <option value="minor_luca">⚠️ Luca Rossi (Age 17 — Ticino, Underage REJECT)</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
              Hardware Enclave Mode
            </label>
            <div className="flex items-center gap-3 h-10">
              <label className="inline-flex items-center gap-2 text-sm text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={useHardwareBiometrics}
                  onChange={(e) => setUseHardwareBiometrics(e.target.checked)}
                  disabled={isRunning}
                  className="rounded border-slate-700 bg-slate-800 text-blue-600 focus:ring-blue-500 w-4 h-4"
                />
                Require Physical Touch ID / Platform Biometrics
              </label>
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
              Restricted Retail Item at POS
            </label>
            <input
              type="text"
              value={productScanned}
              onChange={(e) => setProductScanned(e.target.value)}
              disabled={isRunning}
              className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
            />
          </div>
        </div>
      </div>

      {/* Main 4-Step Pipeline Body */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        
        {/* Left Column: Steps 1 & 2 */}
        <div className="space-y-6">
          {/* STEP 1: Sovereign PII Quarantine */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <UserCheck className="w-5 h-5 text-blue-400" />
                Step 1: Citizen Ingestion & Sovereign PII Quarantine
              </h3>
              <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
                0 BYTES LEAKAGE
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-3">
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">Citizen Full Name:</span>
                <span className="font-mono text-white flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-amber-400" />
                  {citizen.fullName}
                  <span className="text-[10px] bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">QUARANTINED</span>
                </span>
              </div>
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">Date of Birth:</span>
                <span className="font-mono text-white flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5 text-amber-400" />
                  {citizen.dateOfBirth}
                  <span className="text-[10px] bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">QUARANTINED</span>
                </span>
              </div>
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">eIDAS Citizen Identifier:</span>
                <span className="font-mono text-white">{citizen.userId}</span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-400">Verified Age (Mathematical Parameter x):</span>
                <span className={`font-mono font-bold ${citizen.age >= 18 ? 'text-emerald-400' : 'text-red-400'}`}>
                  {citizen.age} Years Old ({citizen.age >= 18 ? 'Adult' : 'Minor'})
                </span>
              </div>
            </div>

            <div className="mt-4 p-3 bg-blue-950/30 border border-blue-900/40 rounded-xl text-xs text-blue-300 flex items-start gap-2.5">
              <Shield className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
              <span>
                <strong>Sovereign Privacy Guarantee:</strong> Plaintext PII (Name, Date of Birth, National ID) is strictly quarantined inside the citizen's local device boundary. Only the zero-knowledge statement is proven downstream.
              </span>
            </div>
          </div>

          {/* STEP 2: Hardware Enclave Attestation */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Cpu className="w-5 h-5 text-indigo-400" />
                Step 2: Hardware Enclave Attestation (FIDO2 / WebAuthn)
              </h3>
              <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-indigo-950/40 text-indigo-400 border border-indigo-800/40">
                W3C LEVEL 2/3
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-3">
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">Authenticator Type:</span>
                <span className="font-mono text-slate-200">
                  {useHardwareBiometrics ? 'Apple Secure Enclave / Touch ID (Physical)' : 'Software Platform Enclave Simulator (FIDO2 L2)'}
                </span>
              </div>
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">Attestation Public Key:</span>
                <span className="font-mono text-slate-200">ECDSA P-256 (COSE Key Map -7)</span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-400">Derived Hardware Fingerprint:</span>
                <span className="font-mono font-bold text-indigo-400">
                  {hwFingerprint || (isRunning ? 'Computing SHA-256(credId || authData)...' : 'Pending Step 2')}
                </span>
              </div>
            </div>

            <div className="mt-4 p-3 bg-indigo-950/30 border border-indigo-900/40 rounded-xl text-xs text-indigo-300 flex items-start gap-2.5">
              <Key className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
              <span>
                <strong>Hardware Binding:</strong> Derives <code className="bg-indigo-900/50 px-1 py-0.5 rounded">HW_FINGERPRINT = SHA-256(credId || authData)</code>. 
                This cryptographic identifier serves as the authentic second factor for the institutional handshake.
              </span>
            </div>
          </div>
        </div>

        {/* Right Column: Steps 3 & 4 */}
        <div className="space-y-6">
          {/* STEP 3: Dual-Key & ZKP Age-Gate */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Shield className="w-5 h-5 text-emerald-400" />
                Step 3: Sovereign Dual-Key Handshake & ZKP Age-Gate
              </h3>
              <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-emerald-950/40 text-emerald-400 border border-emerald-800/40">
                1355 BYTES PROOF
              </span>
            </div>

            <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-3">
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">Institutional Challenge (Key 1):</span>
                <span className="font-mono text-xs text-slate-300">
                  {envelope?.cryptographicReceipt.dualKeyChallengeId || 'Fresh signed nonce with 60s TTL'}
                </span>
              </div>
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">User Enclave Second Factor (Key 2):</span>
                <span className="font-mono text-xs text-indigo-300">
                  {hwFingerprint ? `Bound to ${hwFingerprint}` : 'Pending Enclave Fingerprint'}
                </span>
              </div>
              <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                <span className="text-slate-400">NIZKP Cryptosystem:</span>
                <span className="font-mono text-sm text-emerald-400">Pedersen + B2 8-Bit Sigma Range</span>
              </div>
              <div className="flex justify-between items-center text-sm">
                <span className="text-slate-400">ZKP Verification Status:</span>
                <span className={`font-mono font-bold ${validationStatus === 'APPROVED' ? 'text-emerald-400' : validationStatus === 'REJECTED' ? 'text-red-400' : 'text-slate-400'}`}>
                  {validationStatus === 'APPROVED' ? '✅ VALID (x >= 18 ENFORCED)' : validationStatus === 'REJECTED' ? '❌ REJECTED (UNDERAGE / TAMPERED)' : 'Pending'}
                </span>
              </div>
            </div>

            {errorMessage && (
              <div className="mt-4 p-3 bg-red-950/40 border border-red-800/60 rounded-xl text-xs text-red-300 flex items-start gap-2.5">
                <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <strong className="block text-red-200">Validation Error:</strong>
                  {errorMessage}
                </div>
              </div>
            )}
          </div>

          {/* STEP 4: POS Validation Envelope & POS Simulator */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                <Store className="w-5 h-5 text-amber-400" />
                Step 4: POS Validation Envelope & Merchant Screen
              </h3>
              <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-amber-950/40 text-amber-400 border border-amber-800/40">
                VE-2026 CLEARANCE
              </span>
            </div>

            {envelope && validationStatus === 'APPROVED' ? (
              <div className="space-y-6">
                {/* QR Code and Envelope Summary */}
                <div className="flex flex-col sm:flex-row items-center gap-6 bg-slate-950/70 p-4 rounded-xl border border-slate-800">
                  <div className="shrink-0">
                    <QrCodeSvg value={envelope.qrPayload} size={150} />
                  </div>
                  <div className="space-y-2 text-xs w-full">
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Envelope ID:</span>
                      <span className="font-mono text-emerald-400 font-bold">{envelope.envelopeId}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Timestamp:</span>
                      <span className="font-mono text-slate-300">{new Date(envelope.timestamp).toLocaleTimeString()}</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Plaintext PII Transmitted:</span>
                      <span className="font-mono text-emerald-400 font-bold">0 BYTES</span>
                    </div>
                    <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                      <span className="text-slate-400">Compliance Rebate:</span>
                      <span className="font-mono text-blue-400 font-bold">CHF {envelope.merchantClearance.complianceRebateChf.toFixed(2)}</span>
                    </div>
                    <button
                      onClick={handleDownloadPdf}
                      className="mt-2 w-full py-2 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-blue-600/20"
                    >
                      <Download className="w-3.5 h-3.5" />
                      Download Official Swiss Audit Certificate (PDF)
                    </button>
                  </div>
                </div>

                {/* Simulated Point-of-Sale Terminal Screen */}
                <div className="bg-slate-950 border-2 border-slate-700 rounded-xl p-5 shadow-2xl relative">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                    <div className="flex items-center gap-2">
                      <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
                      <span className="text-xs font-mono font-bold text-slate-300">
                        SWISS RETAIL KIOSK POS TERMINAL #04
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-500">BILANX-POS-ONLINE</span>
                  </div>

                  {!posScanned ? (
                    <div className="text-center py-4 space-y-3">
                      <p className="text-xs text-slate-400">
                        Scan customer validation envelope QR code to authorize restricted sale:
                      </p>
                      <button
                        onClick={() => setPosScanned(true)}
                        className="py-2.5 px-6 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-emerald-600/20 transition-all flex items-center gap-2 mx-auto"
                      >
                        <Smartphone className="w-4 h-4" />
                        Scan Customer Envelope QR
                      </button>
                    </div>
                  ) : (
                    <div className="space-y-3 animate-fadeIn">
                      <div className="p-3 bg-emerald-950/60 border border-emerald-500/50 rounded-xl text-center">
                        <span className="text-sm font-extrabold text-emerald-400 flex items-center justify-center gap-2">
                          <Check className="w-4 h-4" />
                          🟢 18+ AGE VERIFIED — SALE AUTHORIZED
                        </span>
                      </div>
                      <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-300">
                        <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                          <span className="text-slate-500 block">Restricted Item:</span>
                          {envelope.merchantClearance.productScanned}
                        </div>
                        <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                          <span className="text-slate-500 block">PII Accessed by Merchant:</span>
                          <span className="text-emerald-400 font-bold">0 Bytes (Zero Retention)</span>
                        </div>
                        <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                          <span className="text-slate-500 block">Excise Tax Rebate:</span>
                          <span className="text-blue-400 font-bold">+ CHF 0.15 Credited</span>
                        </div>
                        <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                          <span className="text-slate-500 block">Legal Directive:</span>
                          <span>Swiss FADP / eIDAS 2.0</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-center py-10 bg-slate-950/40 border border-slate-800/60 rounded-xl text-slate-500 text-sm">
                Complete Steps 1–3 to generate the Zero Data-Liability POS Validation Envelope.
              </div>
            )}
          </div>
        </div>

      </div>

      {/* Real-time Cryptographic Audit Trail */}
      {logs.length > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
          <h3 className="text-base font-bold text-white mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5 text-blue-400" />
            Real-Time Cryptographic Execution Audit Trail
          </h3>

          <div className="space-y-3">
            {logs.map((log, idx) => (
              <div 
                key={idx}
                className="bg-slate-950/70 border border-slate-800 rounded-xl p-3.5 flex items-start justify-between text-xs font-mono"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${log.status === 'PASS' ? 'bg-emerald-400' : 'bg-red-400'}`} />
                    <span className="font-bold text-slate-200">Step {log.step}: {log.title}</span>
                  </div>
                  <p className="text-slate-400 pl-4">{log.details}</p>
                </div>
                <div className="text-right shrink-0 pl-4 text-slate-500">
                  <div>{log.durationMs} ms</div>
                  <div className="text-[10px]">{new Date(log.timestamp).toLocaleTimeString()}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default SwissUnifiedPoCDemo;
