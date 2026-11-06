import React from 'react';
import { Shield, Key, Cpu, FileCheck, Download, RefreshCw, CheckCircle2, XCircle, Lock, AlertTriangle, Store, Clock, Sparkles, Smartphone, Check, UserCheck, Usb, Fingerprint, Globe2, FileCode, Send, Copy, Server, Layers, FileText, ShieldCheck, Sliders, ArrowRight, ExternalLink, Eye, Link as LinkIcon, User, Radio, BookOpen } from 'lucide-react';
import { QrCodeSvg } from '../components/QrCodeSvg.tsx';
import { CITIZEN_PRESETS, type CitizenPresetKey } from '../lib/e2e/runSwissDemonstration.ts';

export function TrustPane(bag: Record<string, any>) {
  const {
    acsLoading,
    acsResult,
    activeTab,
    applyPresetVector,
    assertionsList,
    authenticatorMode,
    authnLoading,
    authnResult,
    copiedAuthnB64,
    copiedAuthnXml,
    copiedMetadata,
    copyToClipboard,
    customBoundCitizen,
    e2eResult,
    effectiveCitizen,
    envelope,
    errorMessage,
    fetchMetadata,
    handleAuthenticateWebAuthn,
    handleBindAcsToPilot,
    handleBindEnclaveToStep2,
    handleBindStoredAssertion,
    handleClearCustomBinding,
    handleDownloadPdf,
    handleGenerateAuthnRequest,
    handlePosScan,
    handleRegisterWebAuthnKey,
    handleReset,
    handleRunAcsValidation,
    hardwareAvailable,
    hwFingerprint,
    isE2eRunning,
    isRunning,
    jurisdiction,
    loa,
    logs,
    metadataLoading,
    metadataResult,
    posScanned,
    productScanned,
    profile,
    rfidList,
    selectedPreset,
    selectedPresetVector,
    selectedRfidItem,
    selectedRfidUid,
    setActiveTab,
    setAuthenticatorMode,
    setCopiedAuthnB64,
    setCopiedAuthnXml,
    setCopiedMetadata,
    setLoa,
    setProductScanned,
    setSelectedPreset,
    setSelectedRfidUid,
    setSpEntityId,
    spEntityId,
    validationStatus,
    webauthnCred,
    webauthnError,
    webauthnLoading,
    webauthnResult,
  } = bag;
  return (
    <>
      {/* =====================================================================
          VIEW 5: INSTITUTIONAL ASSERTIONS & EXPLANATORY REPORTS
         ===================================================================== */}
      {(activeTab === 'trust' || activeTab === 'unified') && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-blue-500/20 text-blue-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-blue-400/30">
                  Institutional Database
                </span>
                <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-emerald-400/30">
                  eIDAS 2.0 & RFID Assertions
                </span>
              </div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-blue-400" />
                Active Institutional Assertions & Explanatory Reports
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Cryptographically bound natural person assertions and physical UHF RFID supply-chain tracking assertions.
              </p>
            </div>
          </div>

          {/* eIDAS Assertions Section */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" /> Verified eIDAS Natural Person Assertions ({assertionsList.length})
            </h4>

            <div className="grid grid-cols-1 gap-3">
              {assertionsList.map((assertion) => (
                <div
                  key={assertion.id}
                  className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:border-slate-700 transition-all font-mono text-xs"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-white text-sm">{assertion.id}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        assertion.loa === 'high' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-blue-950 text-blue-300 border border-blue-800'
                      }`}>
                        LoA {assertion.loa.toUpperCase()}
                      </span>
                      <span className="bg-slate-800 text-slate-300 text-[10px] px-2 py-0.5 rounded">
                        {assertion.attributes.ageOver18 ? 'Adult 18+' : 'Minor'}
                      </span>
                    </div>
                    <div className="text-slate-400 text-[11px]">
                      Issuer: <span className="text-slate-300">{assertion.issuer}</span> | Subject: <span className="text-slate-300">{assertion.subjectId}</span>
                    </div>
                    <div className="text-slate-500 text-[10px]">
                      Txn: {assertion.transactionId} | Signature: {assertion.signature} | {new Date(assertion.timestamp).toLocaleString()}
                    </div>
                  </div>

                  <button
                    onClick={() => handleBindStoredAssertion(assertion)}
                    className="py-1.5 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-sans font-bold flex items-center gap-1.5 shrink-0 cursor-pointer shadow-md"
                  >
                    <LinkIcon className="w-3.5 h-3.5" />
                    <span>Bind to Pilot (Step 1)</span>
                  </button>
                </div>
              ))}
            </div>
          </div>

          {/* UHF RFID Assertions Section */}
          <div className="space-y-3 pt-4 border-t border-slate-800">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
              <Radio className="w-4 h-4 text-amber-400" /> Institutional UHF RFID Physical Product Assertions ({rfidList.length})
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {rfidList.map((rfid) => (
                <div
                  key={rfid.id}
                  className="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2 font-mono text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{rfid.productName}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                      rfid.status === 'authentic' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'
                    }`}>
                      {rfid.status}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Hardware UID: <span className="text-slate-300 font-bold">{rfid.hardwareUid}</span> ({rfid.category})
                  </div>
                  <div className="text-[10px] text-slate-500 break-all">
                    HMAC-SHA256: {rfid.hmacSha256}
                  </div>
                  <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 border-t border-slate-900">
                    <span>RSSI: {rfid.rssi} dBm | Tags: {rfid.tagsRead}</span>
                    <span className="text-emerald-400 font-bold">Excise Recovered: €{rfid.exciseRecovered.toFixed(2)}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          VIEW 6: HARDWARE SECURE ENCLAVE (TRL 5 WEBAUTHN)
         ===================================================================== */}
      {(activeTab === 'trust' || activeTab === 'unified') && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-emerald-400/30">
                  TRL 5 Hardware Enclave
                </span>
                <span className="bg-blue-500/20 text-blue-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-blue-400/30">
                  WebAuthn / FIDO2 Attestation
                </span>
              </div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-emerald-400" />
                Physical Device Hardware Enclave Key Binding & Verification
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Binds the natural person identity to physical hardware (Apple Secure Enclave, Touch ID, Windows Hello, YubiKey TPM) via standard WebAuthn APIs.
              </p>
            </div>

            <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
              hardwareAvailable 
                ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-300 font-bold' 
                : 'bg-amber-950/60 border-amber-500/50 text-amber-300 font-bold'
            }`}>
              <span className={`w-2 h-2 rounded-full ${hardwareAvailable ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'}`} />
              <span>{hardwareAvailable ? 'Hardware Authenticator Detected (Touch ID / TPM)' : 'Software Enclave Emulation Mode'}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Step 1: Register Hardware Key */}
            <div className="p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wider">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[10px]">1</span>
                <span>Register Hardware Enclave Key</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Triggers physical biometrics (Touch ID / Face ID) to generate an ECDSA P-256 public/private keypair inside the hardware Secure Enclave.
              </p>
              <button
                onClick={handleRegisterWebAuthnKey}
                disabled={webauthnLoading}
                className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-lg transition-all shadow-md flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {webauthnLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" /> Prompting Touch ID / Hardware...
                  </>
                ) : (
                  <>
                    <Fingerprint className="w-4 h-4" /> Trigger Secure Enclave Registration
                  </>
                )}
              </button>
            </div>

            {/* Step 2: Sign Challenge */}
            <div className="p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-200 uppercase tracking-wider">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[10px]">2</span>
                <span>Sign Challenge via Hardware Biometrics</span>
              </div>
              <p className="text-xs text-slate-400 leading-relaxed font-sans">
                Signs a server-issued challenge using the registered hardware private key inside the device enclave and verifies the assertion signature.
              </p>
              <button
                onClick={handleAuthenticateWebAuthn}
                disabled={webauthnLoading || !webauthnCred}
                className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-lg transition-all shadow-md flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {webauthnLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" /> Verifying Touch ID Signature...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" /> Sign & Verify Hardware Assertion
                  </>
                )}
              </button>
            </div>
          </div>

          {/* WebAuthn Result & Bind Button */}
          {webauthnResult && (
            <div className="p-4 bg-slate-950 border border-emerald-500/50 rounded-xl space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-400 font-bold">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>{webauthnResult.message}</span>
                </div>
                <button
                  onClick={handleBindEnclaveToStep2}
                  className="py-1.5 px-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-sans font-bold flex items-center gap-1.5 cursor-pointer shadow-md"
                >
                  <LinkIcon className="w-3.5 h-3.5" />
                  <span>Bind to Step 2 Enclave Attestation</span>
                </button>
              </div>

              <div className="text-[11px] text-slate-400">
                Credential ID: <span className="text-slate-200 font-bold">{webauthnResult.credentialId}</span>
              </div>
              {webauthnResult.signature && (
                <div className="text-[10px] text-slate-500 break-all">
                  Signature: {webauthnResult.signature}
                </div>
              )}
            </div>
          )}

          {webauthnError && (
            <div className="p-3 bg-red-950/40 border border-red-800/60 rounded-xl text-xs text-red-300 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{webauthnError}</span>
            </div>
          )}
        </div>
      )}
    </>
  );
}
