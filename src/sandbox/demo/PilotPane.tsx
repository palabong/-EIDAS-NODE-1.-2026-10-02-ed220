import React from 'react';
import { Shield, Key, Cpu, FileCheck, Download, RefreshCw, CheckCircle2, XCircle, Lock, AlertTriangle, Store, Clock, Sparkles, Smartphone, Check, UserCheck, Usb, Fingerprint, Globe2, FileCode, Send, Copy, Server, Layers, FileText, ShieldCheck, Sliders, ArrowRight, ExternalLink, Eye, Link as LinkIcon, User, Radio, BookOpen } from 'lucide-react';
import { QrCodeSvg } from '../components/QrCodeSvg.tsx';
import { CITIZEN_PRESETS, type CitizenPresetKey } from '../lib/e2e/runSwissDemonstration.ts';

export function PilotPane(bag: Record<string, any>) {
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
      {(activeTab === 'pilot' || activeTab === 'unified') && (
        <div className="space-y-8">
          
          {/* Configuration & Citizen Selection Bar */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Lock className="w-5 h-5 text-blue-400" />
                Demonstration Control & Policy Configuration ({profile.shortLabel})
              </h2>
              {customBoundCitizen && (
                <span className="bg-emerald-950/60 text-emerald-400 border border-emerald-500/40 px-3 py-1 rounded-full text-xs font-mono font-bold flex items-center gap-1.5">
                  <LinkIcon className="w-3.5 h-3.5" />
                  Bound SAML Assertion Active
                </span>
              )}
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
                  Citizen Profile Scenario ({jurisdiction === 'CH' ? 'Swiss' : 'Italian'} Jurisdiction)
                </label>
                {customBoundCitizen ? (
                  <div className="bg-slate-800 border border-emerald-500/50 rounded-xl p-2.5 text-xs text-white flex items-center justify-between">
                    <div>
                      <div className="font-bold text-emerald-300">{customBoundCitizen.fullName}</div>
                      <div className="text-[10px] text-slate-400 font-mono">Age: {customBoundCitizen.age} | LoA: {customBoundCitizen.levelOfAssurance.toUpperCase()}</div>
                    </div>
                    <button
                      onClick={handleClearCustomBinding}
                      className="text-[10px] bg-slate-700 hover:bg-slate-600 text-slate-200 px-2 py-1 rounded cursor-pointer"
                    >
                      Clear
                    </button>
                  </div>
                ) : (
                  <select
                    id="select-citizen-scenario"
                    value={selectedPreset}
                    onChange={(e) => {
                      setSelectedPreset(e.target.value as CitizenPresetKey);
                      handleReset();
                    }}
                    disabled={isRunning}
                    className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                  >
                    {jurisdiction === 'CH' ? (
                      <>
                        <option value="swiss_adult">🇨🇭 Heinrich Keller (Age 32 — Zurich, Substantial LoA, Adult PASS)</option>
                        <option value="eu_adult">🇩🇪 Dr. Clara Schmidt (Age 37 — Berlin, High LoA, Adult PASS)</option>
                        <option value="minor_luca">⚠️ Luca Rossi (Age 17 — Ticino, Underage REJECT)</option>
                      </>
                    ) : (
                      <>
                        <option value="it_adult_high">🇮🇹 Marco Rossi (Age 35 — Roma, CIE / SPID High LoA, Adult PASS)</option>
                        <option value="it_adult_substantial">⚠️ Giulia Bianchi (Age 28 — Milano, SPID L2 Substantial, LoA High Check)</option>
                        <option value="it_minor_matteo">⚠️ Matteo Russo (Age 16 — Napoli, Underage REJECT)</option>
                      </>
                    )}
                  </select>
                )}
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
                  Hardware Security Token Mode
                </label>
                <select
                  id="select-authenticator-mode"
                  value={authenticatorMode}
                  onChange={(e) => {
                    setAuthenticatorMode(e.target.value as any);
                    handleReset();
                  }}
                  disabled={isRunning}
                  className="w-full bg-slate-800 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
                >
                  <option value="simulator">Software Enclave Simulator (FIDO2 L2 Headless)</option>
                  <option value="yubikey_ctap2">🔑 YubiKey 5 Series (CTAP2 Cross-Platform Token)</option>
                  <option value="platform_biometrics">Touch ID / Apple Secure Enclave (Physical Browser)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-400 mb-2 uppercase tracking-wider">
                  Regulated Service / Product at Verification Gate
                </label>
                <input
                  id="input-restricted-product"
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
            
            {/* Left Column: Step 0, Step 1 & Step 2 */}
            <div className="space-y-6">
              {/* STEP 0: Physical Item Scan & RFID Check */}
              <div 
                id="step-0-rfid-panel"
                className={`bg-slate-900 border rounded-2xl p-6 shadow-xl transition-all ${
                  selectedRfidItem.status === 'counterfeit'
                    ? 'border-red-800/80 shadow-red-950/20'
                    : selectedRfidItem.status === 'recalled'
                    ? 'border-amber-800/80 shadow-amber-950/20'
                    : 'border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Radio className="w-5 h-5 text-amber-400" />
                    Step 0: Physical Item Scan & RFID Check
                  </h3>
                  <span className={`px-2.5 py-1 rounded-md text-xs font-mono font-bold uppercase tracking-wider ${
                    selectedRfidItem.status === 'authentic'
                      ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60'
                      : selectedRfidItem.status === 'counterfeit'
                      ? 'bg-red-950/80 text-red-400 border border-red-700'
                      : 'bg-amber-950/80 text-amber-400 border border-amber-700'
                  }`}>
                    {selectedRfidItem.status === 'authentic'
                      ? '[OK / AUTHENTIC]'
                      : selectedRfidItem.status === 'counterfeit'
                      ? '[STOCK POLICY BLOCK: COUNTERFEIT DETECTED]'
                      : '[STOCK POLICY BLOCK: RECALLED STOCK]'}
                  </span>
                </div>

                {/* UHF RFID Catalog Live Selection */}
                <div className="space-y-3 mb-4">
                  <div className="flex items-center justify-between">
                    <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider">
                      UHF RFID Product Selection (Live Catalog Scan)
                    </label>
                    <span className="text-[10px] text-slate-500 font-mono">
                      Institutional RFID SVS Consortium
                    </span>
                  </div>

                  <select
                    id="select-uhf-rfid-catalog"
                    value={selectedRfidUid}
                    onChange={(e) => {
                      setSelectedRfidUid(e.target.value);
                      handleReset();
                    }}
                    disabled={isRunning}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:ring-2 focus:ring-amber-500 disabled:opacity-50 font-sans"
                  >
                    {rfidList.map((item) => (
                      <option key={item.hardwareUid} value={item.hardwareUid}>
                        {item.productName} — {item.hardwareUid} ({item.status.toUpperCase()}, €{item.exciseRecovered.toFixed(2)} excise)
                      </option>
                    ))}
                  </select>

                  {/* Interactive Quick-Select Buttons */}
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    {rfidList.map((item) => {
                      const isSelected = item.hardwareUid === selectedRfidUid;
                      const isAuth = item.status === 'authentic';
                      const isFake = item.status === 'counterfeit';
                      return (
                        <button
                          key={item.hardwareUid}
                          type="button"
                          onClick={() => {
                            setSelectedRfidUid(item.hardwareUid);
                            handleReset();
                          }}
                          disabled={isRunning}
                          className={`p-2.5 rounded-xl border text-left transition-all cursor-pointer ${
                            isSelected
                              ? isAuth
                                ? 'bg-emerald-950/40 border-emerald-500 text-white ring-1 ring-emerald-500/30'
                                : isFake
                                ? 'bg-red-950/60 border-red-500 text-white ring-1 ring-red-500/40'
                                : 'bg-amber-950/50 border-amber-500 text-white ring-1 ring-amber-500/40'
                              : 'bg-slate-950/60 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
                          }`}
                        >
                          <div className="flex items-center justify-between">
                            <span className="text-[11px] font-bold truncate max-w-[130px]">{item.productName}</span>
                            <span className={`text-[9px] font-mono px-1 py-0.5 rounded font-bold uppercase ${
                              isAuth ? 'bg-emerald-900/60 text-emerald-300' : isFake ? 'bg-red-900/60 text-red-300' : 'bg-amber-900/60 text-amber-300'
                            }`}>
                              {item.status}
                            </span>
                          </div>
                          <div className="text-[10px] font-mono text-slate-500 mt-1">
                            {item.hardwareUid} • €{item.exciseRecovered.toFixed(2)}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Real-Time UHF RFID Telemetry Grid */}
                <div className="bg-slate-950/80 border border-slate-800/90 rounded-xl p-4 space-y-2.5 text-xs font-mono">
                  <div className="flex justify-between items-center border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400">Hardware UID:</span>
                    <span className="font-bold text-white flex items-center gap-2">
                      <span className="text-amber-400">{selectedRfidItem.hardwareUid}</span>
                      <span className="text-[10px] text-slate-300 bg-slate-800 px-1.5 py-0.5 rounded font-sans">
                        {selectedRfidItem.category}
                      </span>
                    </span>
                  </div>

                  <div className="flex justify-between items-center border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400">RSSI Signal:</span>
                    <span className="text-slate-200 flex items-center gap-2">
                      <span className={selectedRfidItem.rssi > -35 ? 'text-emerald-400 font-bold' : 'text-amber-400 font-bold'}>
                        {selectedRfidItem.rssi} dBm
                      </span>
                      <span className="text-slate-600">|</span>
                      <span>Tag Count: {selectedRfidItem.tagsRead} tags ({selectedRfidItem.collisions} collisions)</span>
                    </span>
                  </div>

                  <div className="flex justify-between items-center border-b border-slate-800/80 pb-2">
                    <span className="text-slate-400">Manufacturer Signature:</span>
                    <div className="flex items-center gap-2">
                      <span className={selectedRfidItem.signature.startsWith('SIG-ECDSA-') ? 'text-emerald-400 font-bold' : 'text-red-400 font-bold'}>
                        {selectedRfidItem.signature}
                      </span>
                      <span className={`text-[9px] font-sans px-1.5 py-0.5 rounded font-bold uppercase ${
                        selectedRfidItem.signature.startsWith('SIG-ECDSA-')
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : 'bg-red-950 text-red-400 border border-red-800'
                      }`}>
                        {selectedRfidItem.signature.startsWith('SIG-ECDSA-') ? 'SIG-ECDSA-VALID' : 'SIG-UNKNOWN-OR-REVOKED'}
                      </span>
                    </div>
                  </div>

                  <div className="flex justify-between items-center pt-0.5">
                    <span className="text-slate-400">Excise Duty Recovery:</span>
                    <span className={`font-bold text-sm ${
                      selectedRfidItem.exciseRecovered > 0 ? 'text-emerald-400' : 'text-red-400'
                    }`}>
                      €{selectedRfidItem.exciseRecovered.toFixed(2)} {selectedRfidItem.exciseRecovered > 0 ? '(100% Settled)' : '(Zeroed / €0.00)'}
                    </span>
                  </div>
                </div>

                {/* Stock Policy Gate Enforcement Feedback Banner */}
                <div className="mt-4">
                  {selectedRfidItem.status === 'authentic' ? (
                    <div className="p-3.5 bg-emerald-950/40 border border-emerald-500/40 rounded-xl text-xs text-emerald-200 flex items-start gap-2.5">
                      <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="block text-emerald-300 font-bold uppercase tracking-wider">
                          [OK / AUTHENTIC] — Stock Policy Cleared
                        </strong>
                        <p className="text-[11px] text-emerald-200/90 mt-0.5">
                          Manufacturer ECDSA signature validated on consortium ledger. Item verified authentic. Proceeding smoothly to customer age-gate validation with full excise duty recovery settled (€{selectedRfidItem.exciseRecovered.toFixed(2)}).
                        </p>
                      </div>
                    </div>
                  ) : selectedRfidItem.status === 'counterfeit' ? (
                    <div id="counterfeit-stock-alert" className="p-3.5 bg-red-950/60 border border-red-500/80 rounded-xl text-xs text-red-200 flex items-start gap-2.5 animate-fadeIn">
                      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="block text-red-300 font-bold uppercase tracking-wider">
                          [STOCK POLICY BLOCK: COUNTERFEIT DETECTED]
                        </strong>
                        <p className="text-[11px] text-red-200/90 mt-0.5">
                          Counterfeit physical serial detected ({selectedRfidItem.hardwareUid}). Manufacturer signature is unverified or revoked ({selectedRfidItem.signature}). Transaction outcome set to <span className="font-mono font-bold text-red-100">REJECTED_COUNTERFEIT</span>, excise recovery zeroed (€0.00), and checkout blocked.
                        </p>
                      </div>
                    </div>
                  ) : (
                    <div id="recalled-stock-alert" className="p-3.5 bg-amber-950/60 border border-amber-500/80 rounded-xl text-xs text-amber-200 flex items-start gap-2.5 animate-fadeIn">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="block text-amber-300 font-bold uppercase tracking-wider">
                          [STOCK POLICY BLOCK: RECALLED STOCK]
                        </strong>
                        <p className="text-[11px] text-amber-200/90 mt-0.5">
                          Hardware serial {selectedRfidItem.hardwareUid} flagged on institutional safety recall registry. Checkout halted by stock policy gate. Excise recovery zeroed (€0.00).
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* STEP 1: Sovereign PII Quarantine & SAML Binding */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <UserCheck className="w-5 h-5 text-blue-400" />
                    Step 1: Identity Ingestion & Sovereign PII Quarantine
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
                      {effectiveCitizen.fullName}
                      <span className="text-[10px] bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">QUARANTINED</span>
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">Date of Birth:</span>
                    <span className="font-mono text-white flex items-center gap-2">
                      <Lock className="w-3.5 h-3.5 text-amber-400" />
                      {effectiveCitizen.dateOfBirth}
                      <span className="text-[10px] bg-amber-500/20 text-amber-400 px-1.5 py-0.5 rounded">QUARANTINED</span>
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">eIDAS Citizen Identifier:</span>
                    <span className="font-mono text-white">{effectiveCitizen.userId}</span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">Level of Assurance (LoA):</span>
                    <span className={`font-mono font-bold ${effectiveCitizen.levelOfAssurance === 'high' ? 'text-emerald-400' : 'text-blue-400'}`}>
                      {effectiveCitizen.levelOfAssurance.toUpperCase()} {jurisdiction === 'IT' && effectiveCitizen.levelOfAssurance !== 'high' && '(Requires High)'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">Verified Age (Parameter x):</span>
                    <span className={`font-mono font-bold ${effectiveCitizen.age >= 18 ? 'text-emerald-400' : 'text-red-400'}`}>
                      {effectiveCitizen.age} Years Old ({effectiveCitizen.age >= 18 ? 'Adult' : 'Minor'})
                    </span>
                  </div>
                </div>

                {/* Explanatory SAML Bridge Link */}
                <div className="mt-4 p-3 bg-blue-950/40 border border-blue-900/60 rounded-xl text-xs space-y-2">
                  <div className="flex items-center justify-between text-blue-300 font-bold">
                    <span className="flex items-center gap-1.5">
                      <LinkIcon className="w-3.5 h-3.5 text-blue-400" />
                      eIDAS SAML 2.0 Ingestion Bridge:
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">GET /saml/metadata</span>
                  </div>
                  <p className="text-[11px] text-slate-300">
                    Identity attributes originate from cross-border SAML 2.0 assertions. Quarantined on citizen device boundary before Step 3 ZKP evaluation.
                  </p>
                  <div className="flex gap-2 pt-1">
                    <button
                      onClick={() => setActiveTab('protocols')}
                      className="px-2.5 py-1 bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 rounded text-[10px] font-bold border border-blue-500/30 cursor-pointer flex items-center gap-1"
                    >
                      <Send className="w-3 h-3" /> Inspect AuthnRequest
                    </button>
                    <button
                      onClick={() => setActiveTab('protocols')}
                      className="px-2.5 py-1 bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 rounded text-[10px] font-bold border border-blue-500/30 cursor-pointer flex items-center gap-1"
                    >
                      <Key className="w-3 h-3" /> Test ACS Vectors
                    </button>
                    <button
                      onClick={() => setActiveTab('protocols')}
                      className="px-2.5 py-1 bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 rounded text-[10px] font-bold border border-blue-500/30 cursor-pointer flex items-center gap-1"
                    >
                      <FileCode className="w-3 h-3" /> View SP Metadata
                    </button>
                  </div>
                </div>
              </div>

              {/* STEP 2: Hardware Enclave & Token Attestation */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Cpu className="w-5 h-5 text-indigo-400" />
                    Step 2: Hardware Security Key & Token Attestation
                  </h3>
                  <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-indigo-950/40 text-indigo-400 border border-indigo-800/40">
                    {authenticatorMode === 'yubikey_ctap2' ? 'CTAP2 ROAMING' : 'W3C LEVEL 2/3'}
                  </span>
                </div>

                <div className="bg-slate-950/70 border border-slate-800/80 rounded-xl p-4 space-y-3">
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">Authenticator Type:</span>
                    <span className="font-mono text-slate-200">
                      {authenticatorMode === 'yubikey_ctap2' ? 'YubiKey 5 Series (CTAP2 Cross-Platform)' : authenticatorMode === 'platform_biometrics' ? 'Apple Secure Enclave / Touch ID (Physical)' : 'Software Platform Enclave Simulator (FIDO2 L2)'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">Attestation Public Key:</span>
                    <span className="font-mono text-slate-200">ECDSA P-256 (COSE Key Map ES256)</span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">Derived Hardware Fingerprint:</span>
                    <span className="font-mono font-bold text-indigo-400">
                      {hwFingerprint || (isRunning ? 'Computing SHA-256(credId || authData)...' : 'Pending Step 2')}
                    </span>
                  </div>
                </div>

                <div className="mt-4 p-3 bg-indigo-950/30 border border-indigo-900/40 rounded-xl text-xs text-indigo-300 flex items-start justify-between gap-2.5">
                  <div className="flex items-start gap-2.5">
                    <Key className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                    <span>
                      <strong>Hardware Binding:</strong> Derives <code className="bg-indigo-900/50 px-1 py-0.5 rounded">HW_FINGERPRINT = SHA-256(credId || authData)</code>.
                    </span>
                  </div>
                  <button
                    onClick={() => setActiveTab('trust')}
                    className="px-2 py-1 bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-200 rounded text-[10px] font-bold border border-indigo-500/30 shrink-0 cursor-pointer"
                  >
                    Test Enclave (TRL 5)
                  </button>
                </div>
              </div>
            </div>

            {/* Right Column: Steps 3 & 4 */}
            <div className="space-y-6">
              {/* STEP 3: Dual-Key Handshake & ZKP Age-Gate */}
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
                    <span className="text-slate-400">Institutional Node ({profile.jurisdictionCode}):</span>
                    <span className="font-mono text-xs text-slate-300">
                      {profile.institutionId}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">Institutional Challenge (Key 1):</span>
                    <span className="font-mono text-xs text-slate-300">
                      {envelope?.cryptographicReceipt.dualKeyChallengeId || 'Fresh signed nonce with 60s TTL'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">User Hardware Factor (Key 2):</span>
                    <span className="font-mono text-xs text-indigo-300">
                      {hwFingerprint ? `Bound to ${hwFingerprint}` : 'Pending Hardware Fingerprint'}
                    </span>
                  </div>
                  <div className="flex justify-between items-center text-sm border-b border-slate-800 pb-2">
                    <span className="text-slate-400">NIZKP Cryptosystem:</span>
                    <span className="font-mono text-sm text-emerald-400">Pedersen + B2 8-Bit Sigma Range (NIST P-256)</span>
                  </div>
                  <div className="flex justify-between items-center text-sm">
                    <span className="text-slate-400">Policy Verification Status:</span>
                    <span className={`font-mono font-bold ${validationStatus === 'APPROVED' ? 'text-emerald-400' : validationStatus.startsWith('REJECTED') ? 'text-red-400' : 'text-slate-400'}`}>
                      {validationStatus === 'APPROVED' 
                        ? '✅ VALID (x >= 18 ENFORCED)' 
                        : validationStatus === 'REJECTED_COUNTERFEIT'
                        ? '❌ REJECTED_COUNTERFEIT (STOCK POLICY VIOLATION)'
                        : validationStatus === 'REJECTED' 
                        ? '❌ REJECTED (POLICY / AGE VIOLATION)' 
                        : 'Pending'}
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

              {/* STEP 4: POS Validation Envelope & Terminal Screen */}
              <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    <Store className="w-5 h-5 text-amber-400" />
                    Step 4: Clearance Envelope & Point-of-Sale Terminal
                  </h3>
                  <span className="px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-amber-950/40 text-amber-400 border border-amber-800/40">
                    {jurisdiction === 'IT' ? 'AGCOM VERIFIED' : 'VE-2026 CLEARANCE'}
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
                          <span className="text-slate-400">Jurisdiction Profile:</span>
                          <span className="font-mono text-slate-200">{profile.shortLabel}</span>
                        </div>
                        <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                          <span className="text-slate-400">Product Authenticity:</span>
                          <span className="font-mono text-emerald-400 font-bold">
                            {envelope.merchantClearance.productAuthenticity || '[OK / AUTHENTIC]'}
                          </span>
                        </div>
                        <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                          <span className="text-slate-400">Plaintext PII Transmitted:</span>
                          <span className="font-mono text-emerald-400 font-bold">0 BYTES</span>
                        </div>
                        <div className="flex justify-between border-b border-slate-800/80 pb-1.5">
                          <span className="text-slate-400">Compliance Credit:</span>
                          <span className="font-mono text-blue-400 font-bold">
                            {profile.complianceCredit.currency} {profile.complianceCredit.amount.toFixed(2)} ({profile.complianceCredit.label})
                          </span>
                        </div>
                        <button
                          id="btn-download-pdf-receipt"
                          onClick={handleDownloadPdf}
                          className="mt-2 w-full py-2 px-3 bg-blue-600 hover:bg-blue-500 text-white rounded-lg font-bold text-xs flex items-center justify-center gap-2 transition-all shadow-md shadow-blue-600/20 cursor-pointer"
                        >
                          <Download className="w-3.5 h-3.5" />
                          Download {profile.jurisdictionCode === 'CH' ? 'Swiss' : 'Italian'} Official Audit Certificate (PDF)
                        </button>
                      </div>
                    </div>

                    {/* Simulated Point-of-Sale Terminal Screen */}
                    <div className="bg-slate-950 border-2 border-slate-700 rounded-xl p-5 shadow-2xl relative">
                      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
                        <div className="flex items-center gap-2">
                          <div className="w-3 h-3 rounded-full bg-emerald-500 animate-pulse" />
                          <span className="text-xs font-mono font-bold text-slate-300">
                            {jurisdiction === 'IT' ? 'AGCOM VERIFIED TERMINAL #02 (ROMA)' : 'SWISS RETAIL KIOSK POS TERMINAL #04'}
                          </span>
                        </div>
                        <span className="text-[11px] font-mono text-slate-500">BILANX-ONLINE</span>
                      </div>

                      {!posScanned && !isE2eRunning && (
                        <div className="text-center py-4 space-y-3">
                          <p className="text-xs text-slate-400">
                            Scan customer validation envelope QR code to authorize restricted access/sale:
                          </p>
                          <button
                            id="btn-scan-pos-qr"
                            onClick={handlePosScan}
                            className="py-2.5 px-6 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-emerald-600/20 transition-all flex items-center gap-2 mx-auto cursor-pointer"
                          >
                            <Smartphone className="w-4 h-4" />
                            Scan Customer Envelope QR
                          </button>
                        </div>
                      )}
                      
                      {isE2eRunning && (
                        <div className="text-center py-6 space-y-3 animate-pulse">
                          <RefreshCw className="w-8 h-8 text-emerald-500 animate-spin mx-auto" />
                          <p className="text-xs text-emerald-400 font-mono">Running Dual-Key E2E Cryptography...</p>
                        </div>
                      )}

                      {posScanned && e2eResult && (
                        <div className="space-y-3 animate-fadeIn">
                          <div className={`p-3 border rounded-xl text-center ${e2eResult.dualKeyOk && e2eResult.ageGateOk ? 'bg-emerald-950/60 border-emerald-500/50' : 'bg-red-950/60 border-red-500/50'}`}>
                            {e2eResult.dualKeyOk && e2eResult.ageGateOk ? (
                              <span className="text-sm font-extrabold text-emerald-400 flex items-center justify-center gap-2">
                                <Check className="w-4 h-4" />
                                🟢 18+ AGE VERIFIED — AUTHORIZED
                              </span>
                            ) : (
                              <span className="text-sm font-extrabold text-red-400 flex items-center justify-center gap-2">
                                <XCircle className="w-4 h-4" />
                                🔴 AGE VERIFICATION FAILED
                              </span>
                            )}
                            {e2eResult.error && (
                              <div className="text-red-300 text-[10px] mt-2 font-mono">{e2eResult.error}</div>
                            )}
                          </div>
                          
                          <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-300">
                            <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                              <span className="text-slate-500 block">Total Latency:</span>
                              <span className="text-blue-400 font-bold block">{e2eResult.timings.total_ms.toFixed(1)} ms</span>
                              <span className="text-[9px] text-slate-400 block mt-1">Dual-Key: {e2eResult.timings.dualKey_ms.toFixed(1)}ms</span>
                              <span className="text-[9px] text-slate-400 block">Prove: {e2eResult.timings.prove_ms.toFixed(1)}ms | Verify: {e2eResult.timings.verify_ms.toFixed(1)}ms</span>
                            </div>
                            <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                              <span className="text-slate-500 block">PII Accessed / Proof Size:</span>
                              <span className="text-emerald-400 font-bold block">0 Bytes PII Retained</span>
                              <span className="text-[10px] text-slate-400 block mt-1 font-mono">ZKP Bytes: {e2eResult.proofByteLength} B</span>
                            </div>
                            <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                              <span className="text-slate-500 block">Restricted Item / Portal:</span>
                              <span className="truncate block font-bold text-slate-200">{envelope.merchantClearance.productScanned}</span>
                              <span className="text-[10px] text-amber-400 block font-mono">UID: {envelope.merchantClearance.productHardwareUid || selectedRfidItem.hardwareUid}</span>
                            </div>
                            <div className="bg-slate-900/80 p-2 rounded border border-slate-800">
                              <span className="text-slate-500 block">Stock Policy Gate:</span>
                              <span className="text-emerald-400 font-bold block">{envelope.merchantClearance.productAuthenticity || '[OK / AUTHENTIC]'}</span>
                              <span className="text-[10px] text-slate-400 block font-mono">Excise: €{(envelope.merchantClearance.exciseDutyRecovered ?? selectedRfidItem.exciseRecovered).toFixed(2)}</span>
                            </div>
                            <div className="bg-slate-900/80 p-2 rounded border border-slate-800 col-span-2 flex justify-between items-center">
                              <div>
                                <span className="text-slate-500 block">Regulatory Directive:</span>
                                <span className="truncate block">{profile.auditDirective}</span>
                              </div>
                              <div className="text-right">
                                <span className="text-slate-500 block">Compliance Credit:</span>
                                <span className="text-blue-400 font-bold">+{profile.complianceCredit.currency} {profile.complianceCredit.amount.toFixed(2)}</span>
                              </div>
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-10 bg-slate-950/40 border border-slate-800/60 rounded-xl text-slate-500 text-sm">
                    Complete Steps 1–3 to generate the Zero Data-Liability Validation Envelope.
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
                Real-Time Cryptographic Execution Audit Trail ({profile.shortLabel})
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
      )}
    </>
  );
}
