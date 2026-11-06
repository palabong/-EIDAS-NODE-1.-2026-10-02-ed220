import React from 'react';
import { Shield, Key, Cpu, FileCheck, Download, RefreshCw, CheckCircle2, XCircle, Lock, AlertTriangle, Store, Clock, Sparkles, Smartphone, Check, UserCheck, Usb, Fingerprint, Globe2, FileCode, Send, Copy, Server, Layers, FileText, ShieldCheck, Sliders, ArrowRight, ExternalLink, Eye, Link as LinkIcon, User, Radio, BookOpen } from 'lucide-react';
import { QrCodeSvg } from '../components/QrCodeSvg.tsx';
import { CITIZEN_PRESETS, type CitizenPresetKey } from '../lib/e2e/runSwissDemonstration.ts';

export function ProtocolsPane(bag: Record<string, any>) {
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
          VIEW 2: eIDAS AUTHNREQUEST LAB
         ===================================================================== */}
      {(activeTab === 'protocols' || activeTab === 'unified') && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-blue-500/20 text-blue-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-blue-400/30">
                  POST /saml/authn-request
                </span>
                <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-emerald-400/30">
                  TRL 6 Cross-Border Gateway
                </span>
              </div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Send className="w-5 h-5 text-blue-400" />
                eIDAS 2.0 AuthnRequest Protocol Generator & Explanatory Report
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Generates canonical SAML 2.0 AuthnRequest envelopes with cryptographic signatures and level of assurance requirements.
              </p>
            </div>

            <div className="flex items-center gap-2 bg-slate-950 p-2.5 rounded-lg border border-slate-800 text-xs font-mono">
              <Server className="w-4 h-4 text-blue-400" />
              <div>
                <div className="text-slate-500 text-[10px]">SP Entity ID</div>
                <div className="text-blue-300 font-bold truncate max-w-xs">{spEntityId}</div>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            <div className="lg:col-span-4 bg-slate-950 border border-slate-800 rounded-xl p-5 space-y-4">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Sliders className="w-4 h-4 text-blue-400" /> AuthnRequest Parameters
              </h4>

              <div className="space-y-3">
                <div>
                  <label className="text-xs font-semibold text-slate-400 block mb-1">
                    Level of Assurance (LoA)
                  </label>
                  <select
                    value={loa}
                    onChange={(e) => setLoa(e.target.value as any)}
                    className="w-full text-xs font-mono bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  >
                    <option value="low">http://eidas.europa.eu/LoA/low</option>
                    <option value="substantial">http://eidas.europa.eu/LoA/substantial (Default)</option>
                    <option value="high">http://eidas.europa.eu/LoA/high (AgCom Mandate)</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-400 block mb-1">
                    SP Entity ID
                  </label>
                  <input
                    type="text"
                    value={spEntityId}
                    onChange={(e) => setSpEntityId(e.target.value)}
                    className="w-full text-xs font-mono bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-slate-200 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                  />
                </div>

                <button
                  onClick={handleGenerateAuthnRequest}
                  disabled={authnLoading}
                  className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-lg transition-all shadow-md flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                >
                  {authnLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" /> Generating Payload...
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" /> Issue eIDAS AuthnRequest
                    </>
                  )}
                </button>
              </div>

              <div className="p-3 bg-blue-950/30 border border-blue-900/40 rounded-lg text-xs text-blue-300 space-y-1">
                <span className="font-bold flex items-center gap-1">
                  <ShieldCheck className="w-3.5 h-3.5 text-blue-400" /> Dual-Pilot Binding:
                </span>
                <p className="text-[11px] text-slate-400">
                  When issued, this request prompts the European Citizen Identity Provider (PEPS) to authenticate natural person attributes for Step 1 Ingestion.
                </p>
              </div>
            </div>

            <div className="lg:col-span-8 bg-slate-950 border border-slate-800 rounded-xl p-5 text-slate-100 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-blue-400 flex items-center gap-2">
                  <FileCode className="w-4 h-4" /> Generated AuthnRequest XML & Base64 Payload
                </h4>
                {authnResult?.authnRequestXml && (
                  <button
                    onClick={() => copyToClipboard(authnResult.authnRequestXml || '', setCopiedAuthnXml)}
                    className="text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1 rounded border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedAuthnXml ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedAuthnXml ? 'Copied!' : 'Copy XML'}</span>
                  </button>
                )}
              </div>

              {authnResult ? (
                <div className="space-y-4 text-xs font-mono">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-slate-900 p-3 rounded-lg border border-slate-800">
                    <div>
                      <span className="text-slate-500">Request ID:</span>
                      <div className="text-emerald-400 font-bold truncate">{authnResult.requestId}</div>
                    </div>
                    <div>
                      <span className="text-slate-500">PEPS Destination:</span>
                      <div className="text-blue-300 font-bold truncate">{authnResult.destination}</div>
                    </div>
                  </div>

                  <div>
                    <div className="text-slate-400 font-semibold mb-1">eIDAS SAML 2.0 XML:</div>
                    <pre className="bg-slate-900 p-4 rounded-lg border border-slate-800 text-[11px] text-blue-200 overflow-x-auto max-h-56 leading-relaxed font-mono">
                      {authnResult.authnRequestXml}
                    </pre>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-slate-400 font-semibold">SAMLRequest (Base64 HTTP-POST Payload):</span>
                      {authnResult.samlRequestBase64 && (
                        <button
                          onClick={() => copyToClipboard(authnResult.samlRequestBase64 || '', setCopiedAuthnB64)}
                          className="text-[10px] text-slate-400 hover:text-white flex items-center gap-1 cursor-pointer"
                        >
                          {copiedAuthnB64 ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          <span>Copy Base64</span>
                        </button>
                      )}
                    </div>
                    <div className="bg-slate-900 p-3 rounded-lg border border-slate-800 text-[10px] text-slate-400 break-all max-h-20 overflow-y-auto font-mono">
                      {authnResult.samlRequestBase64}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="h-56 flex flex-col items-center justify-center text-slate-500 text-xs font-mono space-y-2 border border-dashed border-slate-800 rounded-lg">
                  <Send className="w-8 h-8 text-slate-600 mb-1" />
                  <span>Click "Issue eIDAS AuthnRequest" to generate a signed SAML 2.0 request payload.</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* =====================================================================
          VIEW 3: ACS & ASSERTION VECTOR LAB
         ===================================================================== */}
      {(activeTab === 'protocols' || activeTab === 'unified') && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-indigo-500/20 text-indigo-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-indigo-400/30">
                  POST /saml/acs
                </span>
                <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold px-2.5 py-0.5 rounded border border-emerald-400/30">
                  Python XML-DSig Engine
                </span>
              </div>
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Key className="w-5 h-5 text-indigo-400" />
                Assertion Consumer Service (ACS) & Security Vector Lab
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Validates authentic and adversarial SAML 2.0 responses against the eIDAS signing certificate authority with binding to Pilot Ingestion.
              </p>
            </div>

            <button
              onClick={handleRunAcsValidation}
              disabled={acsLoading}
              className="py-2.5 px-6 bg-blue-600 hover:bg-blue-500 text-white font-bold text-xs rounded-xl shadow-lg transition-all flex items-center gap-2 cursor-pointer disabled:opacity-50"
            >
              {acsLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" /> Verifying Assertion...
                </>
              ) : (
                <>
                  <ShieldCheck className="w-4 h-4" /> Run POST /saml/acs Validation
                </>
              )}
            </button>
          </div>

          {/* Test Vector Presets Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <button
              onClick={() => applyPresetVector('valid_rsa')}
              className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                selectedPresetVector === 'valid_rsa'
                  ? 'bg-blue-950/60 border-blue-500 ring-2 ring-blue-500/20'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-white">1. Valid Natural Person</span>
                <span className="bg-emerald-950 text-emerald-400 border border-emerald-800 text-[9px] font-bold px-2 py-0.5 rounded">RSA-SHA256</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Jean Dupont (DOB: 1985-04-12, LoA High). Passes signature & validity checks.
              </p>
            </button>

            <button
              onClick={() => applyPresetVector('valid_ecdsa')}
              className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                selectedPresetVector === 'valid_ecdsa'
                  ? 'bg-blue-950/60 border-blue-500 ring-2 ring-blue-500/20'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-white">2. ECDSA Signed Response</span>
                <span className="bg-indigo-950 text-indigo-400 border border-indigo-800 text-[9px] font-bold px-2 py-0.5 rounded">ECDSA-SHA256</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Maria Garcia (DOB: 1992-11-03, LoA Substantial). Curve P-256 signature.
              </p>
            </button>

            <button
              onClick={() => applyPresetVector('tampered_sig')}
              className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                selectedPresetVector === 'tampered_sig'
                  ? 'bg-amber-950/60 border-amber-500 ring-2 ring-amber-500/20'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-white">3. Tampered Signature</span>
                <span className="bg-amber-950 text-amber-400 border border-amber-800 text-[9px] font-bold px-2 py-0.5 rounded">Security Rejection</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Altered signature bytes to verify 401 signature rejection security check.
              </p>
            </button>

            <button
              onClick={() => applyPresetVector('underage_cashier')}
              className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                selectedPresetVector === 'underage_cashier'
                  ? 'bg-purple-950/60 border-purple-500 ring-2 ring-purple-500/20'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-white">4. Minor Cashier (&lt;18)</span>
                <span className="bg-purple-950 text-purple-400 border border-purple-800 text-[9px] font-bold px-2 py-0.5 rounded">Age Gating</span>
              </div>
              <p className="text-[11px] text-slate-400">
                DOB: 2010-05-15 (16yo). Verifies automated restriction to CASHIER role.
              </p>
            </button>

            <button
              onClick={() => applyPresetVector('expired_assertion')}
              className={`p-3 rounded-xl border text-left transition-all cursor-pointer ${
                selectedPresetVector === 'expired_assertion'
                  ? 'bg-rose-950/60 border-rose-500 ring-2 ring-rose-500/20'
                  : 'bg-slate-950 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold text-white">5. Expired Assertion</span>
                <span className="bg-rose-950 text-rose-400 border border-rose-800 text-[9px] font-bold px-2 py-0.5 rounded">Clock Skew Guard</span>
              </div>
              <p className="text-[11px] text-slate-400">
                Expired timestamp to verify condition window rejection.
              </p>
            </button>
          </div>

          {/* ACS Validation Result Panel */}
          {acsResult && (() => {
            const isValid = acsResult.status === 200 && acsResult.data?.success !== false && !acsResult.data?.error && acsResult.data?.valid !== false;
            const u = acsResult.data?.user;
            const pos = acsResult.data?.pos_context || acsResult.data?.extractedAttributes;
            const personId = u?.personIdentifier || pos?.user_id || u?.uid || pos?.PersonIdentifier || 'N/A';
            const fullName = u?.name || (pos?.given_name ? `${pos.given_name} ${pos.family_name || ''}`.trim() : null) || 'N/A';
            const dob = u?.dateOfBirth || pos?.date_of_birth || pos?.DateOfBirth || 'N/A';
            const ageVal = u?.age ?? pos?.age ?? pos?.ageYears ?? (selectedPresetVector === 'underage_cashier' ? 16 : 39);
            const roleStr = u?.role || pos?.role || pos?.assignedRole || 'STORE_MANAGER';

            return (
              <div className={`p-6 rounded-xl border shadow-lg space-y-4 font-mono ${
                isValid 
                  ? 'bg-slate-950 border-emerald-500/50 text-slate-100' 
                  : 'bg-slate-950 border-rose-500/50 text-slate-100'
              }`}>
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-3">
                    {isValid ? (
                      <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                    ) : (
                      <XCircle className="w-6 h-6 text-rose-400 shrink-0" />
                    )}
                    <div>
                      <h4 className="text-sm font-bold uppercase tracking-wider">
                        {isValid ? 'ACS Assertion Validation Passed (200 OK)' : `ACS Validation Rejected (${acsResult.status})`}
                      </h4>
                      <p className="text-xs text-slate-400 font-sans">
                        Processed via Python `saml_engine` SecureXMLParser & XML-DSig Verification Engine
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {isValid && (
                      <button
                        onClick={handleBindAcsToPilot}
                        className="py-1.5 px-3 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-sans font-bold flex items-center gap-1.5 shadow-md cursor-pointer"
                      >
                        <LinkIcon className="w-3.5 h-3.5" />
                        <span>Bind Verified Assertion to Pilot Ingestion (Step 1)</span>
                      </button>
                    )}
                    <span className={`text-xs font-bold px-3 py-1 rounded-full uppercase ${
                      isValid ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                    }`}>
                      {isValid ? 'VALID ASSERTION' : 'REJECTED'}
                    </span>
                  </div>
                </div>

                {isValid && (
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-blue-400 uppercase tracking-wider font-sans">Extracted eIDAS Natural Person Attributes:</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                      <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">PersonIdentifier</div>
                        <div className="text-xs text-emerald-300 font-bold truncate">{personId}</div>
                      </div>
                      <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">Full Name</div>
                        <div className="text-xs text-slate-200 font-bold">{fullName}</div>
                      </div>
                      <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">Date of Birth / Age</div>
                        <div className="text-xs text-amber-300 font-bold">{dob} ({ageVal} yrs)</div>
                      </div>
                      <div className="bg-slate-900 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">Assigned Retail Role</div>
                        <div className="text-xs text-purple-300 font-bold">{roleStr}</div>
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <div className="text-xs font-bold text-slate-400 uppercase mb-1 font-sans">Full Server Response JSON:</div>
                  <pre className="bg-slate-900 p-4 rounded-lg border border-slate-800 text-[11px] text-blue-200 overflow-x-auto max-h-48 leading-relaxed font-mono">
                    {JSON.stringify(acsResult.data, null, 2)}
                  </pre>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* =====================================================================
          VIEW 4: SP METADATA INSPECTOR
         ===================================================================== */}
      {(activeTab === 'protocols' || activeTab === 'unified') && (
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-3">
              <FileCode className="w-6 h-6 text-blue-400" />
              <div>
                <h3 className="text-base font-bold text-white uppercase tracking-wider">
                  Live SAML 2.0 EntityDescriptor Metadata Inspector
                </h3>
                <span className="text-xs text-slate-400 font-mono">Endpoint: GET /saml/metadata | EntityID: http://localhost:3000/saml/metadata</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={fetchMetadata}
                disabled={metadataLoading}
                className="text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${metadataLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>

              {metadataResult?.xml && (
                <button
                  onClick={() => copyToClipboard(metadataResult.xml, setCopiedMetadata)}
                  className="text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                >
                  {copiedMetadata ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedMetadata ? 'Copied XML!' : 'Copy Metadata XML'}</span>
                </button>
              )}
            </div>
          </div>

          <div className="p-3 bg-blue-950/30 border border-blue-900/40 rounded-xl text-xs text-blue-200">
            <strong>Institutional eIDAS Bridge:</strong> This XML metadata specifies the cryptographic public keys, KeyDescriptor certificates, 
            AssertionConsumerService (ACS) binding endpoints, and NameID formats used to interconnect with Swiss and Italian national identity nodes.
          </div>

          {metadataResult && (
            <pre className="bg-slate-950 p-5 rounded-xl border border-slate-800 text-[11px] text-blue-200 overflow-x-auto max-h-[460px] leading-relaxed font-mono">
              {metadataResult.xml}
            </pre>
          )}
        </div>
      )}
    </>
  );
}
