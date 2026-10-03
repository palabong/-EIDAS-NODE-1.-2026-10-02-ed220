import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  Key, 
  FileCode, 
  RefreshCw, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Copy, 
  Check, 
  Send, 
  Lock, 
  User, 
  Sparkles,
  Server,
  Layers,
  Fingerprint
} from 'lucide-react';
import {
  isHardwareEnclaveAvailable,
  registerHardwareEnclaveKey,
  authenticateWithHardwareEnclave,
  WebAuthnCredentialInfo
} from '../lib/webauthnEnclave';

interface SamlMetadataResult {
  status: number;
  contentType: string;
  xml: string;
}

interface AuthnRequestResult {
  success: boolean;
  requestId?: string;
  destination?: string;
  authnRequestXml?: string;
  samlRequestBase64?: string;
  error?: string;
}

interface AcsValidationResult {
  status: number;
  data: any;
}

export default function EidasNodeLab() {
  // Tabs inside the SAML Lab: 'authn' | 'acs' | 'metadata' | 'session' | 'webauthn'
  const [labTab, setLabTab] = useState<'authn' | 'acs' | 'metadata' | 'session' | 'webauthn'>('authn');

  // Metadata State
  const [metadataLoading, setMetadataLoading] = useState(false);
  const [metadataResult, setMetadataResult] = useState<SamlMetadataResult | null>(null);
  const [copiedMetadata, setCopiedMetadata] = useState(false);

  // AuthnRequest State
  const [loa, setLoa] = useState<'low' | 'substantial' | 'high'>('substantial');
  const [spEntityId, setSpEntityId] = useState('http://localhost:3000/saml/metadata');
  const [authnLoading, setAuthnLoading] = useState(false);
  const [authnResult, setAuthnResult] = useState<AuthnRequestResult | null>(null);
  const [copiedAuthnXml, setCopiedAuthnXml] = useState(false);
  const [copiedAuthnB64, setCopiedAuthnB64] = useState(false);

  // ACS / Response Validation State
  const [selectedPreset, setSelectedPreset] = useState<string>('valid_rsa');
  const [customSamlResponse, setCustomSamlResponse] = useState<string>('');
  const [acsLoading, setAcsLoading] = useState(false);
  const [acsResult, setAcsResult] = useState<AcsValidationResult | null>(null);

  // Session State
  const [sessionLoading, setSessionLoading] = useState(false);
  const [sessionResult, setSessionResult] = useState<any>(null);

  // WebAuthn / Hardware Enclave State (Phase 2 TRL 5)
  const [hardwareAvailable, setHardwareAvailable] = useState<boolean>(false);
  const [webauthnLoading, setWebauthnLoading] = useState<boolean>(false);
  const [webauthnCred, setWebauthnCred] = useState<WebAuthnCredentialInfo | null>(null);
  const [webauthnResult, setWebauthnResult] = useState<any>(null);
  const [webauthnError, setWebauthnError] = useState<string | null>(null);

  // Auto-fetch metadata & hardware status on initial load
  useEffect(() => {
    fetchMetadata();
    checkSession();
    isHardwareEnclaveAvailable().then(setHardwareAvailable).catch(() => setHardwareAvailable(false));
  }, []);

  const fetchMetadata = async () => {
    setMetadataLoading(true);
    try {
      const res = await fetch('/saml/metadata');
      const text = await res.text();
      setMetadataResult({
        status: res.status,
        contentType: res.headers.get('content-type') || 'application/samlmetadata+xml',
        xml: text
      });
    } catch (err: any) {
      setMetadataResult({
        status: 500,
        contentType: 'text/plain',
        xml: `Error connecting to SAML metadata endpoint: ${err.message}`
      });
    } finally {
      setMetadataLoading(false);
    }
  };

  const handleGenerateAuthnRequest = async () => {
    setAuthnLoading(true);
    setAuthnResult(null);
    try {
      const res = await fetch('/saml/authn-request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ spEntityId, loa })
      });
      const data = await res.json();
      setAuthnResult(data);
    } catch (err: any) {
      setAuthnResult({
        success: false,
        error: `Network error: ${err.message}`
      });
    } finally {
      setAuthnLoading(false);
    }
  };

  const checkSession = async () => {
    setSessionLoading(true);
    try {
      const res = await fetch('/saml/session');
      const data = await res.json();
      setSessionResult({ status: res.status, data });
    } catch (err: any) {
      setSessionResult({ status: 500, data: { error: err.message } });
    } finally {
      setSessionLoading(false);
    }
  };

  const applyPresetVector = (presetKey: string) => {
    setSelectedPreset(presetKey);
    setAcsResult(null);
  };

  const handleRunAcsValidation = async () => {
    setAcsLoading(true);
    setAcsResult(null);
    try {
      let bodyData: any = {};

      if (selectedPreset === 'custom') {
        bodyData = { samlResponse: customSamlResponse };
      } else {
        bodyData = { preset: selectedPreset };
      }

      const res = await fetch('/saml/acs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(bodyData)
      });

      const data = await res.json();
      setAcsResult({ status: res.status, data });

      checkSession();
    } catch (err: any) {
      setAcsResult({ status: 500, data: { error: `Validation request failed: ${err.message}` } });
    } finally {
      setAcsLoading(false);
    }
  };

  // WebAuthn Register Hardware Enclave Key
  const handleRegisterWebAuthnKey = async () => {
    setWebauthnLoading(true);
    setWebauthnError(null);
    setWebauthnResult(null);
    try {
      const cred = await registerHardwareEnclaveKey('daniele.palagi92@gmail.com', 'Daniele Palagi');
      setWebauthnCred(cred);
      setWebauthnResult({
        status: 'VERIFIED',
        message: 'Hardware Enclave Key Registered & Attested in Server',
        credentialId: cred.id,
        authenticatorAttachment: cred.authenticatorAttachment
      });
    } catch (err: any) {
      setWebauthnError(err.message || 'WebAuthn hardware key registration failed.');
    } finally {
      setWebauthnLoading(false);
    }
  };

  // WebAuthn Hardware Assertion Signing
  const handleAuthenticateWebAuthn = async () => {
    if (!webauthnCred) {
      setWebauthnError('Please register a hardware enclave key first.');
      return;
    }
    setWebauthnLoading(true);
    setWebauthnError(null);
    try {
      const assertion = await authenticateWithHardwareEnclave(webauthnCred.id);
      setWebauthnResult({
        status: 'AUTHENTICATED',
        message: 'Hardware Touch ID / Secure Enclave Assertion Verified (TRL 5)',
        credentialId: assertion.id,
        signature: assertion.response.signature
      });
    } catch (err: any) {
      setWebauthnError(err.message || 'WebAuthn assertion signing failed.');
    } finally {
      setWebauthnLoading(false);
    }
  };

  const copyToClipboard = (text: string, setFn: (val: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setFn(true);
    setTimeout(() => setFn(false), 2000);
  };

  return (
    <div className="w-full max-w-7xl mx-auto space-y-6">
      
      {/* Top Banner Header */}
      <div className="bg-gradient-to-r from-slate-900 via-blue-950 to-slate-900 border border-blue-800/40 rounded-xl p-6 shadow-xl text-white relative overflow-hidden">
        <div className="absolute right-0 top-0 bottom-0 w-1/3 bg-gradient-to-l from-blue-600/10 to-transparent pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 relative z-10">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="bg-blue-500/20 text-blue-300 text-[10px] font-mono font-bold uppercase tracking-widest px-2.5 py-0.5 rounded border border-blue-400/30">
                eIDAS 2.0 Node Protocol
              </span>
              <span className="bg-emerald-500/20 text-emerald-300 text-[10px] font-mono font-bold uppercase tracking-widest px-2.5 py-0.5 rounded border border-emerald-400/30">
                TRL 5 Hardware Enclave Active
              </span>
            </div>
            <h1 className="text-2xl font-black tracking-tight flex items-center gap-2.5">
              <ShieldCheck className="text-blue-400 w-7 h-7" />
              <span>eIDAS SAML 2.0 & Hardware Secure Enclave Lab</span>
            </h1>
            <p className="text-xs text-slate-300 max-w-2xl">
              Direct interactive UI suite for inspecting SAML 2.0 Metadata, generating eIDAS AuthnRequests, 
              testing XML-DSig signature verification, and validating WebAuthn Secure Enclave hardware binding (TRL 5).
            </p>
          </div>

          <div className="flex items-center gap-2 bg-slate-800/80 p-3 rounded-lg border border-slate-700 text-xs font-mono">
            <Server className="w-4 h-4 text-blue-400" />
            <div>
              <div className="text-slate-400 text-[10px]">SP Entity ID</div>
              <div className="text-blue-300 font-bold">http://localhost:3000/saml/metadata</div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 mt-6 border-b border-slate-800 pb-2 overflow-x-auto">
          <button
            onClick={() => setLabTab('authn')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
              labTab === 'authn'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Send className="w-3.5 h-3.5" />
            <span>1. AuthnRequest Generator</span>
          </button>

          <button
            onClick={() => setLabTab('acs')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
              labTab === 'acs'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            <span>2. ACS & Assertion Validator</span>
          </button>

          <button
            onClick={() => setLabTab('metadata')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
              labTab === 'metadata'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>3. SP Metadata Inspector</span>
          </button>

          <button
            onClick={() => setLabTab('session')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
              labTab === 'session'
                ? 'bg-blue-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <User className="w-3.5 h-3.5" />
            <span>4. Active Session Status</span>
          </button>

          <button
            onClick={() => setLabTab('webauthn')}
            className={`px-4 py-2 text-xs font-bold rounded-lg transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
              labTab === 'webauthn'
                ? 'bg-emerald-600 text-white shadow-md'
                : 'text-emerald-400 hover:text-white hover:bg-slate-800/60'
            }`}
          >
            <Fingerprint className="w-3.5 h-3.5" />
            <span>5. Hardware Secure Enclave (TRL 5)</span>
          </button>
        </div>
      </div>

      {/* TAB 1: AuthnRequest Generator */}
      {labTab === 'authn' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          <div className="lg:col-span-4 bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
              <Send className="w-4 h-4 text-blue-600" /> AuthnRequest Parameters
            </h3>

            <div className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-600 block mb-1">
                  Level of Assurance (LoA)
                </label>
                <select
                  value={loa}
                  onChange={(e) => setLoa(e.target.value as any)}
                  className="w-full text-xs font-mono bg-slate-50 border border-slate-300 rounded-lg p-2.5 text-slate-800 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                >
                  <option value="low">http://eidas.europa.eu/LoA/low</option>
                  <option value="substantial">http://eidas.europa.eu/LoA/substantial (Default)</option>
                  <option value="high">http://eidas.europa.eu/LoA/high</option>
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-600 block mb-1">
                  SP Entity ID
                </label>
                <input
                  type="text"
                  value={spEntityId}
                  onChange={(e) => setSpEntityId(e.target.value)}
                  className="w-full text-xs font-mono bg-slate-50 border border-slate-300 rounded-lg p-2.5 text-slate-800 focus:ring-2 focus:ring-blue-500 focus:outline-none"
                />
              </div>

              <button
                onClick={handleGenerateAuthnRequest}
                disabled={authnLoading}
                className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-lg transition-all shadow-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {authnLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" /> Generating...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" /> Generate eIDAS AuthnRequest
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="lg:col-span-8 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl text-slate-100 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-blue-400 flex items-center gap-2">
                <FileCode className="w-4 h-4" /> Generated AuthnRequest Payload
              </h3>
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
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div>
                    <span className="text-slate-500">Request ID:</span>
                    <div className="text-emerald-400 font-bold">{authnResult.requestId}</div>
                  </div>
                  <div>
                    <span className="text-slate-500">PEPS Destination:</span>
                    <div className="text-blue-300 font-bold truncate">{authnResult.destination}</div>
                  </div>
                </div>

                <div>
                  <div className="text-slate-400 font-semibold mb-1">eIDAS SAML 2.0 XML:</div>
                  <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-[11px] text-blue-200 overflow-x-auto max-h-72 leading-relaxed font-mono">
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
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 text-[10px] text-slate-400 break-all max-h-24 overflow-y-auto font-mono">
                    {authnResult.samlRequestBase64}
                  </div>
                </div>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-slate-500 text-xs font-mono space-y-2 border border-dashed border-slate-800 rounded-lg">
                <Send className="w-8 h-8 text-slate-600 mb-1" />
                <span>Click "Generate eIDAS AuthnRequest" to issue a signed SAML request.</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: ACS & Assertion Validator */}
      {labTab === 'acs' && (
        <div className="space-y-6">
          <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-700 flex items-center gap-2">
              <Key className="w-4 h-4 text-blue-600" /> Select Assertion Vector Profile
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <button
                onClick={() => applyPresetVector('valid_rsa')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  selectedPreset === 'valid_rsa'
                    ? 'bg-blue-50 border-blue-500 ring-2 ring-blue-500/20'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-900">1. Valid Natural Person</span>
                  <span className="bg-emerald-100 text-emerald-700 text-[9px] font-bold px-2 py-0.5 rounded">RSA-SHA256</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Compliant eIDAS Assertion for Jean Dupont (DOB: 1985-04-12, LoA High).
                </p>
              </button>

              <button
                onClick={() => applyPresetVector('valid_ecdsa')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  selectedPreset === 'valid_ecdsa'
                    ? 'bg-blue-50 border-blue-500 ring-2 ring-blue-500/20'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-900">2. ECDSA Signed Response</span>
                  <span className="bg-indigo-100 text-indigo-700 text-[9px] font-bold px-2 py-0.5 rounded">ECDSA-SHA256</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Compliant eIDAS Assertion for Maria Garcia (DOB: 1992-11-03, LoA Substantial).
                </p>
              </button>

              <button
                onClick={() => applyPresetVector('tampered_sig')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  selectedPreset === 'tampered_sig'
                    ? 'bg-amber-50 border-amber-500 ring-2 ring-amber-500/20'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-900">3. Tampered Signature</span>
                  <span className="bg-amber-100 text-amber-800 text-[9px] font-bold px-2 py-0.5 rounded">Security Rejection</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Altered signature bytes to test 401 verification rejection.
                </p>
              </button>

              <button
                onClick={() => applyPresetVector('underage_cashier')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  selectedPreset === 'underage_cashier'
                    ? 'bg-purple-50 border-purple-500 ring-2 ring-purple-500/20'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-900">4. Minor Cashier (&lt;18)</span>
                  <span className="bg-purple-100 text-purple-700 text-[9px] font-bold px-2 py-0.5 rounded">Age Gating</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  DOB 2010-05-15. Verifies automated constraint to CASHIER role.
                </p>
              </button>

              <button
                onClick={() => applyPresetVector('expired_assertion')}
                className={`p-3 rounded-lg border text-left transition-all cursor-pointer ${
                  selectedPreset === 'expired_assertion'
                    ? 'bg-rose-50 border-rose-500 ring-2 ring-rose-500/20'
                    : 'bg-slate-50 border-slate-200 hover:bg-slate-100'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-bold text-slate-900">5. Expired Assertion</span>
                  <span className="bg-rose-100 text-rose-700 text-[9px] font-bold px-2 py-0.5 rounded">Clock Skew Guard</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Expired timestamp to verify condition window rejection.
                </p>
              </button>
            </div>

            <div className="flex justify-end">
              <button
                onClick={handleRunAcsValidation}
                disabled={acsLoading}
                className="py-2.5 px-6 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-lg transition-all shadow-md flex items-center gap-2 cursor-pointer disabled:opacity-50"
              >
                {acsLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" /> Validating Assertion...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" /> Run POST /saml/acs Validation
                  </>
                )}
              </button>
            </div>
          </div>

          {/* ACS Result Panel */}
          {acsResult && (() => {
            const isValid = acsResult.status === 200 && acsResult.data?.success !== false && !acsResult.data?.error && acsResult.data?.valid !== false;
            const user = acsResult.data?.user;
            const pos = acsResult.data?.pos_context || acsResult.data?.extractedAttributes;
            const personId = user?.personIdentifier || pos?.user_id || user?.uid || pos?.PersonIdentifier || 'N/A';
            const fullName = user?.name || (pos?.given_name ? `${pos.given_name} ${pos.family_name || ''}`.trim() : null) || (pos?.CurrentGivenName ? `${pos.CurrentGivenName} ${pos.CurrentFamilyName || ''}`.trim() : 'N/A');
            const dob = user?.dateOfBirth || pos?.date_of_birth || pos?.DateOfBirth || 'N/A';
            const ageVal = user?.age ?? pos?.age ?? pos?.ageYears;
            const ageDisplay = ageVal !== undefined ? ` (${ageVal} yrs)` : '';
            const roleStr = user?.role || pos?.role || pos?.assignedRole || 'STORE_MANAGER';

            return (
              <div className={`p-6 rounded-xl border shadow-lg space-y-4 font-mono ${
                isValid 
                  ? 'bg-slate-900 border-emerald-500/50 text-slate-100' 
                  : 'bg-slate-900 border-rose-500/50 text-slate-100'
              }`}>
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-3">
                    {isValid ? (
                      <CheckCircle2 className="w-6 h-6 text-emerald-400" />
                    ) : (
                      <XCircle className="w-6 h-6 text-rose-400" />
                    )}
                    <div>
                      <h4 className="text-sm font-bold uppercase tracking-wider">
                        {isValid ? 'ACS Assertion Validation Passed (200 OK)' : `ACS Validation Rejected (${acsResult.status})`}
                      </h4>
                      <p className="text-xs text-slate-400">
                        Processed via Python `saml_engine` SecureXMLParser & XML-DSig Verification Engine
                      </p>
                    </div>
                  </div>

                  <span className={`text-xs font-bold px-3 py-1 rounded-full uppercase ${
                    isValid ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' : 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  }`}>
                    {isValid ? 'VALID ASSERTION' : 'REJECTED / INVALID'}
                  </span>
                </div>

                {/* Verified Attributes Grid */}
                {isValid && (
                  <div className="space-y-2">
                    <div className="text-xs font-bold text-blue-400 uppercase tracking-wider">Extracted eIDAS Natural Person Attributes:</div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">PersonIdentifier</div>
                        <div className="text-xs text-emerald-300 font-bold truncate">{personId}</div>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">Full Name</div>
                        <div className="text-xs text-slate-200 font-bold">{fullName}</div>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">Date of Birth / Age</div>
                        <div className="text-xs text-amber-300 font-bold">{dob}{ageDisplay}</div>
                      </div>
                      <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                        <div className="text-[10px] text-slate-500">Assigned Retail Role</div>
                        <div className="text-xs text-purple-300 font-bold">{roleStr}</div>
                      </div>
                    </div>
                  </div>
                )}

                <div>
                  <div className="text-xs font-bold text-slate-400 uppercase mb-1">Full Server Response JSON:</div>
                  <pre className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-[11px] text-blue-200 overflow-x-auto max-h-60 leading-relaxed font-mono">
                    {JSON.stringify(acsResult.data, null, 2)}
                  </pre>
                </div>
              </div>
            );
          })()}
        </div>
      )}

      {/* TAB 3: SP Metadata Inspector */}
      {labTab === 'metadata' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl text-slate-100 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <FileCode className="w-5 h-5 text-blue-400" />
              <div>
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-200">
                  Live SAML 2.0 EntityDescriptor Metadata XML
                </h3>
                <span className="text-xs text-slate-400">Endpoint: GET /saml/metadata</span>
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={fetchMetadata}
                disabled={metadataLoading}
                className="text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1.5 rounded border border-slate-700 flex items-center gap-1.5 cursor-pointer"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${metadataLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>

              {metadataResult?.xml && (
                <button
                  onClick={() => copyToClipboard(metadataResult.xml, setCopiedMetadata)}
                  className="text-xs font-mono text-slate-300 hover:text-white bg-slate-800 px-3 py-1.5 rounded border border-slate-700 flex items-center gap-1.5 cursor-pointer"
                >
                  {copiedMetadata ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedMetadata ? 'Copy Metadata XML' : 'Copy Metadata XML'}</span>
                </button>
              )}
            </div>
          </div>

          {metadataResult && (
            <pre className="bg-slate-950 p-5 rounded-lg border border-slate-800 text-[11px] text-blue-200 overflow-x-auto max-h-[500px] leading-relaxed font-mono">
              {metadataResult.xml}
            </pre>
          )}
        </div>
      )}

      {/* TAB 4: Active Session Status */}
      {labTab === 'session' && (
        <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-xs space-y-4">
          <div className="flex items-center justify-between border-b border-slate-200 pb-3">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-800 flex items-center gap-2">
              <User className="w-4 h-4 text-blue-600" /> SAML Active Session Monitor
            </h3>

            <button
              onClick={checkSession}
              disabled={sessionLoading}
              className="text-xs font-bold text-slate-700 bg-slate-100 hover:bg-slate-200 px-3 py-1.5 rounded-lg border border-slate-300 flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${sessionLoading ? 'animate-spin' : ''}`} />
              <span>Check Session Status</span>
            </button>
          </div>

          {sessionResult ? (
            <div className="space-y-4 font-mono">
              <div className="flex items-center gap-3">
                <span className="text-xs font-semibold text-slate-600">HTTP Status:</span>
                <span className={`text-xs font-bold px-2.5 py-0.5 rounded ${
                  sessionResult.status === 200 ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-800'
                }`}>
                  {sessionResult.status} {sessionResult.status === 200 ? 'Session Active' : 'Unauthorized / No Session'}
                </span>
              </div>

              <pre className="bg-slate-900 p-4 rounded-lg text-xs text-blue-200 overflow-x-auto">
                {JSON.stringify(sessionResult.data, null, 2)}
              </pre>
            </div>
          ) : (
            <div className="text-xs text-slate-500 font-mono">Loading session status...</div>
          )}
        </div>
      )}

      {/* TAB 5: Hardware Secure Enclave (TRL 5) */}
      {labTab === 'webauthn' && (
        <div className="bg-white border border-slate-200 rounded-xl p-6 shadow-xs space-y-6 font-sans">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-200 pb-4">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="bg-emerald-100 text-emerald-800 text-[10px] font-mono font-bold px-2 py-0.5 rounded">TRL 5 Relevant Environment</span>
                <span className="bg-blue-100 text-blue-800 text-[10px] font-mono font-bold px-2 py-0.5 rounded">FIDO2 / WebAuthn</span>
              </div>
              <h3 className="text-lg font-black text-slate-900 flex items-center gap-2">
                <Fingerprint className="w-5 h-5 text-emerald-600" />
                Hardware Secure Enclave Key Binding & Verification
              </h3>
              <p className="text-xs text-slate-500 mt-0.5">
                Binds the user identity to physical device hardware (Apple Secure Enclave / Touch ID / Windows Hello / YubiKey TPM) via standard WebAuthn.
              </p>
            </div>

            <div className={`px-3 py-1.5 rounded-lg border text-xs font-mono flex items-center gap-2 ${
              hardwareAvailable 
                ? 'bg-emerald-50 border-emerald-300 text-emerald-800 font-bold' 
                : 'bg-amber-50 border-amber-300 text-amber-800 font-bold'
            }`}>
              <span className={`w-2 h-2 rounded-full ${hardwareAvailable ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
              <span>{hardwareAvailable ? 'Hardware Authenticator Detected (Touch ID / TPM)' : 'Emulated / Software WebAuthn Mode'}</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Action 1: Register Hardware Key */}
            <div className="p-5 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[10px]">1</span>
                <span>Register Hardware Enclave Key</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Triggers device biometrics (Touch ID / Face ID) to generate an ECDSA P-256 public/private keypair inside the hardware Secure Enclave and register public attestation on `/api/webauthn/register-verify`.
              </p>
              <button
                onClick={handleRegisterWebAuthnKey}
                disabled={webauthnLoading}
                className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-lg transition-all shadow-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
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

            {/* Action 2: Sign Assertion */}
            <div className="p-5 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-xs font-bold text-slate-800 uppercase tracking-wider">
                <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[10px]">2</span>
                <span>Sign Challenge via Hardware Touch ID</span>
              </div>
              <p className="text-xs text-slate-600 leading-relaxed">
                Signs a server-issued challenge using the registered hardware private key inside the device enclave and verifies the assertion signature on `/api/webauthn/authenticate-verify`.
              </p>
              <button
                onClick={handleAuthenticateWebAuthn}
                disabled={webauthnLoading || !webauthnCred}
                className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs rounded-lg transition-all shadow-xs flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
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

          {/* WebAuthn Error Message */}
          {webauthnError && (
            <div className="p-4 bg-rose-50 border border-rose-300 rounded-xl text-xs text-rose-800 flex items-start gap-2.5">
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block">WebAuthn Hardware Verification Error:</span>
                <span>{webauthnError}</span>
              </div>
            </div>
          )}

          {/* WebAuthn Live Result Display */}
          {webauthnResult && (
            <div className="p-5 bg-slate-900 border border-emerald-500/50 rounded-xl text-slate-100 font-mono space-y-3 shadow-lg">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div className="flex items-center gap-2 text-xs font-bold text-emerald-400 uppercase tracking-wider">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>{webauthnResult.status}: Hardware Enclave Assertion Success</span>
                </div>
                <span className="text-[10px] bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30">
                  TRL 5 Hardware Validated
                </span>
              </div>
              <p className="text-xs text-slate-300 font-sans">{webauthnResult.message}</p>
              <pre className="bg-slate-950 p-4 rounded-lg text-[11px] text-blue-200 overflow-x-auto max-h-56 leading-relaxed">
                {JSON.stringify(webauthnResult, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

    </div>
  );
}
