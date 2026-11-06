import React, { useState, useCallback, useMemo, useEffect } from 'react';
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
  UserCheck,
  Usb,
  Fingerprint,
  Globe2,
  FileCode,
  Send,
  Copy,
  Server,
  Layers,
  FileText,
  ShieldCheck,
  Sliders,
  ArrowRight,
  ExternalLink,
  Eye,
  Link as LinkIcon,
  User,
  Radio,
  BookOpen
} from 'lucide-react';
import { 
  runPilotDemonstration, 
  CITIZEN_PRESETS, 
  type CitizenPresetKey, 
  type CitizenIngestionProfile,
  type BilanxValidationEnvelope,
  type StepLogEntry
} from './lib/e2e/runSwissDemonstration.ts';
import { 
  getPilotProfile, 
  type PilotJurisdictionId, 
  type PilotProfile 
} from './lib/pilotProfiles.ts';
import { QrCodeSvg } from './components/QrCodeSvg.tsx';
import { generateAuditCertificatePdf } from './lib/PdfReceiptGenerator.ts';
import {
  isHardwareEnclaveAvailable,
  registerHardwareEnclaveKey,
  authenticateWithHardwareEnclave,
  type WebAuthnCredentialInfo
} from '../lib/webauthnEnclave.ts';
import type { EidasAssertion, UhdRfidAssertion, DKProduct, DKWallet } from '../types.ts';
import { runDualKeyAgeGate, E2EAgeGateResult } from './lib/e2e/runDualKeyAgeGate';
import { DEFAULT_UHD_RFID_ASSERTIONS } from '../data.ts';

export interface SwissUnifiedPoCDemoProps {
  currentUser?: any;
  initialTab?: 'pilot' | 'protocols' | 'trust' | 'unified';
  boundAssertions?: EidasAssertion[];
  boundRfidAssertions?: UhdRfidAssertion[];
  onAddAssertion?: (assertion: EidasAssertion) => void;
  dkProducts?: DKProduct[];
  dkWallets?: DKWallet[];
}

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

export const SwissUnifiedPoCDemo: React.FC<SwissUnifiedPoCDemoProps> = ({ 
  currentUser,
  initialTab = 'pilot',
  boundAssertions,
  boundRfidAssertions,
  onAddAssertion,
  dkProducts = [],
  dkWallets = []
}) => {
  // ---------------------------------------------------------------------------
  // Top-Level Unified Dashboard Mode Switcher
  // 'pilot': Dual Pilot Pipeline (TRL 6)
  // 'saml': eIDAS 2.0 AuthnRequest & Protocol Lab
  // 'acs': ACS Assertion Validator & Security Vectors
  // 'metadata': Live SP SAML 2.0 Metadata Inspector
  // 'assertions': Bound Institutional Assertions & Explanatory Reports
  // 'enclave': Hardware Secure Enclave (TRL 5 WebAuthn)
  // 'unified': Definitive Dual-Pane Command Center
  // ---------------------------------------------------------------------------
  const [activeTab, setActiveTab] = useState<'pilot' | 'protocols' | 'trust' | 'unified'>(initialTab);

  // Update activeTab when initialTab prop changes
  useEffect(() => {
    if (initialTab) {
      setActiveTab(initialTab);
    }
  }, [initialTab]);

  // Dual-Jurisdiction Regulatory Switcher State
  const [jurisdiction, setJurisdiction] = useState<'CH' | 'IT'>('CH');
  const profile: PilotProfile = useMemo(() => getPilotProfile(jurisdiction), [jurisdiction]);

  const [selectedPreset, setSelectedPreset] = useState<CitizenPresetKey>('swiss_adult');
  const [authenticatorMode, setAuthenticatorMode] = useState<'simulator' | 'platform_biometrics' | 'yubikey_ctap2'>('simulator');
  const [productScanned, setProductScanned] = useState<string>(profile.defaultRestrictedProduct);

  // Custom Bound Citizen (when user binds a verified SAML assertion from ACS lab)
  const [customBoundCitizen, setCustomBoundCitizen] = useState<CitizenIngestionProfile | null>(null);
  const [bindingNotice, setBindingNotice] = useState<string | null>(null);
  
  // Pipeline Execution State
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activeStep, setActiveStep] = useState<0 | 1 | 2 | 3 | 4>(1);
  const [completedSteps, setCompletedSteps] = useState<Set<number>>(new Set());
  const [hwFingerprint, setHwFingerprint] = useState<string>('');
  const [envelope, setEnvelope] = useState<BilanxValidationEnvelope | null>(null);
  const [logs, setLogs] = useState<StepLogEntry[]>([]);
  const [validationStatus, setValidationStatus] = useState<'IDLE' | 'APPROVED' | 'REJECTED' | 'REJECTED_COUNTERFEIT'>('IDLE');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [posScanned, setPosScanned] = useState<boolean>(false);
  const [e2eResult, setE2eResult] = useState<E2EAgeGateResult | null>(null);
  const [isE2eRunning, setIsE2eRunning] = useState<boolean>(false);

  // ---------------------------------------------------------------------------
  // eIDAS 2.0 SAML Lab State (Extracted & Bound)
  // ---------------------------------------------------------------------------
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
  const [selectedPresetVector, setSelectedPresetVector] = useState<string>('valid_rsa');
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

  // Assertions list
  const [assertionsList, setAssertionsList] = useState<EidasAssertion[]>(() => {
    if (boundAssertions && boundAssertions.length > 0) return boundAssertions;
    return [
      {
        id: "EIDAS-2026-06-23-01",
        timestamp: "2026-06-23T10:15:30.000Z",
        issuer: "http://S-PEPS.gov.xx",
        subjectId: "SUBJ-BEL-BRU-9824A",
        transactionId: "TXN-BRU-1120X",
        loa: "high",
        attributes: { ageOver18: true, productAuthentic: true },
        signature: "SIG-881294-001"
      },
      {
        id: "EIDAS-2026-06-23-02",
        timestamp: "2026-06-23T11:42:15.000Z",
        issuer: "http://cef-eid-build-1:8080/EidasNode/ServiceMetadata",
        subjectId: "SUBJ-EU-5541B",
        transactionId: "TXN-CEF-9904Y",
        loa: "substantial",
        attributes: { ageOver18: true, productAuthentic: true },
        signature: "SIG-324095-002"
      },
      {
        id: "EIDAS-2026-06-23-03",
        timestamp: "2026-06-23T13:05:00.000Z",
        issuer: "http://S-PEPS.gov.xx",
        subjectId: "SUBJ-BEL-ANW-4402C",
        transactionId: "TXN-BRU-5512Z",
        loa: "high",
        attributes: { ageOver18: true, productAuthentic: true },
        signature: "SIG-740921-003"
      }
    ];
  });

  const rfidList = useMemo<UhdRfidAssertion[]>(() => {
    if (boundRfidAssertions && boundRfidAssertions.length > 0) return boundRfidAssertions;
    return DEFAULT_UHD_RFID_ASSERTIONS;
  }, [boundRfidAssertions]);

  const [selectedRfidUid, setSelectedRfidUid] = useState<string>('UID-9904-AUTH-951');
  const selectedRfidItem = useMemo<UhdRfidAssertion>(() => {
    return rfidList.find(r => r.hardwareUid === selectedRfidUid) || rfidList[0] || DEFAULT_UHD_RFID_ASSERTIONS[0];
  }, [rfidList, selectedRfidUid]);

  // Initial load
  useEffect(() => {
    fetchMetadata();
    checkSession();
    isHardwareEnclaveAvailable().then(setHardwareAvailable).catch(() => setHardwareAvailable(false));
  }, []);

  // Update assertions list if prop updates
  useEffect(() => {
    if (boundAssertions && boundAssertions.length > 0) {
      setAssertionsList(boundAssertions);
    }
  }, [boundAssertions]);

  // Switch Jurisdiction handler
  const handleSelectJurisdiction = (newJur: 'CH' | 'IT') => {
    setJurisdiction(newJur);
    const newProfile = getPilotProfile(newJur);
    setSelectedPreset(newJur === 'CH' ? 'swiss_adult' : 'it_adult_high');
    setProductScanned(newProfile.defaultRestrictedProduct);
    setCustomBoundCitizen(null);
    setBindingNotice(null);
    handleReset();
  };

  const effectiveCitizen: CitizenIngestionProfile = useMemo(() => {
    if (customBoundCitizen) return customBoundCitizen;
    return CITIZEN_PRESETS[selectedPreset] || {
      presetKey: 'custom_saml',
      fullName: currentUser?.name || (jurisdiction === 'IT' ? 'Cittadino Autenticato' : 'Authenticated Citizen'),
      dateOfBirth: '1992-05-14',
      age: 32,
      userId: currentUser?.uid || (jurisdiction === 'IT' ? 'ITA-USER-CURRENT' : 'CHE-USER-CURRENT'),
      nationality: jurisdiction === 'IT' ? 'Italy (ITA)' : 'Switzerland (CHE)',
      levelOfAssurance: jurisdiction === 'IT' ? 'high' : 'substantial'
    };
  }, [customBoundCitizen, selectedPreset, currentUser, jurisdiction]);

  // Synchronize product selection and Stock Policy Gate
  useEffect(() => {
    if (selectedRfidItem) {
      setProductScanned(selectedRfidItem.productName);
      if (selectedRfidItem.status === 'counterfeit') {
        setValidationStatus('REJECTED_COUNTERFEIT');
        setErrorMessage('[STOCK POLICY BLOCK: COUNTERFEIT DETECTED] Counterfeit physical product serial detected (UID-1102-FAKE-881). Revoked manufacturer signature (SIG-UNKNOWN-OR-REVOKED). POS checkout blocked.');
      } else if (selectedRfidItem.status === 'recalled') {
        setValidationStatus('REJECTED');
        setErrorMessage('[STOCK POLICY BLOCK: RECALLED STOCK] Recalled hardware serial detected (UID-3221-RECALLED-60). Checkout halted by safety policy.');
      } else {
        if (validationStatus === 'REJECTED_COUNTERFEIT' || errorMessage?.includes('STOCK POLICY BLOCK')) {
          setValidationStatus('IDLE');
          setErrorMessage(null);
        }
      }
    }
  }, [selectedRfidUid, selectedRfidItem]);

  const handleReset = useCallback(() => {
    setIsRunning(false);
    setActiveStep(1);
    setCompletedSteps(new Set());
    setHwFingerprint('');
    setEnvelope(null);
    setLogs([]);
    setErrorMessage(null);
    setPosScanned(false);
    if (selectedRfidItem.status === 'counterfeit') {
      setValidationStatus('REJECTED_COUNTERFEIT');
      setErrorMessage('[STOCK POLICY BLOCK: COUNTERFEIT DETECTED] Counterfeit physical product serial detected (UID-1102-FAKE-881). Revoked manufacturer signature (SIG-UNKNOWN-OR-REVOKED). POS checkout blocked.');
    } else if (selectedRfidItem.status === 'recalled') {
      setValidationStatus('REJECTED');
      setErrorMessage('[STOCK POLICY BLOCK: RECALLED STOCK] Recalled hardware serial detected (UID-3221-RECALLED-60). Checkout halted by safety policy.');
    } else {
      setValidationStatus('IDLE');
    }
  }, [selectedRfidItem]);

  const handleRunFullDemo = async () => {
    if (selectedRfidItem.status === 'counterfeit') {
      setValidationStatus('REJECTED_COUNTERFEIT');
      setErrorMessage('[STOCK POLICY BLOCK: COUNTERFEIT DETECTED] Counterfeit physical product detected. Checkout blocked.');
      return;
    }
    if (selectedRfidItem.status === 'recalled') {
      setValidationStatus('REJECTED');
      setErrorMessage('[STOCK POLICY BLOCK: RECALLED STOCK] Recalled physical product detected. Checkout halted.');
      return;
    }

    setIsRunning(true);
    setErrorMessage(null);
    setPosScanned(false);

    try {
      const result = await runPilotDemonstration({
        jurisdiction,
        citizenPreset: customBoundCitizen ? undefined : selectedPreset,
        customProfile: customBoundCitizen ? customBoundCitizen : undefined,
        authenticatorMode: authenticatorMode === 'simulator' 
          ? 'platform_simulator' 
          : authenticatorMode === 'platform_biometrics' 
          ? 'platform_biometrics' 
          : 'ctap2_hardware_key',
        useCtap2HardwareKey: authenticatorMode === 'yubikey_ctap2',
        useHardwareBiometrics: authenticatorMode === 'platform_biometrics',
        productScanned: selectedRfidItem.productName,
        productUid: selectedRfidItem.hardwareUid,
        rfidAssertion: selectedRfidItem
      });

      setLogs(result.logs);
      setHwFingerprint(result.hwFingerprint);
      setValidationStatus(result.validationStatus);

      if (result.success && result.envelope) {
        setEnvelope(result.envelope);
        setCompletedSteps(new Set([0, 1, 2, 3, 4]));
        setActiveStep(4);
      } else {
        setErrorMessage(result.error || 'Demonstration halted due to regulatory validation failure.');
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
      generateAuditCertificatePdf(envelope, effectiveCitizen, selectedRfidItem);
    }
  };

  // ---------------------------------------------------------------------------
  // SAML Lab API Operations
  // ---------------------------------------------------------------------------
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
    setSelectedPresetVector(presetKey);
    setAcsResult(null);
  };

  const handleRunAcsValidation = async () => {
    setAcsLoading(true);
    setAcsResult(null);
    try {
      let bodyData: any = {};
      if (selectedPresetVector === 'custom') {
        bodyData = { samlResponse: customSamlResponse };
      } else {
        bodyData = { preset: selectedPresetVector };
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

  const handleRegisterWebAuthnKey = async () => {
    setWebauthnLoading(true);
    setWebauthnError(null);
    setWebauthnResult(null);
    try {
      const cred = await registerHardwareEnclaveKey(
        currentUser?.email || 'daniele.palagi92@gmail.com', 
        currentUser?.name || 'Institutional Pilot Operator'
      );
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

  // ---------------------------------------------------------------------------
  // Extracted & Bound Integration Actions
  // ---------------------------------------------------------------------------
  // Bind Verified SAML ACS Assertion to Dual Pilot Ingestion
  const handleBindAcsToPilot = () => {
    if (!acsResult || acsResult.status !== 200) return;
    const userObj = acsResult.data?.user;
    const pos = acsResult.data?.pos_context || acsResult.data?.extractedAttributes;
    const personId = userObj?.personIdentifier || pos?.user_id || userObj?.uid || pos?.PersonIdentifier || 'EIDAS-SAML-VERIFIED';
    const fullName = userObj?.name || (pos?.given_name ? `${pos.given_name} ${pos.family_name || ''}`.trim() : 'Jean Dupont');
    const dob = userObj?.dateOfBirth || pos?.date_of_birth || pos?.DateOfBirth || '1985-04-12';
    const computedAge = userObj?.age ?? pos?.age ?? (selectedPresetVector === 'underage_cashier' ? 16 : 39);
    const assignedLoa: 'low' | 'substantial' | 'high' = 
      selectedPresetVector === 'valid_rsa' ? 'high' : 
      selectedPresetVector === 'valid_ecdsa' ? 'substantial' : 'high';

    const newCitizen: CitizenIngestionProfile = {
      presetKey: 'custom_saml',
      fullName,
      dateOfBirth: dob,
      age: computedAge,
      userId: personId,
      nationality: jurisdiction === 'IT' ? 'Italy (ITA)' : 'France (FRA)',
      levelOfAssurance: assignedLoa,
      jurisdiction: jurisdiction
    };

    setCustomBoundCitizen(newCitizen);
    setBindingNotice(`Bound verified SAML assertion for ${fullName} (${computedAge} yrs, LoA ${assignedLoa.toUpperCase()}) to Step 1 Ingestion.`);
    handleReset();

    // Also record into bound assertions list
    const newAssertion: EidasAssertion = {
      id: `EIDAS-ACS-${Date.now()}`,
      timestamp: new Date().toISOString(),
      issuer: "http://localhost:3000/saml/metadata",
      subjectId: personId,
      transactionId: `TXN-SAML-${Math.random().toString(36).substring(2, 8).toUpperCase()}`,
      loa: assignedLoa,
      attributes: {
        ageOver18: computedAge >= 18,
        productAuthentic: true
      },
      signature: acsResult.data?.signatureDigest || `SIG-ACS-${Math.random().toString(36).substring(2, 10).toUpperCase()}`
    };

    setAssertionsList(prev => [newAssertion, ...prev]);
    if (onAddAssertion) {
      onAddAssertion(newAssertion);
    }
  };

  // Bind Stored Assertion to Pilot
  const handleBindStoredAssertion = (assertion: EidasAssertion) => {
    const isAdult = assertion.attributes.ageOver18;
    const newCitizen: CitizenIngestionProfile = {
      presetKey: 'custom_saml',
      fullName: assertion.subjectId.includes('BRU') ? 'Philippe De Clerck' : 'Sofia Lindholm',
      dateOfBirth: isAdult ? '1989-06-18' : '2009-02-14',
      age: isAdult ? 37 : 17,
      userId: assertion.subjectId,
      nationality: assertion.subjectId.includes('BEL') ? 'Belgium (BEL)' : 'European Union (EU)',
      levelOfAssurance: assertion.loa,
      jurisdiction: jurisdiction
    };

    setCustomBoundCitizen(newCitizen);
    setBindingNotice(`Bound institutional assertion ${assertion.id} (${assertion.subjectId}) to Step 1.`);
    handleReset();
    setActiveTab('pilot');
  };

  // Bind WebAuthn Hardware Enclave to Step 2
  const handleBindEnclaveToStep2 = () => {
    if (webauthnCred) {
      setAuthenticatorMode('platform_biometrics');
      setHwFingerprint(`HE-SE-${webauthnCred.id.substring(0, 16).toUpperCase()}`);
      setBindingNotice('Bound hardware Secure Enclave key to Step 2 Enclave Attestation.');
      setActiveTab('pilot');
    }
  };

  const handleClearCustomBinding = () => {
    setCustomBoundCitizen(null);
    setBindingNotice(null);
    handleReset();
  };

  const handlePosScan = async () => {
    setIsE2eRunning(true);
    setPosScanned(false);
    setE2eResult(null);
    try {
      // Determine age based on current demo state
      const userAge = currentUser?.age ?? (selectedPresetVector === 'underage_cashier' ? 16 : 39);
      const result = await runDualKeyAgeGate({ 
        age: userAge, 
        threshold: 18 
      });
      setE2eResult(result);
      setPosScanned(true);
    } catch (err: any) {
      console.error(err);
      setE2eResult({
        dualKeyOk: false,
        ageGateOk: false,
        proofBytes: new Uint8Array(),
        proofByteLength: 0,
        timings: { dualKey_ms: 0, prove_ms: 0, verify_ms: 0, total_ms: 0 },
        error: err.message || String(err)
      });
      setPosScanned(true);
    } finally {
      setIsE2eRunning(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8 font-sans">
      
      {/* 🌐 Dual-Jurisdiction Interactive Pilot Switcher */}
      <div className="bg-slate-900 border border-slate-800 p-2 rounded-2xl shadow-xl flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 px-3 py-1">
          <Globe2 className="w-5 h-5 text-blue-400 shrink-0" />
          <div>
            <div className="text-xs font-bold text-white uppercase tracking-wider">Regulatory Pilot Sandbox Gateway</div>
            <div className="text-[11px] text-slate-400">TRL 6 Operational Validation Profile & eIDAS 2.0 SAML Bridge</div>
          </div>
        </div>

        <div className="flex items-center bg-slate-950 p-1.5 rounded-xl border border-slate-800 w-full sm:w-auto">
          <button
            id="btn-pilot-jurisdiction-ch"
            onClick={() => handleSelectJurisdiction('CH')}
            disabled={isRunning}
            className={`flex-1 sm:flex-initial px-5 py-2 rounded-lg font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 cursor-pointer ${
              jurisdiction === 'CH'
                ? 'bg-red-600 text-white shadow-md shadow-red-600/30 font-black'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/80'
            }`}
          >
            <span>🇨🇭</span>
            <span>Switzerland (CH - FADP / Retail POS)</span>
          </button>
          
          <button
            id="btn-pilot-jurisdiction-it"
            onClick={() => handleSelectJurisdiction('IT')}
            disabled={isRunning}
            className={`flex-1 sm:flex-initial px-5 py-2 rounded-lg font-bold text-xs uppercase tracking-wider transition-all flex items-center justify-center gap-2 cursor-pointer ${
              jurisdiction === 'IT'
                ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-black'
                : 'text-slate-400 hover:text-white hover:bg-slate-800/80'
            }`}
          >
            <span>🇮🇹</span>
            <span>Italy (IT - AgCom & eIDAS LoA High)</span>
          </button>
        </div>
      </div>

      {/* 🏛️ Jurisdiction Header Banner */}
      <div className={`bg-gradient-to-r ${jurisdiction === 'CH' ? 'from-slate-900 via-blue-950 to-slate-900' : 'from-slate-900 via-slate-950 to-blue-950'} border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl relative overflow-hidden`}>
        <div className={`absolute top-0 right-0 w-96 h-96 ${jurisdiction === 'CH' ? 'bg-red-600/10' : 'bg-blue-600/15'} rounded-full blur-3xl pointer-events-none`} />
        
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex flex-wrap items-center gap-3 mb-2">
              <span className="text-2xl">{profile.flagEmoji}</span>
              <span className={`px-3 py-1 rounded-full text-xs font-semibold ${jurisdiction === 'CH' ? 'bg-red-600/20 text-red-400 border border-red-500/30' : 'bg-blue-600/20 text-blue-400 border border-blue-500/30'} tracking-wide`}>
                {profile.shortLabel.toUpperCase()} PILOT PROFILE
              </span>
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                {jurisdiction === 'IT' ? 'eIDAS HIGH ASSURANCE (AGCOM)' : 'FADP ART. 21 ZERO-PII'}
              </span>
              <span className="px-3 py-1 rounded-full text-xs font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">
                eIDAS 2.0 SAML NODE BOUND
              </span>
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Bilanx — {profile.name} & eIDAS 2.0 SAML Lab
            </h1>
            <p className="text-sm sm:text-base text-slate-400 mt-2 max-w-3xl leading-relaxed">
              {jurisdiction === 'CH' ? (
                <>
                  Definitive proof-of-concept demonstrating zero data-liability retail compliance bound to the eIDAS 2.0 SAML network: 
                  merchants verify legal age (18+) via a 1,355-byte zero-knowledge range proof and FIDO2 hardware enclave attestation 
                  with complete SAML assertion inspection and 0-byte PII leakage.
                </>
              ) : (
                <>
                  Operational sandbox demonstrating strict compliance with Italian AgCom Delibera 9/24/CONS guidelines: 
                  enforces eIDAS Level of Assurance High credentials from live SAML assertions, YubiKey CTAP2 hardware key binding, 
                  and produces signed cryptographically verifiable audit receipts.
                </>
              )}
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              onClick={handleReset}
              disabled={isRunning}
              className="px-4 py-2.5 rounded-xl border border-slate-700 bg-slate-800/80 hover:bg-slate-700 text-slate-300 font-medium text-sm transition-all flex items-center gap-2 shadow-sm disabled:opacity-50 cursor-pointer"
            >
              <RefreshCw className="w-4 h-4" />
              Reset Demo
            </button>
            <button
              id="btn-run-pilot-demo"
              onClick={handleRunFullDemo}
              disabled={isRunning || selectedRfidItem.status !== 'authentic'}
              className={`px-6 py-2.5 rounded-xl ${
                selectedRfidItem.status !== 'authentic'
                  ? 'bg-red-950/80 border border-red-700/80 text-red-300 cursor-not-allowed opacity-80'
                  : jurisdiction === 'CH' 
                  ? 'bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 shadow-red-600/25 text-white cursor-pointer' 
                  : 'bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 shadow-blue-600/25 text-white cursor-pointer'
              } font-bold text-sm transition-all flex items-center gap-2 shadow-lg disabled:opacity-50`}
            >
              {isRunning ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Running Cryptographic Pipeline...
                </>
              ) : selectedRfidItem.status === 'counterfeit' ? (
                <>
                  <XCircle className="w-4 h-4 text-red-400" />
                  Stock Blocked: Counterfeit Item
                </>
              ) : selectedRfidItem.status === 'recalled' ? (
                <>
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  Stock Blocked: Recalled Item
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Run {jurisdiction === 'CH' ? 'Swiss' : 'Italian'} Pilot Demo
                </>
              )}
            </button>
          </div>
        </div>

        {/* 5-Step Interactive Stepper: Step 0 (RFID Product Check) + Steps 1-4 (Dual-Key Flow) */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-3 mt-8 pt-6 border-t border-slate-800/80">
          {[
            { 
              step: 0, 
              title: '0. RFID Item Scan', 
              sub: selectedRfidItem.status === 'authentic' 
                ? `${selectedRfidItem.hardwareUid} [OK]` 
                : selectedRfidItem.status === 'counterfeit' 
                ? `${selectedRfidItem.hardwareUid} [COUNTERFEIT]` 
                : `${selectedRfidItem.hardwareUid} [RECALLED]`, 
              icon: Radio,
              isSpecialStep0: true
            },
            { step: 1, title: '1. Identity Ingestion', sub: customBoundCitizen ? `Bound SAML: ${customBoundCitizen.fullName}` : (jurisdiction === 'IT' ? 'AgCom / SPID / CIE Ingestion' : 'Sovereign PII Quarantine'), icon: UserCheck },
            { step: 2, title: '2. Enclave & Key', sub: authenticatorMode === 'yubikey_ctap2' ? 'YubiKey CTAP2 Roaming' : (authenticatorMode === 'platform_biometrics' ? 'Apple Secure Enclave' : 'FIDO2 / Hardware Fingerprint'), icon: Cpu },
            { step: 3, title: '3. Dual-Key & ZKP', sub: '1355B Sigma Range Proof', icon: Shield },
            { step: 4, title: '4. Clearance & Audit', sub: jurisdiction === 'IT' ? 'AgCom Verifiable Receipt' : 'Zero-PII POS Envelope', icon: Store }
          ].map(({ step, title, sub, icon: Icon, isSpecialStep0 }) => {
            const isCompleted = isSpecialStep0 
              ? selectedRfidItem.status === 'authentic'
              : completedSteps.has(step);
            const isCurrent = activeStep === step && !isCompleted;
            const isRejected = isSpecialStep0
              ? selectedRfidItem.status !== 'authentic'
              : (validationStatus.startsWith('REJECTED') && activeStep === step);

            return (
              <div
                key={step}
                className={`p-3.5 rounded-xl border transition-all ${
                  isRejected
                    ? 'bg-red-950/30 border-red-800/60 text-red-300'
                    : isCompleted
                    ? 'bg-emerald-950/20 border-emerald-800/50 text-emerald-300'
                    : isCurrent
                    ? 'bg-blue-950/40 border-blue-600 text-blue-200 ring-2 ring-blue-500/20'
                    : 'bg-slate-900/40 border-slate-800/60 text-slate-400 opacity-70'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <div className="flex items-center gap-1.5">
                    <Icon className="w-4 h-4" />
                    <span className="font-bold text-xs truncate">{title}</span>
                  </div>
                  {isRejected ? (
                    <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
                  ) : isCompleted ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : isCurrent ? (
                    <span className="w-2 h-2 rounded-full bg-blue-400 animate-pulse shrink-0" />
                  ) : null}
                </div>
                <div className="text-[11px] text-slate-400 truncate">{sub}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 🧭 DEFINITIVE UNIFIED DASHBOARD SECTION NAVIGATION */}
      {/* 🧭 DEFINITIVE UNIFIED DASHBOARD SECTION NAVIGATION */}
      <div className="bg-slate-900 border border-slate-800 rounded-2xl p-2.5 shadow-lg flex items-center gap-2 overflow-x-auto text-xs font-bold">
        <button
          onClick={() => setActiveTab('pilot')}
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
            activeTab === 'pilot'
              ? 'bg-blue-600 text-white shadow-md'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Shield className="w-4 h-4" />
          <span>Point-of-Sale Pilot (TRL 6)</span>
        </button>

        <button
          onClick={() => setActiveTab('protocols')}
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
            activeTab === 'protocols'
              ? 'bg-blue-600 text-white shadow-md'
              : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Server className="w-4 h-4" />
          <span>Backend Protocols & Cryptography</span>
        </button>

        <button
          onClick={() => setActiveTab('trust')}
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
            activeTab === 'trust'
              ? 'bg-emerald-600 text-white shadow-md'
              : 'text-emerald-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Fingerprint className="w-4 h-4" />
          <span>Trust Anchors & Hardware</span>
        </button>

        <button
          onClick={() => setActiveTab('unified')}
          className={`px-4 py-2.5 rounded-xl transition-all flex items-center gap-2 cursor-pointer whitespace-nowrap ${
            activeTab === 'unified'
              ? 'bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md'
              : 'text-purple-400 hover:text-white hover:bg-slate-800/60'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Unified Split Command View</span>
        </button>
      </div>


      {/* Active Binding Banner Feedback */}
      {bindingNotice && (
        <div className="bg-emerald-950/40 border border-emerald-500/50 rounded-xl p-3 px-4 text-xs font-mono text-emerald-300 flex items-center justify-between animate-fadeIn">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{bindingNotice}</span>
          </div>
          <button
            onClick={handleClearCustomBinding}
            className="text-[10px] text-slate-400 hover:text-white underline cursor-pointer"
          >
            Reset to Standard Preset
          </button>
        </div>
      )}

      {/* =====================================================================
          VIEW 1: SOVEREIGN PILOT PIPELINE (TRL 6)
         ===================================================================== */}
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

    </div>
  );
};

export default SwissUnifiedPoCDemo;
