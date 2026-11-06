import React, { useState, useCallback, useMemo, useEffect } from 'react';
import { PilotPane } from './demo/PilotPane.tsx';
import { ProtocolsPane } from './demo/ProtocolsPane.tsx';
import { TrustPane } from './demo/TrustPane.tsx';
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

  const paneBag = {
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
      <PilotPane {...paneBag} />
      <ProtocolsPane {...paneBag} />
      <TrustPane {...paneBag} />

    </div>
  );
};

export default SwissUnifiedPoCDemo;
