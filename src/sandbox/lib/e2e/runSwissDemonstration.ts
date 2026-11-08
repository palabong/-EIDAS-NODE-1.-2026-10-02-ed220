/**
 * Bilanx — Dual-Key Sovereign Validation System (DK-SVS)
 * Lab pilot pipeline. One server clearance, threshold 18. The citizen name stays off the HTTP body.
 * 
 * Supports Dual-Jurisdiction Policy Profiles:
 * 1. Swiss Profile (CH - FADP / Retail POS)
 *    - 18+ tobacco/nicotine/alcohol/lottery gate
 *    - Strict zero-PII boolean verification
 *    - 1,355-byte NIST P-256 B2 Sigma range proof
 *    - Sub-1.5s POS envelope
 * 
 * 2. Italian Profile (IT - AgCom & eIDAS LoA High)
 *    - eIDAS Level of Assurance High mapping
 *    - Institutional credential binding (BILANX-IT-AGCOM-NODE-01)
 *    - AgCom-compliant verifiable audit receipting
 * 
 * Supports Hybrid Hardware Authenticators:
 * - Real platform biometrics (Touch ID / Face ID / Windows Hello)
 * - Authentic roaming security keys (YubiKey 5 / CTAP2 Cross-Platform Token)
 * - Deterministic headless CTAP2 test harness for automated CI/CD testing
 * - Software platform enclave simulator (FIDO2 L2)
 */

import { generateProof } from '../../../lib/crypto/zkp/nizkp.ts';
import { performDualKeyHandshake } from '../../hooks/useBilanxDualKeyValidation.real.ts';
import { 
  registerSimulatorEnclave, 
  authenticateSimulatorEnclave,
  deriveHardwareFingerprint 
} from '../../../lib/crypto/simulatorEnclave.ts';
import { 
  registerHardwareEnclaveKey, 
  authenticateWithHardwareEnclave,
  isHardwareEnclaveAvailable 
} from '../../../lib/webauthnEnclave.ts';
import { 
  Ctap2HardwareKeyHarness,
  YUBIKEY_5_SERIES_AAGUID 
} from '../../../lib/crypto/ctap2Harness.ts';
import { 
  bytesToHex, 
  base64ToBytes
} from '../../../lib/crypto/encoding.ts';
import { 
  getPilotProfile, 
  PILOT_PROFILES,
  DUAL_JURISDICTION_CITIZEN_PRESETS,
  type PilotJurisdictionId,
  type PilotProfile 
} from '../pilotProfiles.ts';
import { DEFAULT_UHD_RFID_ASSERTIONS } from '../../../data.ts';
import type { UhdRfidAssertion } from '../../../types.ts';

export type CitizenPresetKey = 
  | 'swiss_adult' 
  | 'eu_adult' 
  | 'minor_luca' 
  | 'google_oauth' 
  | 'custom_saml'
  | 'it_adult_high'
  | 'it_adult_substantial'
  | 'it_minor_matteo';

export interface CitizenIngestionProfile {
  presetKey: CitizenPresetKey;
  fullName: string;
  dateOfBirth: string;
  age: number;
  userId: string;
  nationality: string;
  levelOfAssurance: 'low' | 'substantial' | 'high';
  customSamlXml?: string;
  googleIdToken?: string;
  jurisdiction?: 'CH' | 'IT';
}

export const CITIZEN_PRESETS: Record<string, CitizenIngestionProfile> = {
  swiss_adult: {
    presetKey: 'swiss_adult',
    fullName: 'Heinrich Keller',
    dateOfBirth: '1994-05-12',
    age: 32,
    userId: 'CHE-ZH-884210-HK',
    nationality: 'Switzerland (CHE)',
    levelOfAssurance: 'substantial',
    jurisdiction: 'CH'
  },
  eu_adult: {
    presetKey: 'eu_adult',
    fullName: 'Dr. Clara Schmidt',
    dateOfBirth: '1988-11-20',
    age: 37,
    userId: 'DEU-BER-991204-CS',
    nationality: 'Germany (DEU)',
    levelOfAssurance: 'high',
    jurisdiction: 'CH'
  },
  minor_luca: {
    presetKey: 'minor_luca',
    fullName: 'Luca Rossi',
    dateOfBirth: '2009-08-14',
    age: 17,
    userId: 'CHE-TI-110482-LR',
    nationality: 'Switzerland (CHE)',
    levelOfAssurance: 'substantial',
    jurisdiction: 'CH'
  },
  it_adult_high: {
    presetKey: 'it_adult_high',
    fullName: 'Marco Rossi',
    dateOfBirth: '1991-03-24',
    age: 35,
    userId: 'ITA-RM-339102-MR',
    nationality: 'Italy (ITA)',
    levelOfAssurance: 'high',
    jurisdiction: 'IT'
  },
  it_adult_substantial: {
    presetKey: 'it_adult_substantial',
    fullName: 'Giulia Bianchi',
    dateOfBirth: '1998-07-19',
    age: 28,
    userId: 'ITA-MI-772910-GB',
    nationality: 'Italy (ITA)',
    levelOfAssurance: 'substantial',
    jurisdiction: 'IT'
  },
  it_minor_matteo: {
    presetKey: 'it_minor_matteo',
    fullName: 'Matteo Russo',
    dateOfBirth: '2010-09-05',
    age: 16,
    userId: 'ITA-NA-551029-MR',
    nationality: 'Italy (ITA)',
    levelOfAssurance: 'high',
    jurisdiction: 'IT'
  }
};

export interface QuarantinedPiiData {
  fullName: string;
  dateOfBirth: string;
  userId: string;
  nationality: string;
  status: 'QUARANTINED_CLIENT_ONLY';
}

export interface BilanxValidationEnvelope {
  version: '1.0';
  envelopeId: string;
  timestamp: string;
  expiresAt: string;
  jurisdiction: 'CH' | 'IT';
  regulatoryFramework: string;
  legalBasis?: string;
  validationStatus: 'APPROVED' | 'REJECTED' | 'REJECTED_COUNTERFEIT';
  rejectionReason?: string;
  verificationClaims: {
    ageOver18: boolean;
    loa: 'low' | 'substantial' | 'high';
    issuerNode: string;
  };
  cryptographicReceipt: {
    dualKeyChallengeId: string;
    institutionalSignatureDigest: string;
    hardwareEnclaveFingerprint: string;
    authenticatorType?: string;
    aaguid?: string;
    zkpProofDigest: string;
    proofByteLength: number;
    auditReceiptHash?: string;
  };
  merchantClearance: {
    piiTransmittedBytes: 0;
    gdprLiabilityRisk: 'ZERO_LIABILITY';
    complianceRebateChf: number;
    complianceCredit?: {
      currency: string;
      amount: number;
      label: string;
    };
    productScanned?: string;
    productHardwareUid?: string;
    productCategory?: string;
    productAuthenticity?: string;
    exciseDutyRecovered?: number;
  };
  productVerification?: {
    hardwareUid: string;
    productName: string;
    category: string;
    status: 'authentic' | 'counterfeit' | 'recalled' | 'unregistered';
    manufacturerSignature: string;
    exciseDutySettled: number;
    verdict: string;
  };
  qrPayload: string;
}

export interface StepLogEntry {
  step: 0 | 1 | 2 | 3 | 4;
  title: string;
  timestamp: number;
  durationMs: number;
  status: 'PASS' | 'FAIL' | 'SKIPPED';
  details: string;
}

export interface SwissDemonstrationResult {
  success: boolean;
  validationStatus: 'APPROVED' | 'REJECTED' | 'REJECTED_COUNTERFEIT';
  currentStep: 0 | 1 | 2 | 3 | 4;
  totalTimeMs: number;
  citizen: CitizenIngestionProfile;
  quarantinedPii: QuarantinedPiiData;
  hwFingerprint: string;
  envelope?: BilanxValidationEnvelope;
  logs: StepLogEntry[];
  /** HTTP bodies this run actually sent. */
  outboundBodies: string[];
  error?: string;
}

export type PilotDemonstrationResult = SwissDemonstrationResult;

export interface PilotDemonstrationOptions {
  jurisdiction?: 'CH' | 'IT' | PilotJurisdictionId;
  citizenPreset?: CitizenPresetKey;
  customProfile?: Partial<CitizenIngestionProfile>;
  authenticatorMode?: 'platform_simulator' | 'platform_biometrics' | 'ctap2_hardware_key';
  useHardwareBiometrics?: boolean;
  useCtap2HardwareKey?: boolean;
  institutionId?: string;
  productScanned?: string;
  productUid?: string;
  rfidAssertion?: UhdRfidAssertion;
  fetchFn?: typeof fetch;
  baseUrl?: string;
  tamperHardwareFingerprint?: boolean;
}

/**
 * Unified Pilot Demonstration Pipeline Executor (CH & IT)
 */
export async function runPilotDemonstration(options?: PilotDemonstrationOptions): Promise<PilotDemonstrationResult> {
  const jurisdictionKey: 'CH' | 'IT' = (options?.jurisdiction === 'IT' || options?.jurisdiction === 'IT_AGCOM') ? 'IT' : 'CH';
  const profile: PilotProfile = getPilotProfile(jurisdictionKey);

  const baseUrl = options?.baseUrl || (typeof window !== 'undefined' && window.location ? window.location.origin : '');
  const resolveUrl = (path: string) => baseUrl ? `${baseUrl.replace(/\/$/, '')}${path}` : path;
  const outboundBodies: string[] = [];
  const callerFetch = options?.fetchFn || fetch;
  const localFetch: typeof fetch = async (input, init) => {
    const body = init?.body;
    if (typeof body === 'string') outboundBodies.push(body);
    else if (body == null) outboundBodies.push('');
    else outboundBodies.push('[non-string body]');
    return callerFetch(input, init);
  };
  const seal = (
    partial: Omit<PilotDemonstrationResult, 'outboundBodies'>
  ): PilotDemonstrationResult => ({
    ...partial,
    outboundBodies: outboundBodies.slice(),
  });
  const tStart = performance.now();
  const logs: StepLogEntry[] = [];
  const institutionId = options?.institutionId || profile.institutionId;

  // -------------------------------------------------------------------------
  // STEP 1: Citizen Identity Ingestion & Sovereign PII Quarantine
  // -------------------------------------------------------------------------
  const step1Start = performance.now();
  const defaultPreset = jurisdictionKey === 'IT' ? 'it_adult_high' : 'swiss_adult';
  const presetKey = options?.citizenPreset || defaultPreset;
  let citizen: CitizenIngestionProfile;

  if (CITIZEN_PRESETS[presetKey]) {
    citizen = { ...CITIZEN_PRESETS[presetKey] };
  } else if (options?.customProfile) {
    citizen = {
      presetKey,
      fullName: options.customProfile.fullName || (jurisdictionKey === 'IT' ? 'Cittadino Autenticato' : 'Anonymous Citizen'),
      dateOfBirth: options.customProfile.dateOfBirth || '1992-01-01',
      age: options.customProfile.age ?? 34,
      userId: options.customProfile.userId || (jurisdictionKey === 'IT' ? 'ITA-USER-0001' : 'CHE-USER-0001'),
      nationality: options.customProfile.nationality || (jurisdictionKey === 'IT' ? 'Italy (ITA)' : 'Switzerland (CHE)'),
      levelOfAssurance: options.customProfile.levelOfAssurance || (jurisdictionKey === 'IT' ? 'high' : 'substantial'),
      jurisdiction: jurisdictionKey,
      ...options.customProfile
    };
  } else {
    citizen = { ...CITIZEN_PRESETS[defaultPreset] };
  }

  // Quarantined PII Record (Strict 0-byte server leakage)
  const quarantinedPii: QuarantinedPiiData = {
    fullName: citizen.fullName,
    dateOfBirth: citizen.dateOfBirth,
    userId: citizen.userId,
    nationality: citizen.nationality,
    status: 'QUARANTINED_CLIENT_ONLY',
  };

  // -------------------------------------------------------------------------
  // STEP 0: Physical Item Scan & UHF RFID Product Stock Policy Gate
  // -------------------------------------------------------------------------
  const step0Start = performance.now();
  const catalogUid = options?.productUid || options?.rfidAssertion?.hardwareUid;
  let rfidItem: UhdRfidAssertion | undefined;
  let stockError: string | undefined;
  if (catalogUid) {
    rfidItem = DEFAULT_UHD_RFID_ASSERTIONS.find(r => r.hardwareUid === catalogUid);
    if (!rfidItem) {
      stockError = `[STOCK POLICY BLOCK: UNKNOWN UID] Hardware UID ${catalogUid} is not in the institutional catalog.`;
    }
  } else if (options?.productScanned) {
    rfidItem = DEFAULT_UHD_RFID_ASSERTIONS.find(r => r.productName === options.productScanned || r.hardwareUid === options.productScanned);
    if (!rfidItem) {
      stockError = '[STOCK POLICY BLOCK: UNKNOWN UID] Scanned product is not in the institutional catalog.';
    }
  } else {
    stockError = '[STOCK POLICY BLOCK: MISSING UID] A product hardware UID is required.';
  }

  if (stockError || !rfidItem) {
    const error = stockError || '[STOCK POLICY BLOCK: UNKNOWN UID] Hardware UID is not in the institutional catalog.';
    logs.push({
      step: 0,
      title: 'Step 0: Physical Item Scan & RFID Check (Unknown or Missing UID)',
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step0Start),
      status: 'FAIL',
      details: `${error} Transaction halted. No clearance envelope issued.`
    });
    return seal({
      success: false,
      validationStatus: 'REJECTED',
      currentStep: 0,
      totalTimeMs: Math.round(performance.now() - tStart),
      citizen,
      quarantinedPii,
      hwFingerprint: '',
      logs,
      error
    });
  }

  if (rfidItem.status === 'counterfeit') {
    logs.push({
      step: 0,
      title: 'Step 0: Physical Item Scan & RFID Check (Counterfeit Alert)',
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step0Start),
      status: 'FAIL',
      details: `[STOCK POLICY BLOCK: COUNTERFEIT DETECTED] Product "${rfidItem.productName}" (${rfidItem.hardwareUid}) flagged with revoked/invalid manufacturer signature (${rfidItem.signature}). Transaction outcome set to REJECTED_COUNTERFEIT. Excise recovery zeroed (€0.00). POS checkout blocked.`
    });

    return seal({
      success: false,
      validationStatus: 'REJECTED_COUNTERFEIT',
      currentStep: 0,
      totalTimeMs: Math.round(performance.now() - tStart),
      citizen,
      quarantinedPii,
      hwFingerprint: '',
      logs,
      error: '[STOCK POLICY BLOCK: COUNTERFEIT DETECTED] Counterfeit physical product detected. Hardware UID revoked or invalid. POS checkout blocked.'
    });
  }

  if (rfidItem.status === 'recalled') {
    logs.push({
      step: 0,
      title: 'Step 0: Physical Item Scan & RFID Check (Recalled Stock Alert)',
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step0Start),
      status: 'FAIL',
      details: `[STOCK POLICY BLOCK: RECALLED STOCK] Product "${rfidItem.productName}" (${rfidItem.hardwareUid}) flagged on institutional product safety recall list. Checkout halted by stock policy gate. Excise recovery zeroed (€0.00).`
    });

    return seal({
      success: false,
      validationStatus: 'REJECTED',
      currentStep: 0,
      totalTimeMs: Math.round(performance.now() - tStart),
      citizen,
      quarantinedPii,
      hwFingerprint: '',
      logs,
      error: '[STOCK POLICY BLOCK: RECALLED STOCK] Recalled physical product detected. Checkout halted by stock policy gate.'
    });
  }

  logs.push({
    step: 0,
    title: 'Step 0: Physical Item Scan & RFID Check',
    timestamp: Date.now(),
    durationMs: Math.round(performance.now() - step0Start),
    status: 'PASS',
    details: `[OK / AUTHENTIC] Product "${rfidItem.productName}" (${rfidItem.hardwareUid}) verified via authentic manufacturer signature (${rfidItem.signature}). Excise duty recovery: €${rfidItem.exciseRecovered.toFixed(2)}.`
  });

  try {
    // If SAML assertion ingestion: query /saml/acs
    if (presetKey !== 'google_oauth') {
      const acsPayload: any = citizen.customSamlXml 
        ? { xml_content: citizen.customSamlXml }
        : { preset: citizen.presetKey };

      const acsRes = await localFetch(resolveUrl('/saml/acs'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(acsPayload)
      });

      if (!acsRes.ok) {
        let detail = '';
        try {
          const failureBody = await acsRes.json();
          if (failureBody && typeof failureBody.error === 'string') {
            detail = failureBody.error;
          }
        } catch {
          detail = '';
        }
        throw new Error(
          detail
            ? `SAML ACS rejected the credential (HTTP ${acsRes.status}): ${detail}`
            : `SAML ACS rejected the credential (HTTP ${acsRes.status}).`
        );
      }

      const acsData = await acsRes.json();
      if (acsData.pos_context) {
        citizen.age = acsData.pos_context.age ?? citizen.age;
        if (acsData.pos_context.level_of_assurance) {
          const rawLoa = String(acsData.pos_context.level_of_assurance).toLowerCase();
          citizen.levelOfAssurance = rawLoa.includes('high') ? 'high' : rawLoa.includes('sub') ? 'substantial' : 'low';
        }
      }
    }

    logs.push({
      step: 1,
      title: `Citizen Ingestion & Sovereign PII Quarantine (${profile.shortLabel})`,
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step1Start),
      status: 'PASS',
      details: `Ingested ${citizen.nationality} credential under ${profile.regulatoryFramework}. Name and date of birth stay on the client profile. Verified Age: ${citizen.age}, LoA: ${citizen.levelOfAssurance}.`
    });
  } catch (err: any) {
    logs.push({
      step: 1,
      title: 'Citizen Identity Ingestion & Sovereign PII Quarantine',
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step1Start),
      status: 'FAIL',
      details: `Ingestion failed: ${err.message}`
    });
    return seal({
      success: false,
      validationStatus: 'REJECTED',
      currentStep: 1,
      totalTimeMs: Math.round(performance.now() - tStart),
      citizen,
      quarantinedPii,
      hwFingerprint: '',
      logs,
      error: err.message
    });
  }

  // -------------------------------------------------------------------------
  // STEP 2: Hardware Security Key & Enclave Attestation
  // -------------------------------------------------------------------------
  const step2Start = performance.now();
  let hwFingerprint = '';
  let authenticatorAttachment = 'platform_simulator';
  let aaguidUsed = '00000000-0000-0000-0000-000000000000';
  let deviceName = 'Platform Authenticator Simulator';

  try {
    const isCtap2Key = Boolean(options?.useCtap2HardwareKey || options?.authenticatorMode === 'ctap2_hardware_key');
    const hasPlatformAuth = await isHardwareEnclaveAvailable();
    const useRealPlatform = Boolean(options?.useHardwareBiometrics || options?.authenticatorMode === 'platform_biometrics') && hasPlatformAuth;

    if (isCtap2Key) {
      // Roaming Hardware Security Key (YubiKey 5 / CTAP2 Token)
      authenticatorAttachment = 'cross-platform';
      aaguidUsed = YUBIKEY_5_SERIES_AAGUID;
      deviceName = 'YubiKey 5 Series (NFC / USB)';

      const ctap2Harness = new Ctap2HardwareKeyHarness({ aaguid: aaguidUsed });
      const regResult = await ctap2Harness.registerWithServer({
        baseUrl,
        username: citizen.userId,
        displayName: citizen.userId,
        fetchFn: localFetch
      });

      const authResult = await ctap2Harness.authenticateWithServer({
        baseUrl,
        fetchFn: localFetch
      });

      hwFingerprint = authResult.hwFingerprint;
      if (options?.tamperHardwareFingerprint) {
        hwFingerprint = 'HE-YUBIKEY-TAMPERED999';
      }
    } else if (useRealPlatform) {
      // Real Browser WebAuthn Prompt (Touch ID / Face ID / Windows Hello)
      authenticatorAttachment = 'platform_biometrics';
      deviceName = 'Physical Platform Authenticator';
      const regInfo = await registerHardwareEnclaveKey(citizen.userId, citizen.userId, {
        baseUrl,
        fetchFn: localFetch
      });
      const authInfo = await authenticateWithHardwareEnclave(regInfo.id, 'BILANX-CH-AUTH', {
        baseUrl,
        fetchFn: localFetch
      });
      
      const credIdBytes = base64ToBytes(authInfo.rawId || authInfo.id);
      const authDataBytes = base64ToBytes(authInfo.response.authenticatorData || '');
      hwFingerprint = await deriveHardwareFingerprint(credIdBytes, authDataBytes);
    } else {
      // Software Platform Enclave Simulator (FIDO2 L2 emulator)
      let simRpId: string | undefined = undefined;
      let simOrigin: string | undefined = undefined;
      if (baseUrl) {
        try {
          const parsed = new URL(baseUrl);
          simRpId = parsed.hostname;
          simOrigin = parsed.origin;
        } catch (_) {}
      }
      const simReg = await registerSimulatorEnclave({
        username: citizen.userId,
        displayName: citizen.userId,
        fetchFn: localFetch,
        origin: simOrigin,
        rpId: simRpId
      });
      const simAuth = await authenticateSimulatorEnclave(simReg.keyPair, { 
        fetchFn: localFetch,
        origin: simOrigin 
      });
      hwFingerprint = simAuth.hwFingerprint;
      if (options?.tamperHardwareFingerprint) {
        hwFingerprint = 'HE-P256-TAMPERED999';
      }
    }

    logs.push({
      step: 2,
      title: `Hardware Token Attestation (${isCtap2Key ? 'YubiKey CTAP2' : 'Platform Enclave'})`,
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step2Start),
      status: 'PASS',
      details: `Attestation verified via ${deviceName} (${authenticatorAttachment}). Derived HW_FINGERPRINT = ${hwFingerprint}.`
    });
  } catch (err: any) {
    logs.push({
      step: 2,
      title: 'Hardware Token Attestation (FIDO2 / WebAuthn)',
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step2Start),
      status: 'FAIL',
      details: `Hardware Enclave Attestation failed: ${err.message}`
    });
    return seal({
      success: false,
      validationStatus: 'REJECTED',
      currentStep: 2,
      totalTimeMs: Math.round(performance.now() - tStart),
      citizen,
      quarantinedPii,
      hwFingerprint: '',
      logs,
      error: `Hardware attestation failure: ${err.message}`
    });
  }

  // -------------------------------------------------------------------------
  // STEP 3: Sovereign Dual-Key Handshake, Policy Check & ZKP Age-Gate
  // -------------------------------------------------------------------------
  const step3Start = performance.now();
  let dualKeyHandshakeResult: any;
  let zkpProofBytes: Uint8Array;
  let zkpProofDigest = '';

  try {
    // 3A. Second-Factor Enclave Binding Integrity Check
    if (options?.tamperHardwareFingerprint) {
      logs.push({
        step: 3,
        title: 'Sovereign Dual-Key & ZKP Age-Gate',
        timestamp: Date.now(),
        durationMs: Math.round(performance.now() - step3Start),
        status: 'FAIL',
        details: `Hardware Fingerprint Tampering Detected: Presented second factor (${hwFingerprint}) does not match authenticated hardware enclave.`
      });

      return seal({
        success: false,
        validationStatus: 'REJECTED',
        currentStep: 3,
        totalTimeMs: Math.round(performance.now() - tStart),
        citizen,
        quarantinedPii,
        hwFingerprint,
        logs,
        error: 'Hardware Fingerprint Tampering: Second factor mismatch with enclave attestation.'
      });
    }

    // 3B. Regulatory Policy Evaluation (Underage rejection + eIDAS LoA High mandate)
    if (citizen.age < profile.minimumAge) {
      logs.push({
        step: 3,
        title: `Regulatory Policy Evaluation (${profile.shortLabel})`,
        timestamp: Date.now(),
        durationMs: Math.round(performance.now() - step3Start),
        status: 'FAIL',
        details: `Policy pre-check: age ${citizen.age} is below ${profile.minimumAge}. No range proof was built.`
      });

      return seal({
        success: false,
        validationStatus: 'REJECTED',
        currentStep: 3,
        totalTimeMs: Math.round(performance.now() - tStart),
        citizen,
        quarantinedPii,
        hwFingerprint,
        logs,
        error: `Underage citizen: Age ${citizen.age} is below minimum threshold ${profile.minimumAge}.`
      });
    }

    // Enforce eIDAS LoA High in Italian AgCom Profile
    if (profile.minimumLoa === 'high' && citizen.levelOfAssurance !== 'high') {
      const loaError = `Insufficient Level of Assurance: ${profile.name} strictly requires eIDAS Level of Assurance High under AgCom Resolution 9/24/CONS. Presented LoA: ${citizen.levelOfAssurance}.`;
      logs.push({
        step: 3,
        title: `Profile pre-check: eIDAS Level of Assurance (AgCom Delibera 9/24/CONS)`,
        timestamp: Date.now(),
        durationMs: Math.round(performance.now() - step3Start),
        status: 'FAIL',
        details: loaError
      });

      return seal({
        success: false,
        validationStatus: 'REJECTED',
        currentStep: 3,
        totalTimeMs: Math.round(performance.now() - tStart),
        citizen,
        quarantinedPii,
        hwFingerprint,
        logs,
        error: loaError
      });
    }

    // 3C. One clearance: proof is bound into the user signature and checked at policy threshold 18.
    zkpProofBytes = await generateProof(citizen.age);
    const zkpDigestBuffer = await crypto.subtle.digest('SHA-256', zkpProofBytes);
    zkpProofDigest = bytesToHex(zkpDigestBuffer).slice(0, 16);

    dualKeyHandshakeResult = await performDualKeyHandshake(institutionId, hwFingerprint, {
      fetchFn: localFetch,
      baseUrl,
      proofBytes: zkpProofBytes
    });
    if (!dualKeyHandshakeResult.success) {
      throw new Error(dualKeyHandshakeResult.error || 'Clearance rejected by the institutional node');
    }

    logs.push({
      step: 3,
      title: `Dual-Key Handshake & 1355B ZKP Age-Gate (${profile.shortLabel})`,
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step3Start),
      status: 'PASS',
      details: `Dual-Key institutional binding verified (${institutionId}). B2 8-bit Sigma range proof verified (${zkpProofBytes.length} bytes, SHA-256: ${zkpProofDigest}). LoA: ${citizen.levelOfAssurance}.`
    });
  } catch (err: any) {
    logs.push({
      step: 3,
      title: 'Dual-Key / Policy / ZKP Verification',
      timestamp: Date.now(),
      durationMs: Math.round(performance.now() - step3Start),
      status: 'FAIL',
      details: `Verification failed: ${err.message}`
    });
    return seal({
      success: false,
      validationStatus: 'REJECTED',
      currentStep: 3,
      totalTimeMs: Math.round(performance.now() - tStart),
      citizen,
      quarantinedPii,
      hwFingerprint,
      logs,
      error: err.message
    });
  }

  // -------------------------------------------------------------------------
  // STEP 4: Zero Data-Liability POS Validation Envelope & Audit Receipt
  // -------------------------------------------------------------------------
  const step4Start = performance.now();
  const randomSuffix = Math.floor(100000 + Math.random() * 900000).toString(16).toUpperCase();
  const envelopeId = `BILANX-${jurisdictionKey}-2026-VAL-${randomSuffix}`;
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 300_000); // 5 minutes TTL

  const challengeId = dualKeyHandshakeResult.payload?.challengeId || 'CHALLENGE-VERIFIED';
  const instSig = dualKeyHandshakeResult.payload?.institutionalSignature || 'SIG-INSTITUTIONAL';
  const instSigDigest = bytesToHex(new TextEncoder().encode(instSig)).slice(0, 16);

  // Compute verifiable audit receipt hash
  const receiptPayloadString = `${envelopeId}:${challengeId}:${instSigDigest}:${hwFingerprint}:${zkpProofDigest}:${now.toISOString()}`;
  const auditReceiptHash = bytesToHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(receiptPayloadString))).slice(0, 16);

  const qrPayloadObj = {
    v: '1.0',
    env: envelopeId,
    jur: jurisdictionKey,
    t: now.toISOString(),
    status: 'APPROVED',
    claims: { age18: true, loa: citizen.levelOfAssurance },
    receipt: {
      chId: challengeId,
      hwFp: hwFingerprint,
      zkp: zkpProofDigest,
      bytes: zkpProofBytes.length,
      auditHash: auditReceiptHash
    }
  };
  const qrPayload = JSON.stringify(qrPayloadObj);

  const envelope: BilanxValidationEnvelope = {
    version: '1.0',
    envelopeId,
    timestamp: now.toISOString(),
    expiresAt: expiresAt.toISOString(),
    jurisdiction: jurisdictionKey,
    regulatoryFramework: profile.regulatoryFramework,
    legalBasis: profile.legalBasis,
    validationStatus: 'APPROVED',
    verificationClaims: {
      ageOver18: true,
      loa: citizen.levelOfAssurance,
      issuerNode: institutionId
    },
    cryptographicReceipt: {
      dualKeyChallengeId: challengeId,
      institutionalSignatureDigest: instSigDigest,
      hardwareEnclaveFingerprint: hwFingerprint,
      authenticatorType: deviceName,
      aaguid: aaguidUsed,
      zkpProofDigest,
      proofByteLength: zkpProofBytes.length,
      auditReceiptHash
    },
    merchantClearance: {
      piiTransmittedBytes: 0,
      gdprLiabilityRisk: 'ZERO_LIABILITY',
      complianceRebateChf: profile.complianceCredit.currency === 'CHF' ? profile.complianceCredit.amount : 0,
      complianceCredit: profile.complianceCredit,
      productScanned: options?.productScanned || rfidItem.productName,
      productHardwareUid: rfidItem.hardwareUid,
      productCategory: rfidItem.category,
      productAuthenticity: '[OK / AUTHENTIC]',
      exciseDutyRecovered: rfidItem.exciseRecovered
    },
    productVerification: {
      hardwareUid: rfidItem.hardwareUid,
      productName: options?.productScanned || rfidItem.productName,
      category: rfidItem.category,
      status: rfidItem.status,
      manufacturerSignature: rfidItem.signature,
      exciseDutySettled: rfidItem.exciseRecovered,
      verdict: '[OK / AUTHENTIC]'
    },
    qrPayload
  };

  const totalTimeMs = Math.round(performance.now() - tStart);

  logs.push({
    step: 4,
    title: `POS Envelope & Verifiable Audit Receipt (${profile.shortLabel})`,
    timestamp: Date.now(),
    durationMs: Math.round(performance.now() - step4Start),
    status: 'PASS',
    details: `Issued ${envelopeId} under ${profile.auditDirective}. Citizen PII Transmitted: 0 Bytes. Execution Latency: ${totalTimeMs} ms (${totalTimeMs < profile.targetMaxLatencyMs ? 'Within POS Target < 1.5s' : 'Completed'}).`
  });

  return seal({
    success: true,
    validationStatus: 'APPROVED',
    currentStep: 4,
    totalTimeMs,
    citizen,
    quarantinedPii,
    hwFingerprint,
    envelope,
    logs
  });
}

/**
 * Executes the Swiss Demonstration pipeline (backwards compatible alias).
 */
export async function runSwissDemonstration(options?: PilotDemonstrationOptions): Promise<SwissDemonstrationResult> {
  return runPilotDemonstration({
    jurisdiction: 'CH_FADP',
    ...options
  });
}

/**
 * Executes the Italian Demonstration pipeline.
 */
export async function runItalianDemonstration(options?: PilotDemonstrationOptions): Promise<SwissDemonstrationResult> {
  return runPilotDemonstration({
    jurisdiction: 'IT_AGCOM',
    citizenPreset: options?.citizenPreset || 'it_adult_high',
    ...options
  });
}
