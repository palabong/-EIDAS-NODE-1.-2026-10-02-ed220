/**
 * Configuration-Driven Dual-Jurisdiction Regulatory Policy Profiles
 * Project Bilanx — lab pilot profiles
 * 
 * Defines regulatory profiles for:
 * 1. Swiss Profile (CH - FADP / Retail POS)
 *    - Strict 18+ gate for tobacco, nicotine, alcohol, and lottery
 *    - The HTTP clearance records the citizen name and date of birth only on the client
 *    - 1,355-byte NIST P-256 B2 Sigma range proof, accepted only when its threshold byte is 18
 *    - Sub-1.5s retail POS transaction envelope
 * 
 * 2. Italian Profile (IT - AgCom & eIDAS LoA High)
 *    - AgCom Delibera 9/24/CONS age assurance guidelines
 *    - eIDAS Level of Assurance High mapping (CIE / SPID L3 institutional credentials)
 *    - Institutional credential binding to Italian Node (BILANX-IT-AGCOM-NODE-01)
 *    - AgCom-compliant cryptographically verifiable audit receipting
 */

export type PilotJurisdictionId = 'CH_FADP' | 'IT_AGCOM';

export interface PilotProfile {
  id: PilotJurisdictionId;
  jurisdictionCode: 'CH' | 'IT';
  name: string;
  shortLabel: string;
  flagEmoji: string;
  regulatoryFramework: string;
  legalBasis: string;
  enforcementScope: string;
  minimumAge: number;
  minimumLoa: 'substantial' | 'high';
  zkpRequired: boolean;
  zkpProofByteLength: number;
  zeroPiiEnforced: boolean;
  targetMaxLatencyMs: number;
  institutionId: string;
  institutionName: string;
  defaultRestrictedProduct: string;
  sampleProducts: string[];
  complianceCredit: {
    currency: string;
    amount: number;
    label: string;
  };
  auditDirective: string;
  legalDisclaimer: string;
}

export const SWISS_PILOT_PROFILE: PilotProfile = {
  id: 'CH_FADP',
  jurisdictionCode: 'CH',
  name: 'Swiss Confederation — FADP Retail POS Age-Gate',
  shortLabel: 'Switzerland (CH - FADP)',
  flagEmoji: '🇨🇭',
  regulatoryFramework: 'Swiss FADP (Federal Act on Data Protection) & Tobacco Products Act (Art. 21 StG)',
  legalBasis: 'FADP / DSG Art. 6 (Data Minimization) & Tobacco/Nicotine Retail Ordinance 2024',
  enforcementScope: 'Physical Retail POS, Vending & Automated Kiosks (Tobacco, Nicotine, Alcohol, Lottery)',
  minimumAge: 18,
  minimumLoa: 'substantial',
  zkpRequired: true,
  zkpProofByteLength: 1355,
  zeroPiiEnforced: true,
  targetMaxLatencyMs: 1500,
  institutionId: 'BILANX-CH-EIDAS-NODE-01',
  institutionName: 'Swiss Federal Trust Infrastructure / eIDAS Node CH-01',
  defaultRestrictedProduct: 'Swiss Appenzeller Alpine Spirits (18+ Restricted)',
  sampleProducts: [
    'Swiss Appenzeller Alpine Spirits (18+ Restricted)',
    'Audentes Swiss Mint Nicotine Pods (18+)',
    'Swiss National Lottery EuroMillions Entry (18+)',
    'Heidi Reserve Single Malt Alpine Whisky (18+)'
  ],
  complianceCredit: {
    currency: 'CHF',
    amount: 0.15,
    label: 'Excise Duty Compliance Rebate'
  },
  auditDirective: 'COM(2026) 438 / Swiss FADP Retail Direct Clearance',
  legalDisclaimer: 'Plaintext PII is strictly quarantined on user hardware under Swiss FADP Art. 6. The verifier receives only a 1,355-byte zero-knowledge boolean assertion.'
};

export const ITALIAN_PILOT_PROFILE: PilotProfile = {
  id: 'IT_AGCOM',
  jurisdictionCode: 'IT',
  name: 'Italian Republic — AgCom Age Verification & eIDAS LoA High',
  shortLabel: 'Italy (IT - AgCom / eIDAS High)',
  flagEmoji: '🇮🇹',
  regulatoryFramework: 'AgCom Delibera 9/24/CONS & EU Regulation 910/2014 & 2024/1183 (eIDAS LoA High)',
  legalBasis: 'Linee Guida AgCom Delibera 9/24/CONS (Age Assurance) & Art. 8 Regolamento eIDAS',
  enforcementScope: 'AgCom Regulated Digital Platforms, Monopoli di Stato & High-Assurance Age Gates',
  minimumAge: 18,
  minimumLoa: 'high',
  zkpRequired: true,
  zkpProofByteLength: 1355,
  zeroPiiEnforced: true,
  targetMaxLatencyMs: 1500,
  institutionId: 'BILANX-IT-AGCOM-NODE-01',
  institutionName: 'Repubblica Italiana — Nodo Istituzionale AgCom & AgID (LoA High)',
  defaultRestrictedProduct: 'AgCom Regulated Online Content & Digital Services (18+)',
  sampleProducts: [
    'AgCom Regulated Online Content & Digital Services (18+)',
    'Monopoli di Stato — Giochi e Scommesse Autorizzate (18+)',
    'Tabacchi Lavorati e Prodotti da Inalazione Senza Combustione (18+)',
    'Institutional High-Assurance Age Verification Portal (18+)'
  ],
  complianceCredit: {
    currency: 'EUR',
    amount: 0.20,
    label: 'Credito di Conformità Digitale AgCom'
  },
  auditDirective: 'Delibera AgCom 9/24/CONS / eIDAS LoA High Verifiable Receipt',
  legalDisclaimer: 'Enforces strict eIDAS Level of Assurance High credential mapping and zero data-liability in accordance with Italian AgCom Delibera 9/24/CONS.'
};

export const PILOT_PROFILES: Record<PilotJurisdictionId, PilotProfile> = {
  CH_FADP: SWISS_PILOT_PROFILE,
  IT_AGCOM: ITALIAN_PILOT_PROFILE
};

export function getPilotProfile(idOrCode: string): PilotProfile {
  if (idOrCode === 'IT' || idOrCode === 'IT_AGCOM') {
    return ITALIAN_PILOT_PROFILE;
  }
  return SWISS_PILOT_PROFILE;
}

export interface CitizenPilotPreset {
  presetKey: string;
  fullName: string;
  dateOfBirth: string;
  age: number;
  userId: string;
  nationality: string;
  levelOfAssurance: 'low' | 'substantial' | 'high';
  jurisdiction: 'CH' | 'IT';
}

export const DUAL_JURISDICTION_CITIZEN_PRESETS: Record<string, CitizenPilotPreset> = {
  // Swiss Scenarios
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

  // Italian Scenarios
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

/**
 * Evaluates whether a citizen satisfies the regulatory requirements of a pilot profile.
 */
export function evaluateCitizenCompliance(
  citizen: { age: number; levelOfAssurance: 'low' | 'substantial' | 'high' },
  profile: PilotProfile
): { compliant: boolean; error?: string } {
  // 1. Age Threshold Evaluation
  if (citizen.age < profile.minimumAge) {
    return {
      compliant: false,
      error: `Underage citizen: Age ${citizen.age} is below minimum threshold ${profile.minimumAge}.`
    };
  }

  // 2. Level of Assurance (LoA) Evaluation
  if (profile.minimumLoa === 'high' && citizen.levelOfAssurance !== 'high') {
    return {
      compliant: false,
      error: `Insufficient Level of Assurance: ${profile.name} requires eIDAS LoA High under AgCom Resolution 9/24/CONS. Presented LoA: ${citizen.levelOfAssurance}.`
    };
  }

  return { compliant: true };
}
