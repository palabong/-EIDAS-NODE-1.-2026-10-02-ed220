/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface UserProfile {
  name: string;
  role: string;
  bio: string;
  avatar: string;
  email: string;
  company: string;
  licenseNumber: string;
  verificationRate: string; // e.g. "99.8%" vs. standard "20%"
}

export interface ThemeConfig {
  mode: 'light' | 'dark';
  primaryColor: string; // Deep Navy Blue (#1E3A8A)
  highlightColor: string; // Emerald Green (#10B981)
}

export interface PortfolioItem {
  id: string;
  title: string;
  description: string;
  category: 'Age Gate' | 'Identification' | 'Compliance Audit' | 'Digital Signature';
  status: 'active' | 'under_review' | 'certified' | 'revoked';
  efficacyRate: number; // percentage of age checks successfully blocking underage access (e.g., standard checks are 20%, high-tech checks are 99.8%)
  techStack: string[];
  externalUrl?: string;
  complianceDocLink?: string;
  lastAudited: string;
}

export interface ScreeningTicket {
  id: string;
  name: string;
  submittedAt: string;
  userAge: number;
  assertionType: 'tobacco' | 'alcohol' | 'gaming' | 'adult_goods';
  status: 'pending' | 'passed' | 'failed' | 'requires_manual_audit';
  documentType: 'eID' | 'Biometric Face-Scan' | 'Youth Card' | 'Self-Declaration';
  selfDeclarationValue: boolean; // Yes/No
  scannedResultScore: number; // 0-100 indicating trustworthiness of the verification (e.g. Self-Decl yields 20%, Face Sync yields 99.5%)
  metadataJson: string; // LD+JSON or compliance payload
  evaluationNotes?: string;
  region: string;
}

// Dual-Key Sovereign Validation System (DK-SVS) types
export interface DKProduct {
  id: string;
  name: string;
  category: 'Tobacco' | 'Alcohol' | 'Vaporizer' | 'Cannabinoids' | 'Restricted Hardware';
  price: number;
  uid: string;
  status: 'authentic' | 'counterfeit' | 'recalled' | 'unregistered';
  manufacturerSign: string;
}

export interface DKWallet {
  id: string;
  holderClass: 'Adult Verified' | 'Minor Detected' | 'Unsigned Local Profile' | 'Foreign eID';
  ageGroup: 'Over 18' | 'Under 18';
  cryptoSignature: string;
  country: string;
  validAssertion: boolean;
}

export interface EidasAssertion {
  id: string;
  timestamp: string;
  issuer: string;
  subjectId: string;
  transactionId: string;
  loa: 'substantial' | 'high' | 'low';
  attributes: {
    ageOver18: boolean;
    productAuthentic: boolean;
  };
  signature: string;
}

export interface ZKALogEntry {
  id: string;
  timestamp: string;
  operation: string;
  encryptedHash: string;
  ageVerified: boolean;
  hardwareUid: string;
  hardwareStatus: 'VERIFIED' | 'INVALID_REVOKED' | 'COUNTERFEIT_DETECTED' | 'UNREGISTERED';
  resultStatus: 'APPROVED' | 'REJECTED_UNDERAGE' | 'REJECTED_COUNTERFEIT' | 'REJECTED_BOTH';
  productName: string;
  retailerRebate: number;
}

export interface UhdRfidAssertion {
  id: string;
  timestamp: string;
  hardwareUid: string;
  productName: string;
  category: 'Tobacco' | 'Alcohol' | 'Vaporizer' | 'Cannabinoids' | 'Restricted Hardware';
  status: 'authentic' | 'counterfeit' | 'recalled' | 'unregistered';
  hmacSha256: string;
  tagsRead: number;
  rssi: number;
  collisions: number;
  issuer: string;
  exciseRecovered: number;
  signature: string;
}


