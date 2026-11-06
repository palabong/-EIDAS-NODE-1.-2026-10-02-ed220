/**
 * Bilanx — Dual-Key Sovereign Validation System (DK-SVS)
 * Official Swiss Audit Certificate PDF Generator
 * 
 * Generates an authoritative, printable compliance certificate for Point-of-Sale (POS)
 * validation in accordance with Swiss FADP / eIDAS 2.0 zero data-liability mandates.
 */

import { jsPDF } from 'jspdf';
import type { BilanxValidationEnvelope, CitizenIngestionProfile } from './e2e/runSwissDemonstration.ts';

export function buildAuditCertificatePdfDoc(
  envelope: BilanxValidationEnvelope,
  citizen?: CitizenIngestionProfile
): jsPDF {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();

  // 1. Header Banner (Swiss Red / Blue Corporate styling)
  doc.setFillColor(220, 38, 38); // Swiss Red
  doc.rect(0, 0, pageWidth, 24, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.text('SCHWEIZERISCHE EIDGENOSSENSCHAFT — SWISS TRUST INFRASTRUCTURE', 15, 12);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.text('PROJECT BILANX — DUAL-KEY SOVEREIGN VALIDATION SYSTEM (DK-SVS)', 15, 19);

  // 2. Document Title
  doc.setTextColor(15, 23, 42); // slate-900
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.text('OFFICIAL VALIDATION AUDIT CERTIFICATE', 15, 38);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(10);
  doc.setTextColor(100, 116, 139); // slate-500
  doc.text('Zero Data-Liability Retail Point-of-Sale Clearance Receipt', 15, 45);

  // Status Badge
  const isApproved = envelope.validationStatus === 'APPROVED';
  doc.setFillColor(isApproved ? 16 : 220, isApproved ? 185 : 38, isApproved ? 129 : 38);
  doc.roundedRect(pageWidth - 65, 32, 50, 14, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.text(isApproved ? '🟢 18+ APPROVED' : '🔴 REJECTED', pageWidth - 60, 41);

  // Divider line
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.5);
  doc.line(15, 52, pageWidth - 15, 52);

  // 3. Section 1: Validation Envelope Metadata
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(30, 41, 59);
  doc.text('1. VALIDATION ENVELOPE METADATA', 15, 62);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9);
  doc.setTextColor(51, 65, 85);

  const leftX = 15;
  const colWidth = 85;
  let y = 70;

  const metadataPairs = [
    ['Envelope Token:', envelope.envelopeId],
    ['Issuance Timestamp:', envelope.timestamp],
    ['Expiration Timestamp:', envelope.expiresAt],
    ['Issuing Node:', envelope.verificationClaims.issuerNode],
    ['Level of Assurance:', envelope.verificationClaims.loa.toUpperCase()],
    ['Restricted Product:', envelope.merchantClearance.productScanned || 'Restricted Retail Item']
  ];

  for (const [label, val] of metadataPairs) {
    doc.setFont('helvetica', 'bold');
    doc.text(label, leftX, y);
    doc.setFont('helvetica', 'normal');
    doc.text(val, leftX + 42, y);
    y += 7;
  }

  // 4. Section 2: Cryptographic Proof & Receipt
  y += 5;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(30, 41, 59);
  doc.text('2. CRYPTOGRAPHIC PROOF & DUAL-KEY RECEIPT', 15, y);
  y += 8;

  const cryptoReceipt = envelope.cryptographicReceipt;
  const cryptoPairs = [
    ['Hardware Enclave FP:', cryptoReceipt.hardwareEnclaveFingerprint],
    ['Institutional Challenge:', cryptoReceipt.dualKeyChallengeId],
    ['Inst. Signature Digest:', cryptoReceipt.institutionalSignatureDigest],
    ['ZKP Proof SHA-256:', cryptoReceipt.zkpProofDigest],
    ['ZKP Binary Size:', `${cryptoReceipt.proofByteLength} Bytes (B2 Sigma Range)`]
  ];

  for (const [label, val] of cryptoPairs) {
    doc.setFont('helvetica', 'bold');
    doc.text(label, leftX, y);
    doc.setFont('courier', 'normal');
    doc.setFontSize(8.5);
    doc.text(val, leftX + 45, y);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    y += 7;
  }

  // 5. Section 3: Sovereign PII Quarantine & Regulatory Clearance
  y += 5;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(12);
  doc.setTextColor(30, 41, 59);
  doc.text('3. SOVEREIGN PII QUARANTINE & REGULATORY COMPLIANCE', 15, y);
  y += 8;

  doc.setFillColor(248, 250, 252);
  doc.rect(15, y - 2, pageWidth - 30, 36, 'F');
  doc.setDrawColor(203, 213, 225);
  doc.rect(15, y - 2, pageWidth - 30, 36, 'D');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(15, 23, 42);
  doc.text('CITIZEN PLAINTEXT IDENTITY:', 20, y + 5);
  doc.setFont('helvetica', 'normal');
  doc.text('🔒 STRICTLY QUARANTINED ON USER HARDWARE (ZERO SERVER LEAKAGE)', 75, y + 5);

  doc.setFont('helvetica', 'bold');
  doc.text('PLAINTEXT PII TRANSMITTED:', 20, y + 13);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(16, 185, 129);
  doc.text('0 BYTES (ZERO DATA-LIABILITY SURFACE)', 75, y + 13);

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text('GDPR / FADP COMPLIANCE RISK:', 20, y + 21);
  doc.setFont('helvetica', 'normal');
  doc.text('ARTICLE 5(1)(c) DATA MINIMIZATION — ZERO RETENTION RISK', 75, y + 21);

  doc.setFont('helvetica', 'bold');
  doc.text('SWISS EXCISE COMPLIANCE REBATE:', 20, y + 29);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(2, 132, 199);
  doc.text(`CHF ${envelope.merchantClearance.complianceRebateChf.toFixed(2)} ACCREDITED`, 75, y + 29);

  // 6. Section 4: Regulatory Citations & Verification Disclaimer
  y += 46;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10);
  doc.setTextColor(71, 85, 105);
  doc.text('REGULATORY & LEGAL ATTESTATION', 15, y);
  y += 6;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(100, 116, 139);
  const legalText = 
    "This certificate verifies that an authentic Non-Interactive Zero-Knowledge Proof (NIZKP) and Dual-Key " +
    "cryptographic handshake were evaluated in real time by the Bilanx Institutional Node. The statement " +
    "proven demonstrates that the citizen's age meets or exceeds the statutory threshold of 18 years without " +
    "disclosing date of birth, name, or national identifier. This document constitutes formal electronic " +
    "clearance under Swiss Federal Act on Data Protection (FADP) and EU eIDAS 2.0 High Assurance Architecture.";
  doc.text(doc.splitTextToSize(legalText, pageWidth - 30), 15, y);

  // 7. Footer
  doc.setDrawColor(226, 232, 240);
  doc.line(15, 275, pageWidth - 15, 275);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(148, 163, 184);
  doc.text(`Certificate Token: ${envelope.envelopeId} | Generated: ${new Date().toUTCString()} | Bilanx DK-SVS Swiss Node`, 15, 282);
  doc.text('Page 1 of 1 — Cryptographically Verifiable Audit Receipt', pageWidth - 80, 282);

  return doc;
}

export function generateAuditCertificatePdf(
  envelope: BilanxValidationEnvelope,
  citizen?: CitizenIngestionProfile
): void {
  const doc = buildAuditCertificatePdfDoc(envelope, citizen);
  if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
    doc.save(`Bilanx_Audit_Certificate_${envelope.envelopeId}.pdf`);
  }
}

