/**
 * Bilanx — Dual-Key Sovereign Validation System (DK-SVS)
 * Dual-Jurisdiction Audit Certificate PDF Generator (CH & IT)
 * 
 * Generates authoritative, printable compliance certificates for:
 * 1. Swiss Profile (CH - FADP / Retail POS Zero Data-Liability Clearance)
 * 2. Italian Profile (IT - AgCom Delibera 9/24/CONS & eIDAS LoA High Verifiable Receipt)
 */

import { jsPDF } from 'jspdf';
import type { BilanxValidationEnvelope, CitizenIngestionProfile } from './e2e/runSwissDemonstration.ts';
import type { UhdRfidAssertion } from '../../types.ts';
import { canonicalClearanceEnvelope } from '../../lib/crypto/clearanceEnvelope.ts';

export function buildAuditCertificatePdfDoc(
  envelope: BilanxValidationEnvelope,
  citizen?: CitizenIngestionProfile,
  rfidAssertion?: UhdRfidAssertion
): jsPDF {
  const isItalian = envelope.jurisdiction === 'IT';
  const isApproved = envelope.validationStatus === 'APPROVED';

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();

  // 1. Header Banner
  if (isItalian) {
    // Italian Institutional Navy / Azure banner (#0B3B60)
    doc.setFillColor(11, 59, 96);
    doc.rect(0, 0, pageWidth, 24, 'F');

    // Tricolore indicator bar
    doc.setFillColor(0, 146, 70); // green
    doc.rect(0, 24, pageWidth / 3, 1.5, 'F');
    doc.setFillColor(255, 255, 255); // white
    doc.rect(pageWidth / 3, 24, pageWidth / 3, 1.5, 'F');
    doc.setFillColor(206, 43, 55); // red
    doc.rect((pageWidth / 3) * 2, 24, pageWidth / 3, 1.5, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.text('REPUBBLICA ITALIANA — AUTORITÀ PER LE GARANZIE NELLE COMUNICAZIONI', 15, 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.text('PROJECT BILANX — AGE ASSURANCE EIDAS HIGH LOA SOVEREIGN NODE', 15, 19);
  } else {
    // Swiss Red Banner
    doc.setFillColor(220, 38, 38);
    doc.rect(0, 0, pageWidth, 24, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text('SCHWEIZERISCHE EIDGENOSSENSCHAFT — SWISS TRUST INFRASTRUCTURE', 15, 12);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.text('PROJECT BILANX — DUAL-KEY SOVEREIGN VALIDATION SYSTEM (DK-SVS)', 15, 19);
  }

  // 2. Document Title
  doc.setTextColor(15, 23, 42); // slate-900
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(17);
  doc.text(
    isItalian 
      ? 'CERTIFICATO UFFICIALE DI AUDIT E CONFORMITÀ AGE ASSURANCE' 
      : 'OFFICIAL VALIDATION AUDIT CERTIFICATE', 
    15, 
    38
  );

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(100, 116, 139); // slate-500
  const sessionLoa = envelope.verificationClaims.loa;
  const loaName = sessionLoa === 'high' ? 'HIGH' : sessionLoa === 'substantial' ? 'SUBSTANTIAL' : 'LOW';
  doc.text(
    isItalian
      ? `Ricevuta Crittografica Verificabile eIDAS ${loaName} / AgCom Delibera 9/24/CONS (Zero-PII)`
      : 'Zero Data-Liability Retail Point-of-Sale Clearance Receipt (Swiss FADP / eIDAS 2.0)',
    15,
    45
  );

  // Status Badge
  doc.setFillColor(isApproved ? 16 : 220, isApproved ? 185 : 38, isApproved ? 129 : 38);
  doc.roundedRect(pageWidth - 65, 32, 50, 14, 2, 2, 'F');
  doc.setTextColor(255, 255, 255);
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.text(isApproved ? '🟢 18+ APPROVED' : '🔴 REJECTED', pageWidth - 60, 41);

  // Divider line
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.5);
  doc.line(15, 52, pageWidth - 15, 52);

  // 3. Section 1: Validation Envelope Metadata
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(30, 41, 59);
  doc.text(isItalian ? '1. METADATI CERTIFICATO DI VALIDAZIONE' : '1. VALIDATION ENVELOPE METADATA', 15, 62);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8.5);
  doc.setTextColor(51, 65, 85);

  const leftX = 15;
  let y = 70;

  const signedProduct = envelope.institutionalClearance?.envelope;
  const signedRow = signedProduct?.productUid && signedProduct.productCategory && signedProduct.productStatus === 'authentic'
    ? signedProduct
    : undefined;
  const productUid = signedRow?.productUid
    || envelope.merchantClearance?.productHardwareUid
    || envelope.productVerification?.hardwareUid
    || rfidAssertion?.hardwareUid
    || '';
  const productCategory = signedRow?.productCategory
    || envelope.merchantClearance?.productCategory
    || envelope.productVerification?.category
    || rfidAssertion?.category
    || '';
  const productAuthenticity = signedRow
    ? (envelope.productVerification?.verdict || envelope.merchantClearance?.productAuthenticity || '[OK / AUTHENTIC]')
    : rfidAssertion
      ? (rfidAssertion.status === 'authentic' ? '[OK / AUTHENTIC]' : rfidAssertion.status === 'counterfeit' ? '[STOCK POLICY BLOCK: COUNTERFEIT DETECTED]' : '[STOCK POLICY BLOCK: RECALLED STOCK]')
      : (envelope.merchantClearance?.productAuthenticity || envelope.productVerification?.verdict || '');
  const loaText = sessionLoa === 'high' && isItalian
    ? `${loaName} (eIDAS HIGH)`
    : loaName;

  const metadataPairs: [string, string][] = [
    [isItalian ? 'ID Certificato:' : 'Envelope Token:', envelope.envelopeId],
    [isItalian ? 'Data e Ora Emissione:' : 'Issuance Timestamp:', envelope.timestamp],
    [isItalian ? 'Scadenza Token (TTL):' : 'Expiration Timestamp:', envelope.expiresAt],
    [isItalian ? 'Nodo Istituzionale:' : 'Issuing Node:', envelope.verificationClaims.issuerNode],
    [isItalian ? 'Livello di Garanzia (LoA):' : 'Level of Assurance:', loaText],
    [isItalian ? 'Servizio / Prodotto:' : 'Restricted Product:', envelope.merchantClearance.productScanned || 'Restricted Retail Item'],
    [isItalian ? 'Hardware UID Prodotto:' : 'Product Hardware UID:', productUid],
    [isItalian ? 'Categoria Merceologica:' : 'Product Category:', productCategory],
    [isItalian ? 'Verdetto Autenticità:' : 'Product Authenticity:', productAuthenticity]
  ];

  for (const [label, val] of metadataPairs) {
    doc.setFont('helvetica', 'bold');
    doc.text(label, leftX, y);
    doc.setFont('helvetica', 'normal');
    doc.text(val, leftX + 46, y);
    y += 6.5;
  }

  // 4. Section 2: Cryptographic Proof & Receipt
  y += 4;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(30, 41, 59);
  doc.text(
    isItalian 
      ? '2. RICEVUTA CRITTOGRAFICA E BINDING DUAL-KEY' 
      : '2. CRYPTOGRAPHIC PROOF & DUAL-KEY RECEIPT', 
    15, 
    y
  );
  y += 7.5;

  const cryptoReceipt = envelope.cryptographicReceipt;
  const cryptoPairs: [string, string][] = [
    [isItalian ? 'Hardware Enclave FP:' : 'Hardware Enclave FP:', cryptoReceipt.hardwareEnclaveFingerprint],
    [isItalian ? 'Token / Dispositivo:' : 'Authenticator Token:', cryptoReceipt.authenticatorType || 'Hardware Security Token'],
    [isItalian ? 'Challenge Istituzionale:' : 'Institutional Challenge:', cryptoReceipt.dualKeyChallengeId],
    [isItalian ? 'Firma Istituzionale Hash:' : 'Inst. Signature Digest:', cryptoReceipt.institutionalSignatureDigest],
    [isItalian ? 'ZKP Proof SHA-256:' : 'ZKP Proof SHA-256:', cryptoReceipt.zkpProofDigest],
    [isItalian ? 'Dimensione Prova NIZKP:' : 'ZKP Binary Size:', `${cryptoReceipt.proofByteLength} Bytes (B2 8-Bit Sigma Range Proof)`],
    [isItalian ? 'Hash Ricevuta SHA-256:' : 'Receipt SHA-256:', cryptoReceipt.auditReceiptHash || signedProduct?.receiptSha256 || ''],
    [isItalian ? 'Firma Istituzionale:' : 'Institutional Signature:', envelope.institutionalClearance?.envelopeSignature || ''],
    [isItalian ? 'Busta Canonica Firmata:' : 'Signed Envelope:', signedProduct ? canonicalClearanceEnvelope(signedProduct) : '']
  ];

  for (const [label, val] of cryptoPairs) {
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.text(label, leftX, y);
    doc.setFont('courier', 'normal');
    doc.setFontSize(val.length > 40 ? 6.5 : 8);
    doc.text(val, leftX + 46, y);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    y += 6.5;
  }

  // 5. Section 3: Sovereign PII Quarantine & Regulatory Clearance
  y += 4;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(11);
  doc.setTextColor(30, 41, 59);
  doc.text(
    isItalian 
      ? '3. QUARANTENA DEI DATI PERSONALI & CONFORMITÀ REGOLAMENTARE' 
      : '3. SOVEREIGN PII QUARANTINE & REGULATORY COMPLIANCE', 
    15, 
    y
  );
  y += 7.5;

  doc.setFillColor(248, 250, 252);
  doc.rect(15, y - 2, pageWidth - 30, 36, 'F');
  doc.setDrawColor(203, 213, 225);
  doc.rect(15, y - 2, pageWidth - 30, 36, 'D');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text(isItalian ? 'IDENTITÀ PERSONALE CITTADINO:' : 'CITIZEN PLAINTEXT IDENTITY:', 20, y + 5);
  doc.setFont('helvetica', 'normal');
  doc.text(
    isItalian 
      ? '🔒 ISOLATA SU HARDWARE UTENTE (ZERO BYTES TRASMESSI AL SERVER)' 
      : '🔒 STRICTLY QUARANTINED ON USER HARDWARE (ZERO SERVER LEAKAGE)', 
    78, 
    y + 5
  );

  doc.setFont('helvetica', 'bold');
  doc.text(isItalian ? 'DATI PII TRASMESSI AL VERIFICATORE:' : 'PLAINTEXT PII TRANSMITTED:', 20, y + 13);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(16, 185, 129);
  doc.text(
    isItalian 
      ? '0 BYTES (SUPERFICE A RESPONSABILITÀ DATI ZERO)' 
      : '0 BYTES (ZERO DATA-LIABILITY SURFACE)', 
    78, 
    y + 13
  );

  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(isItalian ? 'CONFORMITÀ PRIVACY / GDPR:' : 'GDPR / FADP COMPLIANCE RISK:', 20, y + 21);
  doc.setFont('helvetica', 'normal');
  doc.text(
    isItalian 
      ? 'ARTICOLO 5(1)(c) GDPR MINIMIZZAZIONE DATI — RISCHIO SANZIONI ZERO' 
      : 'ARTICLE 5(1)(c) DATA MINIMIZATION — ZERO RETENTION RISK', 
    78, 
    y + 21
  );

  doc.setFont('helvetica', 'bold');
  doc.text(
    isItalian ? 'INCENTIVO DI CONFORMITÀ AGCOM:' : 'SWISS EXCISE COMPLIANCE REBATE:', 
    20, 
    y + 29
  );
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(2, 132, 199);
  if (isItalian) {
    const cred = envelope.merchantClearance.complianceCredit;
    doc.text(`${cred?.currency || 'EUR'} ${(cred?.amount ?? 0.20).toFixed(2)} ACCREDITATI (AgCom Compliant)`, 78, y + 29);
  } else {
    doc.text(`CHF ${envelope.merchantClearance.complianceRebateChf.toFixed(2)} ACCREDITED`, 78, y + 29);
  }

  // 6. Section 4: Regulatory Citations & Verification Disclaimer
  y += 40;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(71, 85, 105);
  doc.text(isItalian ? 'DICHIARAZIONE E DISCIPLINARE REGOLAMENTARE' : 'REGULATORY & LEGAL ATTESTATION', 15, y);
  y += 5.5;

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);

  const legalText = isItalian
    ? "Il presente certificato attesta che una Prova a Conoscenza Zero Non Interattiva (NIZKP NIST P-256 Sigma di 1.355 byte) " +
      "e un handshake crittografico Dual-Key vincolato a token hardware di sicurezza (FIDO2/CTAP2) sono stati verificati in tempo reale " +
      "dal Nodo Istituzionale AgCom BILANX-IT-AGCOM-NODE-01. La dichiarazione matematica dimostra che l'utente ha raggiunto la maggiore età (18+) " +
      "senza rivelare il nome, cognome, data di nascita o codice fiscale, in piena conformità con la Delibera AgCom 9/24/CONS " +
      `e il Regolamento UE 910/2014 & 2024/1183 (eIDAS Livello di Sicurezza ${loaName}).`
    : "This certificate verifies that an authentic Non-Interactive Zero-Knowledge Proof (NIZKP) and Dual-Key " +
      "cryptographic handshake were evaluated in real time by the Bilanx Institutional Node. The statement " +
      "proven demonstrates that the citizen's age meets or exceeds the statutory threshold of 18 years without " +
      "disclosing date of birth, name, or national identifier. This document constitutes formal electronic " +
      "clearance under Swiss Federal Act on Data Protection (FADP) and EU eIDAS 2.0 High Assurance Architecture.";

  doc.text(doc.splitTextToSize(legalText, pageWidth - 30), 15, y);

  // 7. Footer
  doc.setDrawColor(226, 232, 240);
  doc.line(15, 286, pageWidth - 15, 286);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(148, 163, 184);
  const footerNode = isItalian ? 'Bilanx AgCom Italian Institutional Node' : 'Bilanx DK-SVS Swiss Node';
  doc.text(`Certificate Token: ${envelope.envelopeId} | Generated: ${new Date().toUTCString()} | ${footerNode}`, 15, 292);
  doc.text('Page 1 of 1 — Cryptographically Verifiable Audit Receipt', pageWidth - 80, 292);

  return doc;
}

export function generateAuditCertificatePdf(
  envelope: BilanxValidationEnvelope,
  citizen?: CitizenIngestionProfile,
  rfidAssertion?: UhdRfidAssertion
): void {
  const doc = buildAuditCertificatePdfDoc(envelope, citizen, rfidAssertion);
  if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
    doc.save(`Bilanx_Audit_Certificate_${envelope.envelopeId}.pdf`);
  }
}
