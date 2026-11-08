/**
 * Short-TTL clearance envelope signed by the institutional key.
 * The signed bytes are the canonical JSON of the allow-listed fields.
 * Names, dates of birth, and raw proofs are not fields of this object.
 */

import { bytesToBase64, base64ToBytes, bytesToHex } from './encoding.ts';

export const CLEARANCE_ENVELOPE_TTL_MS = 5 * 60 * 1000;

export const CLEARANCE_PRODUCT_CATEGORIES = [
  'Tobacco',
  'Alcohol',
  'Vaporizer',
  'Cannabinoids',
  'Restricted Hardware',
] as const;

export type ClearanceProductCategory = (typeof CLEARANCE_PRODUCT_CATEGORIES)[number];

export interface ClearanceEnvelope {
  v: 1;
  keyId: string;
  jurisdiction: 'CH' | 'IT';
  /** True only after a resolved session passed the age gate. Numeric age is not a field. */
  sessionAgeGatePassed: true;
  /**
   * Italian LoA High policy result.
   * True only on an IT envelope, after the session LoA was High.
   * False on CH, where that rule is not applied.
   */
  loaHigh: boolean;
  proofSha256: string;
  secondFactorHash: string;
  iat: number;
  exp: number;
  ageOver18: true;
  /** Full SHA-256 of the canonical receipt. The institutional signature covers this field. */
  receiptSha256: string;
  /**
   * True only for a retail sale bound to a catalog row.
   * An age-only clearance is false and carries no product or excise.
   */
  retailSale: boolean;
  /** Present together only after the server verified an authentic catalog row. */
  productUid?: string;
  productCategory?: ClearanceProductCategory;
  productStatus?: 'authentic';
  /** Excise from the catalog row the server trusts. Present only on a retail sale. */
  excise?: number;
}

export type ClearanceEnvelopeFailure = 'unsigned' | 'malformed' | 'signature_rejected' | 'expired';

const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' } as const;

/** Receipt bytes a till can recompute without the client POS wrapper. No names or dates of birth. */
export function canonicalReceiptMaterial(envelope: {
  proofSha256: string;
  secondFactorHash: string;
  jurisdiction: string;
  productUid?: string;
  productCategory?: string;
  productStatus?: string;
}): string {
  const product = envelope.productUid
    ? `|${envelope.productUid}|${envelope.productCategory}|${envelope.productStatus}`
    : '';
  return `${envelope.proofSha256}|${envelope.secondFactorHash}|${envelope.jurisdiction}${product}`;
}

export async function receiptSha256Hex(envelope: {
  proofSha256: string;
  secondFactorHash: string;
  jurisdiction: string;
  productUid?: string;
  productCategory?: string;
  productStatus?: string;
}): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalReceiptMaterial(envelope))
  );
  return bytesToHex(new Uint8Array(digest));
}

/** Till QR. The envelope field is the exact signed canonical JSON string. */
export interface TillClearanceArtifact {
  v: 1;
  envelope: string;
  envelopeSignature: string;
}

function parseJson(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function tillClearanceArtifact(
  envelope: ClearanceEnvelope,
  envelopeSignature: string
): TillClearanceArtifact {
  return {
    v: 1,
    envelope: canonicalClearanceEnvelope(envelope),
    envelopeSignature,
  };
}

/** Accepts the QR JSON string or the parsed artifact. Extra fields are rejected. */
export function readTillClearanceArtifact(value: unknown): TillClearanceArtifact | null {
  const body = typeof value === 'string' ? parseJson(value) : value;
  if (!body || typeof body !== 'object') return null;
  const record = body as Record<string, unknown>;
  if (record.v !== 1) return null;
  if (typeof record.envelope !== 'string' || record.envelope.length === 0) return null;
  if (typeof record.envelopeSignature !== 'string' || record.envelopeSignature.length === 0) return null;
  const extra = Object.keys(record).some((key) => key !== 'v' && key !== 'envelope' && key !== 'envelopeSignature');
  if (extra) return null;
  if (!readClearanceEnvelope(parseJson(record.envelope))) return null;
  return { v: 1, envelope: record.envelope, envelopeSignature: record.envelopeSignature };
}

export function canonicalClearanceEnvelope(envelope: ClearanceEnvelope): string {
  const body: Record<string, unknown> = {
    v: envelope.v,
    keyId: envelope.keyId,
    jurisdiction: envelope.jurisdiction,
    sessionAgeGatePassed: envelope.sessionAgeGatePassed,
    loaHigh: envelope.loaHigh,
    proofSha256: envelope.proofSha256,
    secondFactorHash: envelope.secondFactorHash,
    iat: envelope.iat,
    exp: envelope.exp,
    ageOver18: envelope.ageOver18,
    receiptSha256: envelope.receiptSha256,
    retailSale: envelope.retailSale,
  };
  if (envelope.retailSale) {
    body.productUid = envelope.productUid;
    body.productCategory = envelope.productCategory;
    body.productStatus = envelope.productStatus;
    body.excise = envelope.excise;
  }
  return JSON.stringify(body);
}

function isProductCategory(value: unknown): value is ClearanceProductCategory {
  return typeof value === 'string' && (CLEARANCE_PRODUCT_CATEGORIES as readonly string[]).includes(value);
}

export function readClearanceEnvelope(value: unknown): ClearanceEnvelope | null {
  if (!value || typeof value !== 'object') return null;
  const body = value as Record<string, unknown>;
  if (body.v !== 1) return null;
  if (body.ageOver18 !== true) return null;
  if (body.sessionAgeGatePassed !== true) return null;
  if (body.jurisdiction !== 'CH' && body.jurisdiction !== 'IT') return null;
  if (body.loaHigh !== (body.jurisdiction === 'IT')) return null;
  if (typeof body.keyId !== 'string' || body.keyId.length === 0) return null;
  if (typeof body.proofSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(body.proofSha256)) return null;
  if (typeof body.secondFactorHash !== 'string' || body.secondFactorHash.length === 0) return null;
  if (typeof body.receiptSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(body.receiptSha256)) return null;
  if (typeof body.iat !== 'number' || !Number.isFinite(body.iat)) return null;
  if (typeof body.exp !== 'number' || !Number.isFinite(body.exp)) return null;
  if (typeof body.retailSale !== 'boolean') return null;
  const keys = Object.keys(body);
  const allowed = new Set([
    'v', 'keyId', 'jurisdiction', 'sessionAgeGatePassed', 'loaHigh',
    'proofSha256', 'secondFactorHash', 'iat', 'exp', 'ageOver18',
    'receiptSha256', 'retailSale', 'productUid', 'productCategory', 'productStatus', 'excise',
  ]);
  if (keys.some((key) => !allowed.has(key))) return null;
  const saleKeys = ['productUid', 'productCategory', 'productStatus', 'excise'];
  const hasSaleField = saleKeys.some((key) => Object.prototype.hasOwnProperty.call(body, key));
  if (body.retailSale === true) {
    if (typeof body.productUid !== 'string' || body.productUid.length === 0) return null;
    if (!isProductCategory(body.productCategory)) return null;
    if (body.productStatus !== 'authentic') return null;
    if (typeof body.excise !== 'number' || !Number.isFinite(body.excise) || body.excise < 0) return null;
  } else if (hasSaleField) {
    return null;
  }
  const envelope: ClearanceEnvelope = {
    v: 1,
    keyId: body.keyId,
    jurisdiction: body.jurisdiction,
    sessionAgeGatePassed: true,
    loaHigh: body.jurisdiction === 'IT',
    proofSha256: body.proofSha256,
    secondFactorHash: body.secondFactorHash,
    iat: body.iat,
    exp: body.exp,
    ageOver18: true,
    receiptSha256: body.receiptSha256,
    retailSale: body.retailSale,
  };
  if (body.retailSale === true && typeof body.productUid === 'string' && isProductCategory(body.productCategory) && typeof body.excise === 'number') {
    envelope.productUid = body.productUid;
    envelope.productCategory = body.productCategory;
    envelope.productStatus = 'authentic';
    envelope.excise = body.excise;
  }
  return envelope;
}

/** A till accepts a sale only when the signed envelope says so and names the catalog excise. */
export function acceptRetailSale(envelope: ClearanceEnvelope | null | undefined): boolean {
  return envelope?.retailSale === true
    && typeof envelope.productUid === 'string'
    && envelope.productUid.length > 0
    && typeof envelope.excise === 'number'
    && Number.isFinite(envelope.excise)
    && envelope.excise >= 0;
}

export async function signClearanceEnvelope(
  fields: {
    keyId: string;
    jurisdiction: 'CH' | 'IT';
    proofSha256: string;
    secondFactorHash: string;
    iat?: number;
    exp?: number;
    productUid?: string;
    productCategory?: ClearanceProductCategory;
    productStatus?: 'authentic';
    excise?: number;
  },
  privateKey: CryptoKey
): Promise<{ envelope: ClearanceEnvelope; envelopeSignature: string }> {
  const iat = fields.iat ?? Date.now();
  const candidate: Record<string, unknown> = {
    v: 1,
    keyId: fields.keyId,
    jurisdiction: fields.jurisdiction,
    sessionAgeGatePassed: true,
    loaHigh: fields.jurisdiction === 'IT',
    proofSha256: fields.proofSha256,
    secondFactorHash: fields.secondFactorHash,
    iat,
    exp: fields.exp ?? iat + CLEARANCE_ENVELOPE_TTL_MS,
    ageOver18: true,
    retailSale: false,
  };
  if (
    fields.productUid !== undefined ||
    fields.productCategory !== undefined ||
    fields.productStatus !== undefined ||
    fields.excise !== undefined
  ) {
    candidate.retailSale = true;
    candidate.productUid = fields.productUid;
    candidate.productCategory = fields.productCategory;
    candidate.productStatus = fields.productStatus;
    candidate.excise = fields.excise;
  }
  candidate.receiptSha256 = await receiptSha256Hex({
    proofSha256: fields.proofSha256,
    secondFactorHash: fields.secondFactorHash,
    jurisdiction: fields.jurisdiction,
    productUid: fields.productUid,
    productCategory: fields.productCategory,
    productStatus: fields.productStatus,
  });
  const envelope = readClearanceEnvelope(candidate);
  if (!envelope) {
    throw new Error('Refusing to sign a clearance envelope outside the allow-list');
  }
  const signature = await crypto.subtle.sign(
    ECDSA_SHA256,
    privateKey,
    new TextEncoder().encode(canonicalClearanceEnvelope(envelope))
  );
  return { envelope, envelopeSignature: bytesToBase64(new Uint8Array(signature)) };
}

export async function verifyClearanceEnvelope(
  envelope: unknown,
  envelopeSignature: unknown,
  publicKey: CryptoKey,
  now: number = Date.now()
): Promise<{ ok: true; envelope: ClearanceEnvelope } | { ok: false; reason: ClearanceEnvelopeFailure }> {
  if (typeof envelopeSignature !== 'string' || envelopeSignature.length === 0) {
    return { ok: false, reason: 'unsigned' };
  }
  const parsed = readClearanceEnvelope(envelope);
  if (!parsed) return { ok: false, reason: 'malformed' };
  let signatureOk = false;
  try {
    signatureOk = await crypto.subtle.verify(
      ECDSA_SHA256,
      publicKey,
      base64ToBytes(envelopeSignature),
      new TextEncoder().encode(canonicalClearanceEnvelope(parsed))
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return { ok: false, reason: 'signature_rejected' };
  const expectedReceipt = await receiptSha256Hex(parsed);
  if (expectedReceipt !== parsed.receiptSha256) return { ok: false, reason: 'malformed' };
  if (now >= parsed.exp) return { ok: false, reason: 'expired' };
  return { ok: true, envelope: parsed };
}
