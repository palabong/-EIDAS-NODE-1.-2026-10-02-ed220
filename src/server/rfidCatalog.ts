/**
 * Pilot RFID catalog. The manufacturer signature is ECDSA P-256 SHA-256
 * over the UTF-8 string `UID|category|status`.
 * The public key below is a pilot test key that lives in this repository.
 * A production manufacturer PKI replaces this key. The private key is not stored.
 */

import { base64ToBytes } from '../lib/crypto/encoding.ts';

export const PILOT_MANUFACTURER_PUBLIC_JWK: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'XLzvVVZCqNdPSny_whZHeiu9YwVMbGFSKJgul4FNVN0',
  y: 'olAY6CNcBhhr2kKyqcryJxSAgtnJBqvKa6cX1CHKOW4',
};

export const RFID_PRODUCT_CATEGORIES = [
  'Tobacco',
  'Alcohol',
  'Vaporizer',
  'Cannabinoids',
  'Restricted Hardware',
] as const;

export type RfidProductCategory = (typeof RFID_PRODUCT_CATEGORIES)[number];
export type RfidProductStatus = 'authentic' | 'counterfeit' | 'recalled';

export type StockReason =
  | 'verified'
  | 'unknown_uid'
  | 'missing_uid'
  | 'signature_rejected'
  | 'unsigned'
  | 'counterfeit'
  | 'recalled';

export interface StockDecision {
  ok: boolean;
  reason: StockReason;
  signatureVerified: boolean;
  hardwareUid?: string;
  productName?: string;
  category?: RfidProductCategory;
  status?: RfidProductStatus;
  exciseRecovered?: number;
  verdict?: string;
}

interface CatalogRow {
  hardwareUid: string;
  productName: string;
  category: RfidProductCategory;
  status: RfidProductStatus;
  exciseRecovered: number;
  /** Standard base64 of the raw P-256 signature. Empty means the row is unsigned. */
  signature: string;
}

const CATALOG: readonly CatalogRow[] = [
  {
    hardwareUid: 'UID-9904-AUTH-951',
    productName: 'Audentes Mint Tobacco Pods (Pack of 4)',
    category: 'Tobacco',
    status: 'authentic',
    exciseRecovered: 3.85,
    signature: '+KCZMO7Gk1dSMjGxAZB2X8/tW/ijHwUxbcXacI8IorVHlMmw2mZB3YSMpejdg12pHt6C9caQieOwS5Wmpdh9Dg==',
  },
  {
    hardwareUid: 'UID-8812-AUTH-324',
    productName: 'Veritas Premium Aged Cognac v2',
    category: 'Alcohol',
    status: 'authentic',
    exciseRecovered: 3.85,
    signature: 'KMX2QySscos9PpstJt26cfz0Fnon+6lnBZgv/DctIUXVd3leSJyJUImWok+ZHVmPIj+ufd6mwzfODmGKBx/mCQ==',
  },
  {
    hardwareUid: 'UID-1102-FAKE-881',
    productName: 'Lumina Grapefruit Ice Disposable',
    category: 'Vaporizer',
    status: 'counterfeit',
    exciseRecovered: 0,
    signature: 'p1CxXrN3LXzmf0l5765lImdnPjyvlzggaAit15Hc3Ea44j7AuQxRhUSQaRQhZAxe0LI+3Ew3kW4YZknIwI1pUQ==',
  },
  {
    hardwareUid: 'UID-3221-RECALLED-60',
    productName: 'Chronos CBD Isolate Vaporizer Pen',
    category: 'Cannabinoids',
    status: 'recalled',
    exciseRecovered: 0,
    signature: 'b88CNXXeknt84hzgpYLrH8Nv3WOKFwiOPxcqPsgfEFstcwYftDO8ernqQxKY0/O7AycvUw/dXHhOquvmtePjZQ==',
  },
  {
    hardwareUid: 'UID-7701-AUTH-118',
    productName: 'Swiss Appenzeller Alpine Spirits (18+ Restricted)',
    category: 'Alcohol',
    status: 'authentic',
    exciseRecovered: 3.85,
    signature: '4SNJpvZ6LnJEIY5p/nilZ6UXY9THrrRQATT86Pq3SS31FE2BayQ7sEKAxQ+HA1jAoZwlIp8tEf4W/4hTeHqV0w==',
  },
  {
    hardwareUid: 'UID-4408-AUTH-018',
    productName: 'AgCom Regulated Online Content & Digital Services (18+)',
    category: 'Restricted Hardware',
    status: 'authentic',
    exciseRecovered: 0,
    signature: 't0+m/MFjT5m30LwdLLu1k6fyCR3AA1nlEV62nChWROeKNbQKUGML5GX+FmJchAUebBVWU+8lG2eLvnCr9vwigg==',
  },
  {
    hardwareUid: 'UID-0000-BADSIG-1',
    productName: 'Pilot Tampered Signature Row',
    category: 'Tobacco',
    status: 'authentic',
    exciseRecovered: 0,
    signature: 'AAAA',
  },
  {
    hardwareUid: 'UID-0000-UNSIGNED-1',
    productName: 'Pilot Unsigned Row',
    category: 'Tobacco',
    status: 'authentic',
    exciseRecovered: 0,
    signature: '',
  },
];

const ECDSA_SHA256 = { name: 'ECDSA', hash: 'SHA-256' } as const;
let manufacturerKey: CryptoKey | null = null;

export function manufacturerMessage(uid: string, category: string, status: string): string {
  return `${uid}|${category}|${status}`;
}

async function manufacturerPublicKey(): Promise<CryptoKey> {
  if (!manufacturerKey) {
    manufacturerKey = await crypto.subtle.importKey(
      'jwk',
      PILOT_MANUFACTURER_PUBLIC_JWK,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
  }
  return manufacturerKey;
}

export async function verifyManufacturerSignature(row: {
  hardwareUid: string;
  category: string;
  status: string;
  signature: string;
}): Promise<boolean> {
  if (!row.signature) return false;
  try {
    const key = await manufacturerPublicKey();
    return await crypto.subtle.verify(
      ECDSA_SHA256,
      key,
      base64ToBytes(row.signature),
      new TextEncoder().encode(manufacturerMessage(row.hardwareUid, row.category, row.status))
    );
  } catch {
    return false;
  }
}

function foundRow(row: CatalogRow, extra: Pick<StockDecision, 'ok' | 'reason' | 'signatureVerified' | 'verdict'>): StockDecision {
  return {
    ...extra,
    hardwareUid: row.hardwareUid,
    productName: row.productName,
    category: row.category,
    status: row.status,
    exciseRecovered: row.exciseRecovered,
  };
}

async function decide(row: CatalogRow): Promise<StockDecision> {
  if (row.signature.length === 0) {
    return foundRow(row, { ok: false, reason: 'unsigned', signatureVerified: false });
  }
  const signatureVerified = await verifyManufacturerSignature(row);
  if (!signatureVerified) {
    return foundRow(row, { ok: false, reason: 'signature_rejected', signatureVerified: false });
  }
  if (row.status === 'counterfeit') {
    return foundRow(row, {
      ok: false,
      reason: 'counterfeit',
      signatureVerified: true,
      verdict: '[STOCK POLICY BLOCK: COUNTERFEIT DETECTED]',
    });
  }
  if (row.status === 'recalled') {
    return foundRow(row, {
      ok: false,
      reason: 'recalled',
      signatureVerified: true,
      verdict: '[STOCK POLICY BLOCK: RECALLED STOCK]',
    });
  }
  if (row.status !== 'authentic') {
    return foundRow(row, { ok: false, reason: 'signature_rejected', signatureVerified: true });
  }
  return foundRow(row, {
    ok: true,
    reason: 'verified',
    signatureVerified: true,
    verdict: '[OK / AUTHENTIC]',
  });
}

/**
 * Exact UID wins over the product name. Duplicate names fail closed.
 * The caller cannot supply the category, status, or signature.
 */
export async function verifyStockRequest(request: {
  hardwareUid?: string;
  productName?: string;
}): Promise<StockDecision> {
  const hardwareUid = typeof request.hardwareUid === 'string' ? request.hardwareUid : '';
  const productName = typeof request.productName === 'string' ? request.productName : '';
  if (hardwareUid.length > 0) {
    const row = CATALOG.find((entry) => entry.hardwareUid === hardwareUid);
    if (!row) return { ok: false, reason: 'unknown_uid', signatureVerified: false, hardwareUid };
    return decide(row);
  }
  if (productName.length > 0) {
    const matches = CATALOG.filter((entry) => entry.productName === productName);
    if (matches.length !== 1) return { ok: false, reason: 'unknown_uid', signatureVerified: false };
    return decide(matches[0]);
  }
  return { ok: false, reason: 'missing_uid', signatureVerified: false };
}
