/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 * 
 * Authentic W3C WebAuthn / FIDO2 Level 2 & 3 Server Implementation
 * Project Bilanx Sovereign eIDAS Node (TRL 5 Hardware Enclave Binding)
 * 
 * Features:
 * - Zero external runtime dependencies (pure Node.js crypto)
 * - Self-contained RFC 8949 CBOR Decoder and Encoder
 * - Authentic attestation parsing (COSE Key to SPKI PEM for ES256 & RS256)
 * - Authentic assertion verification over authenticatorData || SHA256(clientDataJSON)
 * - Support for both ASN.1 DER and IEEE P1363 (64-byte raw) ECDSA signatures
 * - Anti-replay challenge management with 120s TTL and atomic consumption
 * - Anti-cloning signature counter enforcement
 * - Strict Relying Party ID hash and Origin validation
 */

import crypto from 'crypto';

// ---------------------------------------------------------------------------
// Interfaces & Types
// ---------------------------------------------------------------------------

export interface StoredWebAuthnCredential {
  credentialId: string;
  publicKeyPem: string;
  username: string;
  counter: number;
  createdAt: string;
  authenticatorAttachment: string;
  aaguid?: string;
  deviceName?: string;
  attestationFormat?: string;
  userVerified?: boolean;
  userPresent?: boolean;
  compromised?: boolean;
}

export interface WebAuthnChallengeRecord {
  challenge: string;
  issuedAt: number;
}

export interface RegisterCredentialParams {
  credentialId: string;
  username: string;
  clientDataJSONB64: string;
  attestationObjectB64?: string;
  authenticatorDataB64?: string;
  publicKeyPem?: string;
  authenticatorAttachment?: string;
  expectedOrigin?: string;
  expectedRpId?: string;
  requireUserVerification?: boolean;
}

export interface VerifyAssertionParams {
  credentialId: string;
  clientDataJSONB64: string;
  authenticatorDataB64: string;
  signatureB64: string;
  expectedOrigin?: string;
  expectedRpId?: string;
  requireUserVerification?: boolean;
}

export interface WebAuthnVerifyResult {
  verified: boolean;
  credential?: StoredWebAuthnCredential;
  userVerified?: boolean;
  userPresent?: boolean;
  aaguid?: string;
  deviceName?: string;
  authenticatorAttachment?: string;
  counter?: number;
  error?: string;
}

// ---------------------------------------------------------------------------
// AAGUID Identification & Device Registry
// ---------------------------------------------------------------------------

export const KNOWN_AAGUIDS: Record<string, string> = {
  'ee882879-721c-4916-ad4e-57c7f15f6f19': 'YubiKey 5 Series (NFC / USB)',
  '2fc0579f-8113-47ea-b116-bb5a8db9202a': 'YubiKey 5 NFC',
  'cb69481e-8ff7-4039-93ec-0a2729a1e67d': 'YubiKey 5Ci',
  'fa2b99dc-9e39-4257-8f92-4a30d23c4118': 'YubiKey 5 Series (Lightning / USB-C)',
  'c167093b-01ec-4e5b-b9d9-ae798c874b34': 'Yubico Security Key NFC',
  '08987058-cadc-4b81-b6e1-30c50432bb21': 'Google Titan Security Key',
  '00000000-0000-0000-0000-000000000000': 'Platform Authenticator / Simulator',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Windows Hello Hardware Authenticator',
  '7499aa65-da2d-4530-80ea-311fe5270146': 'Apple Secure Enclave (Touch ID / Face ID)',
  'dd4ec289-e01d-41c9-bb89-70fa845d4bf2': 'Apple Passkey / iCloud Keychain',
};

export function formatAaguid(buf: Buffer): string {
  if (!buf || buf.length < 16) return '00000000-0000-0000-0000-000000000000';
  const hex = buf.subarray(0, 16).toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`.toLowerCase();
}

export function identifyAaguid(aaguid: string): { aaguid: string; deviceName: string; isHardwareKey: boolean } {
  const norm = aaguid.toLowerCase();
  const deviceName = KNOWN_AAGUIDS[norm] || (norm === '00000000-0000-0000-0000-000000000000' ? 'Platform Authenticator / Simulator' : 'CTAP2 Hardware Security Token');
  const isHardwareKey = norm.startsWith('ee882879') || norm.startsWith('2fc0579f') || norm.startsWith('cb69481e') || norm.startsWith('fa2b99dc') || norm.startsWith('c167093b') || norm.startsWith('08987058');
  return { aaguid: norm, deviceName, isHardwareKey };
}

// ---------------------------------------------------------------------------
// In-Memory Storage & Configuration
// ---------------------------------------------------------------------------

const CHALLENGE_TTL_MS = 120_000; // 2 minutes
export const MAX_ACTIVE_WEBAUTHN_CHALLENGES = 5_000;
export const MAX_STORED_CREDENTIALS = 10_000;
const activeWebAuthnChallenges = new Map<string, WebAuthnChallengeRecord>();
const registeredWebAuthnCredentials = new Map<string, StoredWebAuthnCredential>();

// ---------------------------------------------------------------------------
// Base64 / Base64URL Utilities
// ---------------------------------------------------------------------------

export function decodeBuffer(input: string | Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(input)) return input;
  if (input instanceof Uint8Array) return Buffer.from(input);
  if (typeof input !== 'string') {
    throw new Error('Expected string or Buffer for decoding');
  }
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64');
}

export function toBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Zero-Dependency Lightweight CBOR Decoder & Encoder (RFC 8949)
// ---------------------------------------------------------------------------

export class CborReader {
  private offset = 0;
  constructor(private buffer: Buffer) {}

  public getOffset(): number {
    return this.offset;
  }

  public hasMore(): boolean {
    return this.offset < this.buffer.length;
  }

  public read(): any {
    if (this.offset >= this.buffer.length) {
      throw new Error(`CBOR unexpected EOF at offset ${this.offset}`);
    }

    const initialByte = this.buffer[this.offset++];
    const majorType = initialByte >> 5;
    const additionalInfo = initialByte & 0x1f;

    const lengthOrVal = this.readLengthOrVal(additionalInfo);

    switch (majorType) {
      case 0: // Unsigned integer
        return lengthOrVal;

      case 1: // Negative integer: -1 - val
        return -1 - lengthOrVal;

      case 2: { // Byte string
        const len = lengthOrVal;
        if (this.offset + len > this.buffer.length) {
          throw new Error(`CBOR byte string exceeds buffer at offset ${this.offset}`);
        }
        const slice = this.buffer.subarray(this.offset, this.offset + len);
        this.offset += len;
        return slice;
      }

      case 3: { // UTF-8 text string
        const len = lengthOrVal;
        if (this.offset + len > this.buffer.length) {
          throw new Error(`CBOR text string exceeds buffer at offset ${this.offset}`);
        }
        const str = this.buffer.toString('utf-8', this.offset, this.offset + len);
        this.offset += len;
        return str;
      }

      case 4: { // Array
        const len = lengthOrVal;
        const arr: any[] = [];
        for (let i = 0; i < len; i++) {
          arr.push(this.read());
        }
        return arr;
      }

      case 5: { // Map
        const len = lengthOrVal;
        const map = new Map<any, any>();
        for (let i = 0; i < len; i++) {
          const key = this.read();
          const value = this.read();
          map.set(key, value);
        }
        return map;
      }

      case 6: // Tagged item
        return this.read();

      case 7: // Simple / Float
        if (additionalInfo === 20) return false;
        if (additionalInfo === 21) return true;
        if (additionalInfo === 22) return null;
        if (additionalInfo === 23) return undefined;
        return lengthOrVal;

      default:
        throw new Error(`Unsupported CBOR major type ${majorType}`);
    }
  }

  private readLengthOrVal(info: number): number {
    if (info < 24) {
      return info;
    } else if (info === 24) {
      if (this.offset + 1 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      return this.buffer.readUInt8(this.offset++);
    } else if (info === 25) {
      if (this.offset + 2 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      const val = this.buffer.readUInt16BE(this.offset);
      this.offset += 2;
      return val;
    } else if (info === 26) {
      if (this.offset + 4 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      const val = this.buffer.readUInt32BE(this.offset);
      this.offset += 4;
      return val;
    } else if (info === 27) {
      if (this.offset + 8 > this.buffer.length) throw new Error('CBOR unexpected EOF');
      const big = this.buffer.readBigUInt64BE(this.offset);
      this.offset += 8;
      return Number(big);
    } else {
      throw new Error(`Unsupported CBOR additional info ${info}`);
    }
  }
}

export function decodeCbor(buf: Buffer): any {
  const reader = new CborReader(buf);
  return reader.read();
}

/**
 * Minimal CBOR Encoder for testing and synthetic fixture creation
 */
export function encodeCbor(data: any): Buffer {
  if (data === null || data === undefined) {
    return Buffer.from([0xf6]);
  }
  if (typeof data === 'boolean') {
    return Buffer.from([data ? 0xf5 : 0xf4]);
  }
  if (typeof data === 'number') {
    if (Number.isInteger(data)) {
      if (data >= 0) {
        if (data < 24) return Buffer.from([data]);
        if (data <= 0xff) return Buffer.from([0x18, data]);
        if (data <= 0xffff) {
          const b = Buffer.alloc(3);
          b[0] = 0x19;
          b.writeUInt16BE(data, 1);
          return b;
        }
        const b = Buffer.alloc(5);
        b[0] = 0x1a;
        b.writeUInt32BE(data, 1);
        return b;
      } else {
        const val = -1 - data;
        if (val < 24) return Buffer.from([0x20 + val]);
        if (val <= 0xff) return Buffer.from([0x38, val]);
        if (val <= 0xffff) {
          const b = Buffer.alloc(3);
          b[0] = 0x39;
          b.writeUInt16BE(val, 1);
          return b;
        }
        const b = Buffer.alloc(5);
        b[0] = 0x3a;
        b.writeUInt32BE(val, 1);
        return b;
      }
    }
  }
  if (typeof data === 'string') {
    const strBuf = Buffer.from(data, 'utf-8');
    const len = strBuf.length;
    let header: Buffer;
    if (len < 24) header = Buffer.from([0x60 + len]);
    else if (len <= 0xff) header = Buffer.from([0x78, len]);
    else {
      header = Buffer.alloc(3);
      header[0] = 0x79;
      header.writeUInt16BE(len, 1);
    }
    return Buffer.concat([header, strBuf]);
  }
  if (Buffer.isBuffer(data)) {
    const len = data.length;
    let header: Buffer;
    if (len < 24) header = Buffer.from([0x40 + len]);
    else if (len <= 0xff) header = Buffer.from([0x58, len]);
    else {
      header = Buffer.alloc(3);
      header[0] = 0x59;
      header.writeUInt16BE(len, 1);
    }
    return Buffer.concat([header, data]);
  }
  if (Array.isArray(data)) {
    const count = data.length;
    let header: Buffer;
    if (count < 24) header = Buffer.from([0x80 + count]);
    else header = Buffer.from([0x98, count]);
    return Buffer.concat([header, ...data.map(encodeCbor)]);
  }
  if (data instanceof Map) {
    const count = data.size;
    let header: Buffer;
    if (count < 24) header = Buffer.from([0xa0 + count]);
    else header = Buffer.from([0xb8, count]);
    const entries: Buffer[] = [];
    for (const [k, v] of data.entries()) {
      entries.push(encodeCbor(k), encodeCbor(v));
    }
    return Buffer.concat([header, ...entries]);
  }
  if (typeof data === 'object') {
    const keys = Object.keys(data);
    const count = keys.length;
    let header: Buffer;
    if (count < 24) header = Buffer.from([0xa0 + count]);
    else header = Buffer.from([0xb8, count]);
    const entries: Buffer[] = [];
    for (const k of keys) {
      entries.push(encodeCbor(k), encodeCbor(data[k]));
    }
    return Buffer.concat([header, ...entries]);
  }
  throw new Error(`Unsupported type for CBOR encoding: ${typeof data}`);
}

// ---------------------------------------------------------------------------
// Signature Encoding Helpers (IEEE P1363 to ASN.1 DER)
// ---------------------------------------------------------------------------

function encodeAsn1Integer(bytes: Buffer): Buffer {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  let slice = bytes.subarray(start);
  if (slice[0] & 0x80) {
    slice = Buffer.concat([Buffer.from([0x00]), slice]);
  }
  return Buffer.concat([Buffer.from([0x02, slice.length]), slice]);
}

export function rawSignatureToDer(sig: Buffer): Buffer {
  if (sig.length !== 64) return sig;
  const r = sig.subarray(0, 32);
  const s = sig.subarray(32, 64);
  const rEnc = encodeAsn1Integer(r);
  const sEnc = encodeAsn1Integer(s);
  return Buffer.concat([
    Buffer.from([0x30, rEnc.length + sEnc.length]),
    rEnc,
    sEnc
  ]);
}

/**
 * Validates whether a buffer conforms to the ASN.1 DER SEQUENCE structure for ECDSA P-256 signatures.
 */
export function isDerSignature(sig: Buffer): boolean {
  if (sig.length < 8 || sig.length > 74) return false;
  if (sig[0] !== 0x30) return false;
  if (sig[1] !== sig.length - 2) return false;
  if (sig[2] !== 0x02) return false;
  const lenR = sig[3];
  if (4 + lenR >= sig.length) return false;
  if (sig[4 + lenR] !== 0x02) return false;
  const lenS = sig[5 + lenR];
  if (6 + lenR + lenS !== sig.length) return false;
  return true;
}

// ---------------------------------------------------------------------------
// Public Key Transpilation (COSE Key -> SPKI PEM)
// ---------------------------------------------------------------------------

export function coseKeyToPublicKeyPem(coseMap: Map<any, any>): string {
  const kty = coseMap.get(1);
  const alg = coseMap.get(3);

  if (kty === 2) {
    // EC2 Key (ES256 - ECDSA P-256)
    const crv = coseMap.get(-1);
    const x = coseMap.get(-2);
    const y = coseMap.get(-3);

    if (crv !== 1 || !Buffer.isBuffer(x) || !Buffer.isBuffer(y)) {
      throw new Error('Invalid or unsupported EC2 curve parameters (expected P-256)');
    }
    if (x.length !== 32 || y.length !== 32) {
      throw new Error(`Invalid EC2 coordinate lengths: x=${x.length}, y=${y.length}`);
    }

    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(x).toString('base64url'),
      y: Buffer.from(y).toString('base64url')
    };

    const keyObject = crypto.createPublicKey({ key: jwk as any, format: 'jwk' });
    return keyObject.export({ type: 'spki', format: 'pem' }).toString();
  }

  if (kty === 3) {
    // RSA Key (RS256)
    const n = coseMap.get(-1);
    const e = coseMap.get(-2);

    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) {
      throw new Error('Invalid RSA key parameters in COSE Key');
    }

    const jwk = {
      kty: 'RSA',
      n: Buffer.from(n).toString('base64url'),
      e: Buffer.from(e).toString('base64url')
    };

    const keyObject = crypto.createPublicKey({ key: jwk as any, format: 'jwk' });
    return keyObject.export({ type: 'spki', format: 'pem' }).toString();
  }

  throw new Error(`Unsupported COSE kty ${kty} or alg ${alg}`);
}

// ---------------------------------------------------------------------------
// Origin & RP ID Helpers
// ---------------------------------------------------------------------------

function isOriginAllowed(receivedOrigin: string, expectedOrigin?: string, expectedRpId?: string): boolean {
  if (!expectedOrigin && !expectedRpId) return true;
  if (expectedOrigin && receivedOrigin === expectedOrigin) return true;

  try {
    const url = new URL(receivedOrigin);
    if (expectedRpId) {
      if (url.hostname === expectedRpId) return true;
      if (expectedRpId === 'localhost' && (url.hostname === '127.0.0.1' || url.hostname === '::1')) return true;
      if (expectedRpId === '127.0.0.1' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1')) return true;
    }
    if (expectedOrigin) {
      const expUrl = new URL(expectedOrigin);
      if (url.hostname === expUrl.hostname) return true;
    }
  } catch {
    // If not a standard URL, direct string match fallback
    return receivedOrigin === expectedOrigin;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Public API Methods
// ---------------------------------------------------------------------------

/**
 * Generates a cryptographic WebAuthn challenge string (32 bytes base64url)
 */
export function generateWebAuthnChallenge(): string {
  purgeExpiredChallenges();
  const bytes = crypto.randomBytes(32);
  const challenge = bytes.toString('base64url');
  activeWebAuthnChallenges.set(challenge, { challenge, issuedAt: Date.now() });
  return challenge;
}

/**
 * Returns stored WebAuthn credential by ID
 */
export function getStoredCredential(credentialId: string): StoredWebAuthnCredential | undefined {
  return registeredWebAuthnCredentials.get(credentialId);
}

/**
 * Revokes a stored credential permanently (marking it compromised)
 */
export function revokeStoredCredential(credentialId: string, reason?: string): boolean {
  const cred = registeredWebAuthnCredentials.get(credentialId);
  if (!cred) return false;
  cred.compromised = true;
  return true;
}

/**
 * Deletes a stored credential record
 */
export function deleteStoredCredential(credentialId: string): boolean {
  return registeredWebAuthnCredentials.delete(credentialId);
}

/**
 * Lists all stored credentials (optionally filtered by username)
 */
export function listStoredCredentials(username?: string): StoredWebAuthnCredential[] {
  const creds = Array.from(registeredWebAuthnCredentials.values());
  if (username) {
    return creds.filter(c => c.username === username);
  }
  return creds;
}

/**
 * Returns total count of registered credentials
 */
export function getStoredCredentialsCount(): number {
  return registeredWebAuthnCredentials.size;
}

/**
 * Returns total count of currently active challenges
 */
export function getActiveChallengesCount(): number {
  return activeWebAuthnChallenges.size;
}

/**
 * Clears stored credentials and challenges (for tests)
 */
export function clearWebAuthnState(): void {
  activeWebAuthnChallenges.clear();
  registeredWebAuthnCredentials.clear();
}

/**
 * Internal clean-up of expired challenges with bounded capacity eviction
 */
export function purgeExpiredChallenges(): void {
  const now = Date.now();
  for (const [key, record] of activeWebAuthnChallenges.entries()) {
    if (now - record.issuedAt > CHALLENGE_TTL_MS) {
      activeWebAuthnChallenges.delete(key);
    }
  }
  if (activeWebAuthnChallenges.size > MAX_ACTIVE_WEBAUTHN_CHALLENGES) {
    const toDelete = activeWebAuthnChallenges.size - MAX_ACTIVE_WEBAUTHN_CHALLENGES;
    let deleted = 0;
    for (const key of activeWebAuthnChallenges.keys()) {
      activeWebAuthnChallenges.delete(key);
      deleted++;
      if (deleted >= toDelete) break;
    }
  }
}

/**
 * Verifies WebAuthn attestation / registration payload and stores authentic public key
 */
export function registerWebAuthnCredential(
  optionsOrId: RegisterCredentialParams | string,
  usernameArg?: string,
  clientDataJSONB64Arg?: string,
  attestationObjectB64Arg?: string,
  authenticatorAttachmentArg?: string
): StoredWebAuthnCredential {
  purgeExpiredChallenges();

  // Normalize parameters (supports both options object and positional arguments)
  let params: RegisterCredentialParams;
  if (typeof optionsOrId === 'object') {
    params = optionsOrId;
  } else {
    params = {
      credentialId: optionsOrId,
      username: usernameArg || 'daniele.palagi92@gmail.com',
      clientDataJSONB64: clientDataJSONB64Arg || '',
      attestationObjectB64: attestationObjectB64Arg,
      authenticatorAttachment: authenticatorAttachmentArg || 'platform'
    };
  }

    const {
    credentialId,
    username,
    clientDataJSONB64,
    attestationObjectB64,
    publicKeyPem: directPublicKeyPem,
    authenticatorAttachment = 'platform',
    expectedOrigin,
    expectedRpId,
    requireUserVerification
  } = params;

  if (!credentialId) {
    throw new Error('Missing credentialId');
  }

  // 1. Decode & Verify clientDataJSON
  let clientDataBuf: Buffer;
  let parsedClientData: any;
  try {
    clientDataBuf = decodeBuffer(clientDataJSONB64);
    parsedClientData = JSON.parse(clientDataBuf.toString('utf-8'));
  } catch (err: any) {
    throw new Error(`Invalid clientDataJSON encoding or JSON format: ${err.message}`);
  }

  if (parsedClientData.type !== 'webauthn.create') {
    throw new Error(`Invalid WebAuthn event type: ${parsedClientData.type}, expected 'webauthn.create'`);
  }

  // 2. Challenge Verification & Anti-Replay Consumption
  const challenge = parsedClientData.challenge;
  const challengeRecord = activeWebAuthnChallenges.get(challenge);
  if (!challengeRecord) {
    throw new Error('Challenge not found or already consumed (replay attack detected)');
  }
  if (Date.now() - challengeRecord.issuedAt > CHALLENGE_TTL_MS) {
    activeWebAuthnChallenges.delete(challenge);
    throw new Error('Registration challenge expired');
  }
  activeWebAuthnChallenges.delete(challenge); // Consume challenge immediately

  // 3. Origin Verification
  if (parsedClientData.origin && (expectedOrigin || expectedRpId)) {
    if (!isOriginAllowed(parsedClientData.origin, expectedOrigin, expectedRpId)) {
      throw new Error(`Origin mismatch: expected ${expectedOrigin || expectedRpId}, got ${parsedClientData.origin}`);
    }
  }

  // 4. Extract Public Key & Attestation Metadata
  let resolvedPublicKeyPem = '';
  let aaguidFormatted = '00000000-0000-0000-0000-000000000000';
  let deviceName = 'Platform Authenticator / Simulator';
  let attestationFormat = 'none';
  let userVerified = false;
  let userPresent = true;

  if (attestationObjectB64) {
    const attestationBuf = decodeBuffer(attestationObjectB64);
    const attestationMap = decodeCbor(attestationBuf);
    if (!(attestationMap instanceof Map)) {
      throw new Error('attestationObject root is not a valid CBOR map');
    }

    const authDataBuf: Buffer = attestationMap.get('authData');
    if (!Buffer.isBuffer(authDataBuf) || authDataBuf.length < 37) {
      throw new Error('Invalid or truncated authData in attestationObject');
    }

    // Verify RP ID Hash if provided
    if (expectedRpId) {
      const expectedHash = crypto.createHash('sha256').update(expectedRpId).digest();
      const rpIdHash = authDataBuf.subarray(0, 32);
      if (!crypto.timingSafeEqual(rpIdHash, expectedHash)) {
        throw new Error(`RP ID hash mismatch in attestationObject for rpId '${expectedRpId}'`);
      }
    }

    // Verify User Present (bit 0) and Attested Credential Data (bit 6)
    const flags = authDataBuf[32];
    userPresent = (flags & 0x01) !== 0;
    userVerified = (flags & 0x04) !== 0;

    if (!userPresent) {
      throw new Error('User presence flag (UP) not set in attestation authData');
    }
    if (requireUserVerification && !userVerified) {
      throw new Error('User verification flag (UV) required but not set in attestation authData');
    }
    if ((flags & 0x40) === 0) {
      throw new Error('Attested credential data flag (AT) not set in attestation authData');
    }

    // Attested Credential Data starts at offset 37:
    // aaguid: 16 bytes (37..52)
    // credIdLen: 2 bytes (53..54)
    const aaguidBuf = authDataBuf.subarray(37, 53);
    aaguidFormatted = formatAaguid(aaguidBuf);
    const idInfo = identifyAaguid(aaguidFormatted);
    deviceName = idInfo.deviceName;

    const credIdLen = authDataBuf.readUInt16BE(53);
    const credIdEnd = 55 + credIdLen;
    if (authDataBuf.length < credIdEnd) {
      throw new Error('authData buffer truncated before credential ID end');
    }

    const coseBuf = authDataBuf.subarray(credIdEnd);
    const coseMap = decodeCbor(coseBuf);
    if (!(coseMap instanceof Map)) {
      throw new Error('Failed to parse credentialPublicKey COSE map from authData');
    }

    resolvedPublicKeyPem = coseKeyToPublicKeyPem(coseMap);

    // Process Attestation Statement (fmt & attStmt)
    attestationFormat = (attestationMap.get('fmt') as string) || 'none';
    const attStmt = attestationMap.get('attStmt');

    if (attestationFormat === 'none') {
      // Direct registration without attestation statement (WebAuthn Level 3 standard)
    } else if (attestationFormat === 'packed') {
      if (!(attStmt instanceof Map)) {
        throw new Error('Packed attestation statement missing or invalid');
      }
      const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
      const signedBytes = Buffer.concat([authDataBuf, clientDataHash]);
      const sig = attStmt.get('sig');
      const x5c = attStmt.get('x5c');

      if (!sig || !Buffer.isBuffer(sig)) {
        throw new Error('Packed attestation statement missing signature');
      }

      const derSig = (!isDerSignature(sig) && sig.length === 64) ? rawSignatureToDer(sig) : sig;

      if (Array.isArray(x5c) && x5c.length > 0 && Buffer.isBuffer(x5c[0])) {
        // Full attestation via X.509 certificate chain
        try {
          const cert = new crypto.X509Certificate(x5c[0]);

          // 1. Verify temporal validity of leaf attestation certificate
          const now = new Date();
          const validFrom = cert.validFromDate ?? new Date(cert.validFrom);
          const validTo = cert.validToDate ?? new Date(cert.validTo);
          if (now < validFrom || now > validTo) {
            throw new Error(`Attestation certificate expired or not yet valid (valid from ${cert.validFrom} to ${cert.validTo})`);
          }

          // 2. If chain is present (x5c.length > 1), verify trust chain continuity
          for (let i = 0; i < x5c.length - 1; i++) {
            if (!Buffer.isBuffer(x5c[i]) || !Buffer.isBuffer(x5c[i + 1])) {
              throw new Error(`Invalid certificate element in attestation chain at index ${i}`);
            }
            const childCert = new crypto.X509Certificate(x5c[i]);
            const parentCert = new crypto.X509Certificate(x5c[i + 1]);
            const parentValidFrom = parentCert.validFromDate ?? new Date(parentCert.validFrom);
            const parentValidTo = parentCert.validToDate ?? new Date(parentCert.validTo);
            if (now < parentValidFrom || now > parentValidTo) {
              throw new Error(`Intermediate/root attestation certificate expired or not yet valid (valid from ${parentCert.validFrom} to ${parentCert.validTo})`);
            }
            if (!childCert.verify(parentCert.publicKey)) {
              throw new Error(`Attestation certificate chain verification failed at certificate ${i}`);
            }
          }

          // 3. Verify signature over signedBytes using leaf certificate public key
          const verified = crypto.verify('SHA256', signedBytes, cert.publicKey, derSig);
          if (!verified) {
            throw new Error('Packed attestation certificate chain signature verification failed');
          }
        } catch (err: any) {
          throw new Error(`Packed attestation certificate verification error: ${err.message}`);
        }
      } else {
        // Self-attestation / surrogate attestation signed with the credential's own key
        try {
          const verified = crypto.verify('SHA256', signedBytes, resolvedPublicKeyPem, derSig);
          if (!verified) {
            throw new Error('Packed self-attestation signature verification failed');
          }
        } catch (err: any) {
          throw new Error(`Packed self-attestation verification error: ${err.message}`);
        }
      }
    } else {
      throw new Error(`Unsupported attestation format '${attestationFormat}'`);
    }
  } else if (directPublicKeyPem) {
    // Allow direct PEM / SPKI if supplied (e.g. from tests or pre-parsed clients)
    try {
      const keyObj = crypto.createPublicKey(directPublicKeyPem);
      resolvedPublicKeyPem = keyObj.export({ type: 'spki', format: 'pem' }).toString();
    } catch (err: any) {
      throw new Error(`Invalid direct publicKeyPem: ${err.message}`);
    }
  } else {
    throw new Error('Missing attestationObject or publicKeyPem in registration payload');
  }

  // 5. Duplicate & Revoked Credential Defense
  if (registeredWebAuthnCredentials.has(credentialId)) {
    const existing = registeredWebAuthnCredentials.get(credentialId)!;
    if (existing.compromised) {
      throw new Error(`Credential '${credentialId}' has been revoked due to security violation and cannot be re-registered`);
    }
    throw new Error(`Credential '${credentialId}' is already registered`);
  }

  // Enforce bounded storage capacity under DDoS registration attacks
  if (registeredWebAuthnCredentials.size >= MAX_STORED_CREDENTIALS) {
    for (const [id, cred] of registeredWebAuthnCredentials.entries()) {
      if (!cred.compromised) {
        registeredWebAuthnCredentials.delete(id);
        break;
      }
    }
  }

  // 6. Store Credential Record
  const credential: StoredWebAuthnCredential = {
    credentialId,
    publicKeyPem: resolvedPublicKeyPem,
    username,
    counter: 0,
    createdAt: new Date().toISOString(),
    authenticatorAttachment: authenticatorAttachment || 'platform',
    aaguid: aaguidFormatted,
    deviceName,
    attestationFormat,
    userVerified,
    userPresent
  };

  registeredWebAuthnCredentials.set(credentialId, credential);
  return credential;
}

/**
 * Verifies WebAuthn assertion payload signed inside device Secure Enclave / Authenticator
 */
export function verifyWebAuthnAssertion(
  optionsOrId: VerifyAssertionParams | string,
  clientDataJSONB64Arg?: string,
  signatureB64Arg?: string,
  authenticatorDataB64Arg?: string
): WebAuthnVerifyResult {
  purgeExpiredChallenges();

  // Normalize parameters
  let params: VerifyAssertionParams;
  if (typeof optionsOrId === 'object') {
    params = optionsOrId;
  } else {
    params = {
      credentialId: optionsOrId,
      clientDataJSONB64: clientDataJSONB64Arg || '',
      signatureB64: signatureB64Arg || '',
      authenticatorDataB64: authenticatorDataB64Arg || ''
    };
  }

  const {
    credentialId,
    clientDataJSONB64,
    authenticatorDataB64,
    signatureB64,
    expectedOrigin,
    expectedRpId
  } = params;

  // 1. Look up Credential
  const cred = registeredWebAuthnCredentials.get(credentialId);
  if (!cred) {
    return { verified: false, error: `Credential not found: ${credentialId}` };
  }

  // 1b. Fail-closed check for previously compromised / revoked credentials
  if (cred.compromised) {
    return {
      verified: false,
      error: 'Credential has been revoked due to previously detected clone / tampering attempt'
    };
  }

  // 2. Decode & Verify clientDataJSON
  let clientDataBuf: Buffer;
  let parsedClientData: any;
  try {
    clientDataBuf = decodeBuffer(clientDataJSONB64);
    parsedClientData = JSON.parse(clientDataBuf.toString('utf-8'));
  } catch (err: any) {
    return { verified: false, error: `Invalid clientDataJSON encoding: ${err.message}` };
  }

  if (parsedClientData.type !== 'webauthn.get') {
    return { verified: false, error: `Invalid assertion event type: ${parsedClientData.type}, expected 'webauthn.get'` };
  }

  // 3. Challenge Verification & Anti-Replay
  const challenge = parsedClientData.challenge;
  const challengeRecord = activeWebAuthnChallenges.get(challenge);
  if (!challengeRecord) {
    return { verified: false, error: 'Challenge not found or already consumed (replay attack detected)' };
  }
  if (Date.now() - challengeRecord.issuedAt > CHALLENGE_TTL_MS) {
    activeWebAuthnChallenges.delete(challenge);
    return { verified: false, error: 'Authentication challenge expired' };
  }
  activeWebAuthnChallenges.delete(challenge); // Consume challenge immediately

  // 4. Origin Verification
  if (parsedClientData.origin && (expectedOrigin || expectedRpId)) {
    if (!isOriginAllowed(parsedClientData.origin, expectedOrigin, expectedRpId)) {
      return { verified: false, error: `Origin mismatch: expected ${expectedOrigin || expectedRpId}, got ${parsedClientData.origin}` };
    }
  }

  // 5. Decode & Verify authenticatorData
  let authDataBuf: Buffer;
  try {
    authDataBuf = decodeBuffer(authenticatorDataB64);
  } catch (err: any) {
    return { verified: false, error: `Invalid authenticatorData encoding: ${err.message}` };
  }

  if (authDataBuf.length < 37) {
    return { verified: false, error: `authenticatorData is too short (${authDataBuf.length} bytes, minimum 37)` };
  }

  // 6. RP ID Hash Verification
  if (expectedRpId) {
    const expectedHash = crypto.createHash('sha256').update(expectedRpId).digest();
    const rpIdHash = authDataBuf.subarray(0, 32);
    if (!crypto.timingSafeEqual(rpIdHash, expectedHash)) {
      return { verified: false, error: `RP ID hash mismatch for rpId '${expectedRpId}'` };
    }
  }

  // 7. User Presence (UP) & User Verification (UV) Flag Verification
  const flags = authDataBuf[32];
  const userPresent = (flags & 0x01) !== 0;
  const userVerified = (flags & 0x04) !== 0;

  if (!userPresent) {
    return { verified: false, error: 'User presence flag (UP) not set in authenticatorData' };
  }

  if (params.requireUserVerification && !userVerified) {
    return { verified: false, error: 'User verification flag (UV) required but not set in authenticatorData' };
  }

  // 8. Authentic ECDSA Signature Verification
  const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
  const signedBytes = Buffer.concat([authDataBuf, clientDataHash]);

  let sigBuf: Buffer;
  try {
    sigBuf = decodeBuffer(signatureB64);
  } catch (err: any) {
    return { verified: false, error: `Invalid signature encoding: ${err.message}` };
  }

  // Auto-convert raw 64-byte IEEE P1363 signatures to standard ASN.1 DER if needed
  const derSig = (!isDerSignature(sigBuf) && sigBuf.length === 64) ? rawSignatureToDer(sigBuf) : sigBuf;

  let isValidSignature = false;
  try {
    isValidSignature = crypto.verify('SHA256', signedBytes, cred.publicKeyPem, derSig);
  } catch (err: any) {
    return { verified: false, error: `Cryptographic verification error: ${err.message}` };
  }

  if (!isValidSignature) {
    return { verified: false, error: 'Cryptographic signature verification failed' };
  }

  // 9. Compromised Credential Revocation Check
  if (cred.compromised) {
    return {
      verified: false,
      error: 'Credential has been revoked due to previously detected clone / tampering attempt'
    };
  }

  // 10. Signature Counter (Anti-Cloning) Verification
  const signCount = authDataBuf.readUInt32BE(33);
  if ((cred.counter > 0 || signCount > 0) && signCount <= cred.counter) {
    cred.compromised = true;
    return {
      verified: false,
      error: `Cloned authenticator detected: signCount (${signCount}) did not increase past stored counter (${cred.counter})`
    };
  }
  if (cred.authenticatorAttachment === 'cross-platform' && signCount <= cred.counter) {
    cred.compromised = true;
    return {
      verified: false,
      error: `Cloned authenticator detected: roaming hardware key signature counter (${signCount}) must strictly exceed stored counter (${cred.counter})`
    };
  }

  // 11. Update Counter & Return Verified Credential
  cred.counter = signCount;
  return {
    verified: true,
    credential: cred,
    userVerified,
    userPresent,
    aaguid: cred.aaguid,
    deviceName: cred.deviceName,
    authenticatorAttachment: cred.authenticatorAttachment,
    counter: cred.counter
  };
}
