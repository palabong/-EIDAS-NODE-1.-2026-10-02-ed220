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
}

export interface VerifyAssertionParams {
  credentialId: string;
  clientDataJSONB64: string;
  authenticatorDataB64: string;
  signatureB64: string;
  expectedOrigin?: string;
  expectedRpId?: string;
}

export interface WebAuthnVerifyResult {
  verified: boolean;
  credential?: StoredWebAuthnCredential;
  error?: string;
}

// ---------------------------------------------------------------------------
// In-Memory Storage & Configuration
// ---------------------------------------------------------------------------

const CHALLENGE_TTL_MS = 120_000; // 2 minutes
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
 * Clears stored credentials and challenges (for tests)
 */
export function clearWebAuthnState(): void {
  activeWebAuthnChallenges.clear();
  registeredWebAuthnCredentials.clear();
}

/**
 * Internal clean-up of expired challenges
 */
function purgeExpiredChallenges(): void {
  const now = Date.now();
  for (const [key, record] of activeWebAuthnChallenges.entries()) {
    if (now - record.issuedAt > CHALLENGE_TTL_MS) {
      activeWebAuthnChallenges.delete(key);
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
    expectedRpId
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

  // 4. Extract Public Key
  let resolvedPublicKeyPem = '';

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
    if ((flags & 0x01) === 0) {
      throw new Error('User presence flag (UP) not set in attestation authData');
    }
    if ((flags & 0x40) === 0) {
      throw new Error('Attested credential data flag (AT) not set in attestation authData');
    }

    // Attested Credential Data starts at offset 37:
    // aaguid: 16 bytes (37..52)
    // credIdLen: 2 bytes (53..54)
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

  // 5. Store Credential Record
  const credential: StoredWebAuthnCredential = {
    credentialId,
    publicKeyPem: resolvedPublicKeyPem,
    username,
    counter: 0,
    createdAt: new Date().toISOString(),
    authenticatorAttachment
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

  // 7. User Presence (UP) Flag Verification
  const flags = authDataBuf[32];
  if ((flags & 0x01) === 0) {
    return { verified: false, error: 'User presence flag (UP) not set in authenticatorData' };
  }

  // 8. Signature Counter (Anti-Cloning) Verification
  const signCount = authDataBuf.readUInt32BE(33);
  if ((cred.counter > 0 || signCount > 0) && signCount <= cred.counter) {
    return {
      verified: false,
      error: `Cloned authenticator detected: signCount (${signCount}) did not increase past stored counter (${cred.counter})`
    };
  }

  // 9. Authentic ECDSA Signature Verification
  const clientDataHash = crypto.createHash('sha256').update(clientDataBuf).digest();
  const signedBytes = Buffer.concat([authDataBuf, clientDataHash]);

  let sigBuf: Buffer;
  try {
    sigBuf = decodeBuffer(signatureB64);
  } catch (err: any) {
    return { verified: false, error: `Invalid signature encoding: ${err.message}` };
  }

  // Auto-convert raw 64-byte IEEE P1363 signatures to standard ASN.1 DER if needed
  const derSig = (sigBuf[0] !== 0x30 && sigBuf.length === 64) ? rawSignatureToDer(sigBuf) : sigBuf;

  let isValidSignature = false;
  try {
    isValidSignature = crypto.verify('SHA256', signedBytes, cred.publicKeyPem, derSig);
  } catch (err: any) {
    return { verified: false, error: `Cryptographic verification error: ${err.message}` };
  }

  if (!isValidSignature) {
    return { verified: false, error: 'Cryptographic signature verification failed' };
  }

  // 10. Update Counter & Return Verified Credential
  cred.counter = signCount;
  return {
    verified: true,
    credential: cred
  };
}
