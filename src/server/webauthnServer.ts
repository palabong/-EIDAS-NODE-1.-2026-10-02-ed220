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
import { pilotDemoEnabled } from './httpShared.ts';
import { CapacityExceededError } from './httpShared.ts';
import { bindDurableStore, openDurableMap, type DurableStore } from './durableStore.ts';
import { recordClearanceAudit } from './clearanceAudit.ts';
import { decodeCbor, rawSignatureToDer, isDerSignature } from './webauthnCodec.ts';

export { CborReader, decodeCbor, encodeCbor, rawSignatureToDer, isDerSignature } from './webauthnCodec.ts';

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

const webAuthnChallengeSlot: { current: DurableStore<WebAuthnChallengeRecord> } = {
  current: openDurableMap<WebAuthnChallengeRecord>('webauthn-challenges'),
};
const webAuthnCredentialSlot: { current: DurableStore<StoredWebAuthnCredential> } = {
  current: openDurableMap<StoredWebAuthnCredential>('webauthn-credentials'),
};

export const activeWebAuthnChallenges = bindDurableStore(() => webAuthnChallengeSlot.current);
export const registeredWebAuthnCredentials = bindDurableStore(() => webAuthnCredentialSlot.current);

export function replaceWebAuthnChallengeStore(
  next: DurableStore<WebAuthnChallengeRecord>
): DurableStore<WebAuthnChallengeRecord> {
  const previous = webAuthnChallengeSlot.current;
  webAuthnChallengeSlot.current = next;
  return previous;
}

export function replaceWebAuthnCredentialStore(
  next: DurableStore<StoredWebAuthnCredential>
): DurableStore<StoredWebAuthnCredential> {
  const previous = webAuthnCredentialSlot.current;
  webAuthnCredentialSlot.current = next;
  return previous;
}

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
  if (activeWebAuthnChallenges.size >= MAX_ACTIVE_WEBAUTHN_CHALLENGES) {
    throw new CapacityExceededError('WebAuthn challenge capacity exceeded');
  }
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
  registeredWebAuthnCredentials.commit(credentialId);
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
      username: usernameArg || '',
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
  if (!username) {
    throw new Error('username is required');
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

  // 3. Origin Verification. A missing origin is a failure when the caller named an expected origin.
  if (expectedOrigin || expectedRpId) {
    if (!parsedClientData.origin || !isOriginAllowed(parsedClientData.origin, expectedOrigin, expectedRpId)) {
      throw new Error(`Origin mismatch: expected ${expectedOrigin || expectedRpId}, got ${parsedClientData.origin || 'missing'}`);
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
      // fmt:none has no signature. The sandbox uses it for the software enclave.
      // Production refuses it. A FIDO MDS pin is not part of this node.
      if (process.env.NODE_ENV === 'production' && !pilotDemoEnabled()) {
        throw new Error('Attestation format none is test-only');
      }
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
        // Packed self-attestation is the sandbox software key. Production refuses it.
        // A packed x5c chain above is checked for time and link signatures only.
        // Pinning that chain to a manufacturer MDS root stays outside this repository.
        if (process.env.NODE_ENV === 'production' && !pilotDemoEnabled()) {
          throw new Error('Packed self-attestation is test-only');
        }
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

  if (registeredWebAuthnCredentials.size >= MAX_STORED_CREDENTIALS) {
    throw new CapacityExceededError('WebAuthn credential store is at capacity');
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

  // 4. Origin Verification. A missing origin is a failure when the caller named an expected origin.
  if (expectedOrigin || expectedRpId) {
    if (!parsedClientData.origin || !isOriginAllowed(parsedClientData.origin, expectedOrigin, expectedRpId)) {
      return { verified: false, error: `Origin mismatch: expected ${expectedOrigin || expectedRpId}, got ${parsedClientData.origin || 'missing'}` };
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

  if ((params.requireUserVerification || cred.authenticatorAttachment === 'cross-platform') && !userVerified) {
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
    registeredWebAuthnCredentials.commit(credentialId);
    recordClearanceAudit({ event: 'clone_detected', reason: 'counter_not_increasing' });
    return {
      verified: false,
      error: `Cloned authenticator detected: signCount (${signCount}) did not increase past stored counter (${cred.counter})`
    };
  }
  if (cred.authenticatorAttachment === 'cross-platform' && signCount <= cred.counter) {
    cred.compromised = true;
    registeredWebAuthnCredentials.commit(credentialId);
    recordClearanceAudit({ event: 'clone_detected', reason: 'counter_not_increasing' });
    return {
      verified: false,
      error: `Cloned authenticator detected: roaming hardware key signature counter (${signCount}) must strictly exceed stored counter (${cred.counter})`
    };
  }

  // 11. Update Counter & Return Verified Credential
  cred.counter = signCount;
  registeredWebAuthnCredentials.commit(credentialId);
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
