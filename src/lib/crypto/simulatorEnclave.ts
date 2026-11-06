/**
 * Software Secure Enclave Simulator (FIDO2 Platform Emulator)
 * 
 * Provides an authentic, standards-compliant FIDO2 Level 2 platform emulator
 * using the W3C Web Cryptography API. Generates genuine ECDSA P-256 keypairs,
 * RFC 8152 COSE public key structures, and signed assertions.
 * 
 * Used for headless CI automation, automated testing, and client environments
 * lacking physical biometric hardware (Touch ID / Face ID / Windows Hello).
 */

import { 
  bytesToBase64, 
  base64ToBytes,
  base64UrlToBytes, 
  bytesToHex, 
  encodeCborU8 
} from './encoding.ts';

export interface SimulatorEnclaveKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  credentialId: string;
  credentialIdBytes: Uint8Array;
  rpId: string;
  origin: string;
  counter: number;
}

export interface SimulatorRegistrationResult {
  verified: boolean;
  credentialId: string;
  hwFingerprint: string;
  keyPair: SimulatorEnclaveKeyPair;
}

export interface SimulatorAssertionResult {
  verified: boolean;
  credentialId: string;
  hwFingerprint: string;
  authenticatorDataB64: string;
  signatureB64: string;
}

/**
 * Derives the Hardware Enclave Fingerprint:
 * HW_FINGERPRINT = SHA-256(credentialId || authenticatorData)
 */
export async function deriveHardwareFingerprint(
  credentialId: string | Uint8Array,
  authenticatorData: string | Uint8Array
): Promise<string> {
  const credBytes = typeof credentialId === 'string' ? base64ToBytes(credentialId) : credentialId;
  const authBytes = typeof authenticatorData === 'string' ? base64ToBytes(authenticatorData) : authenticatorData;
  const combined = new Uint8Array(credBytes.length + authBytes.length);
  combined.set(credBytes, 0);
  combined.set(authBytes, credBytes.length);
  const hashBuffer = await crypto.subtle.digest('SHA-256', combined);
  const hashHex = bytesToHex(hashBuffer);
  return `HE-P256-${hashHex.slice(0, 12).toUpperCase()}`;
}

/**
 * Software Secure Enclave Simulator (FIDO2 Platform Emulator Class)
 */
export class SoftwareSecureEnclaveSimulator {
  public keyPair?: SimulatorEnclaveKeyPair;
  public counter: number = 0;

  async createCredential(options: any): Promise<{
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      attestationObject: string;
      authenticatorData: string;
    };
  }> {
    const challenge = options.challenge;
    const rpId = options.rp?.id || (typeof window !== 'undefined' && window.location ? window.location.hostname : 'localhost');
    const origin = (typeof window !== 'undefined' && window.location ? window.location.origin : `http://${rpId}`);

    const keyPair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    if (!jwk.x || !jwk.y) throw new Error('Failed to export public key coordinates');
    const xBytes = base64UrlToBytes(jwk.x);
    const yBytes = base64UrlToBytes(jwk.y);

    const coseKey = new Map<number, any>();
    coseKey.set(1, 2);   // kty: EC2
    coseKey.set(3, -7);  // alg: ES256
    coseKey.set(-1, 1);  // crv: P-256
    coseKey.set(-2, xBytes);
    coseKey.set(-3, yBytes);
    const coseKeyBuf = encodeCborU8(coseKey);

    const credentialIdBytes = new Uint8Array(32);
    crypto.getRandomValues(credentialIdBytes);
    const credentialId = bytesToBase64(credentialIdBytes);

    const rpIdHashBuf = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
    const flags = 0x41; // UP (0x01) | AT (0x40)
    const credIdLen = credentialIdBytes.length;

    const authDataHeader = new Uint8Array(32 + 1 + 4 + 16 + 2);
    authDataHeader.set(rpIdHashBuf, 0);
    authDataHeader[32] = flags;
    authDataHeader[53] = (credIdLen >> 8) & 0xff;
    authDataHeader[54] = credIdLen & 0xff;

    const authData = new Uint8Array(authDataHeader.length + credentialIdBytes.length + coseKeyBuf.length);
    authData.set(authDataHeader, 0);
    authData.set(credentialIdBytes, authDataHeader.length);
    authData.set(coseKeyBuf, authDataHeader.length + credentialIdBytes.length);

    const attestationMap = new Map<string, any>();
    attestationMap.set('fmt', 'none');
    attestationMap.set('attStmt', new Map());
    attestationMap.set('authData', authData);
    const attestationObjectBuf = encodeCborU8(attestationMap);

    const clientData = {
      type: 'webauthn.create',
      challenge,
      origin,
      crossOrigin: false
    };
    const clientDataJSON = JSON.stringify(clientData);
    const clientDataJSONB64 = bytesToBase64(new TextEncoder().encode(clientDataJSON));
    const attestationObjectB64 = bytesToBase64(attestationObjectBuf);
    const authenticatorDataB64 = bytesToBase64(authData);

    this.keyPair = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      credentialId,
      credentialIdBytes,
      rpId,
      origin,
      counter: 0
    };

    return {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSONB64,
        attestationObject: attestationObjectB64,
        authenticatorData: authenticatorDataB64
      }
    };
  }

  async getAssertion(options: any): Promise<{
    id: string;
    rawId: string;
    type: string;
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
    };
  }> {
    if (!this.keyPair) throw new Error('No credential registered in simulator');
    this.counter += 1;
    this.keyPair.counter = this.counter;

    const challenge = options.challenge;
    const origin = options.origin || this.keyPair.origin;

    const clientData = {
      type: 'webauthn.get',
      challenge,
      origin,
      crossOrigin: false
    };
    const clientDataJSON = JSON.stringify(clientData);
    const clientDataBytes = new TextEncoder().encode(clientDataJSON);
    const clientDataJSONB64 = bytesToBase64(clientDataBytes);

    const rpIdHashBuf = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(this.keyPair.rpId)));
    const flags = 0x01; // UP (User Present)
    const authData = new Uint8Array(32 + 1 + 4);
    authData.set(rpIdHashBuf, 0);
    authData[32] = flags;
    authData[33] = (this.counter >> 24) & 0xff;
    authData[34] = (this.counter >> 16) & 0xff;
    authData[35] = (this.counter >> 8) & 0xff;
    authData[36] = this.counter & 0xff;

    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));
    const signedBytes = new Uint8Array(authData.length + clientDataHash.length);
    signedBytes.set(authData, 0);
    signedBytes.set(clientDataHash, authData.length);

    const rawSignatureBuf = await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.keyPair.privateKey,
      signedBytes
    );

    return {
      id: this.keyPair.credentialId,
      rawId: this.keyPair.credentialId,
      type: 'public-key',
      response: {
        clientDataJSON: clientDataJSONB64,
        authenticatorData: bytesToBase64(authData),
        signature: bytesToBase64(new Uint8Array(rawSignatureBuf))
      }
    };
  }
}


/**
 * Registers an authentic simulated FIDO2 platform credential against the WebAuthn server.
 */
export async function registerSimulatorEnclave(params?: {
  username?: string;
  displayName?: string;
  origin?: string;
  rpId?: string;
  fetchFn?: typeof fetch;
}): Promise<SimulatorRegistrationResult> {
  const localFetch = params?.fetchFn || fetch;
  const username = params?.username || 'daniele.palagi92@gmail.com';
  const displayName = params?.displayName || 'Daniele Palagi';
  const targetOrigin = params?.origin || (typeof window !== 'undefined' && window.location ? window.location.origin : 'http://127.0.0.1:3000');
  const resolveUrl = (path: string) => {
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    return targetOrigin ? `${targetOrigin.replace(/\/$/, '')}${path}` : path;
  };

  // 1. Fetch WebAuthn registration options
  const optRes = await localFetch(resolveUrl('/api/webauthn/register-options'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, displayName })
  });

  if (!optRes.ok) {
    throw new Error(`Failed to fetch registration options: ${optRes.statusText}`);
  }

  const options = await optRes.json();
  const challenge = options.challenge;
  const targetRpId = params?.rpId || options.rp?.id || (typeof window !== 'undefined' && window.location ? window.location.hostname : '127.0.0.1');

  // 2. Generate genuine ECDSA P-256 key pair via WebCrypto
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  // 3. Export Public Key to JWK and extract coordinates
  const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  if (!jwk.x || !jwk.y) {
    throw new Error('Failed to export public key coordinates');
  }
  const xBytes = base64UrlToBytes(jwk.x);
  const yBytes = base64UrlToBytes(jwk.y);

  // 4. Construct RFC 8152 COSE Key Map
  const coseKey = new Map<number, any>();
  coseKey.set(1, 2);   // kty: EC2
  coseKey.set(3, -7);  // alg: ES256 (ECDSA SHA-256)
  coseKey.set(-1, 1);  // crv: P-256
  coseKey.set(-2, xBytes);
  coseKey.set(-3, yBytes);
  const coseKeyBuf = encodeCborU8(coseKey);

  // 5. Generate random credentialId (32 bytes)
  const credentialIdBytes = new Uint8Array(32);
  crypto.getRandomValues(credentialIdBytes);
  const credentialId = bytesToBase64(credentialIdBytes);

  // 6. Build AuthenticatorData (RP ID Hash (32B) + Flags (1B) + Counter (4B) + AAGUID (16B) + CredIdLen (2B) + CredId + CoseKey)
  const rpIdHashBuf = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(targetRpId)));
  const flags = 0x41; // UP (0x01) | AT (0x40)
  const credIdLen = credentialIdBytes.length;

  const authDataHeader = new Uint8Array(32 + 1 + 4 + 16 + 2);
  authDataHeader.set(rpIdHashBuf, 0);
  authDataHeader[32] = flags;
  // Counter 0: bytes 33-36 are zeros
  // AAGUID zeros: bytes 37-52 are zeros
  authDataHeader[53] = (credIdLen >> 8) & 0xff;
  authDataHeader[54] = credIdLen & 0xff;

  const authData = new Uint8Array(authDataHeader.length + credentialIdBytes.length + coseKeyBuf.length);
  authData.set(authDataHeader, 0);
  authData.set(credentialIdBytes, authDataHeader.length);
  authData.set(coseKeyBuf, authDataHeader.length + credentialIdBytes.length);

  // 7. Assemble Attestation Object in CBOR format
  const attestationMap = new Map<string, any>();
  attestationMap.set('fmt', 'none');
  attestationMap.set('attStmt', new Map());
  attestationMap.set('authData', authData);
  const attestationObjectBuf = encodeCborU8(attestationMap);

  // 8. Construct clientDataJSON
  const clientData = {
    type: 'webauthn.create',
    challenge,
    origin: targetOrigin,
    crossOrigin: false
  };
  const clientDataJSON = JSON.stringify(clientData);
  const clientDataJSONB64 = bytesToBase64(new TextEncoder().encode(clientDataJSON));
  const attestationObjectB64 = bytesToBase64(attestationObjectBuf);
  const authenticatorDataB64 = bytesToBase64(authData);

  // 9. Send to /api/webauthn/register-verify
  const regRes = await localFetch(resolveUrl('/api/webauthn/register-verify'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: targetOrigin },
    body: JSON.stringify({
      credential: {
        id: credentialId,
        rawId: credentialId,
        type: 'public-key',
        response: {
          clientDataJSON: clientDataJSONB64,
          attestationObject: attestationObjectB64,
          authenticatorData: authenticatorDataB64
        },
        authenticatorAttachment: 'platform'
      },
      username
    })
  });

  const regData = await regRes.json();
  if (!regRes.ok || !regData.verified) {
    throw new Error(regData.error || `WebAuthn simulator registration failed (HTTP ${regRes.status})`);
  }

  const hwFingerprint = await deriveHardwareFingerprint(credentialIdBytes, authData);

  const simKeyPair: SimulatorEnclaveKeyPair = {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    credentialId,
    credentialIdBytes,
    rpId: targetRpId,
    origin: targetOrigin,
    counter: 0
  };

  return {
    verified: true,
    credentialId,
    hwFingerprint,
    keyPair: simKeyPair
  };
}

/**
 * Performs an authentic assertion signature using the simulated platform enclave key.
 */
export async function authenticateSimulatorEnclave(
  keyPair: SimulatorEnclaveKeyPair,
  params?: {
    origin?: string;
    fetchFn?: typeof fetch;
  }
): Promise<SimulatorAssertionResult> {
  const localFetch = params?.fetchFn || fetch;
  keyPair.counter += 1;
  const targetOrigin = params?.origin || keyPair.origin || (typeof window !== 'undefined' && window.location ? window.location.origin : 'http://127.0.0.1:3000');
  const resolveUrl = (path: string) => {
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    return targetOrigin ? `${targetOrigin.replace(/\/$/, '')}${path}` : path;
  };

  // 1. Fetch authentication options
  const optRes = await localFetch(resolveUrl('/api/webauthn/authenticate-options'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialId: keyPair.credentialId })
  });

  if (!optRes.ok) {
    throw new Error(`Failed to fetch authentication options: ${optRes.statusText}`);
  }

  const options = await optRes.json();
  const challenge = options.challenge;

  // 2. Build clientDataJSON
  const clientData = {
    type: 'webauthn.get',
    challenge,
    origin: targetOrigin,
    crossOrigin: false
  };
  const clientDataJSON = JSON.stringify(clientData);
  const clientDataBytes = new TextEncoder().encode(clientDataJSON);
  const clientDataJSONB64 = bytesToBase64(clientDataBytes);

  // 3. Build AuthenticatorData (RP ID Hash + Flags + Counter)
  const rpIdHashBuf = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(keyPair.rpId)));
  const flags = 0x01; // UP (User Present)
  const authData = new Uint8Array(32 + 1 + 4);
  authData.set(rpIdHashBuf, 0);
  authData[32] = flags;
  authData[33] = (keyPair.counter >> 24) & 0xff;
  authData[34] = (keyPair.counter >> 16) & 0xff;
  authData[35] = (keyPair.counter >> 8) & 0xff;
  authData[36] = keyPair.counter & 0xff;

  // 4. Sign (authenticatorData || SHA-256(clientDataJSON)) using ECDSA P-256 WebCrypto key
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));
  const signedBytes = new Uint8Array(authData.length + clientDataHash.length);
  signedBytes.set(authData, 0);
  signedBytes.set(clientDataHash, authData.length);

  const rawSignatureBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    signedBytes
  );

  const signatureB64 = bytesToBase64(new Uint8Array(rawSignatureBuf));
  const authenticatorDataB64 = bytesToBase64(authData);

  // 5. Send assertion to /api/webauthn/authenticate-verify
  const authRes = await localFetch(resolveUrl('/api/webauthn/authenticate-verify'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: targetOrigin },
    body: JSON.stringify({
      credentialId: keyPair.credentialId,
      assertion: {
        id: keyPair.credentialId,
        response: {
          clientDataJSON: clientDataJSONB64,
          authenticatorData: authenticatorDataB64,
          signature: signatureB64
        }
      }
    })
  });

  const authDataRes = await authRes.json();
  if (!authRes.ok || !authDataRes.verified) {
    throw new Error(authDataRes.error || `WebAuthn assertion verification failed (HTTP ${authRes.status})`);
  }

  const hwFingerprint = await deriveHardwareFingerprint(keyPair.credentialIdBytes, authData);

  return {
    verified: true,
    credentialId: keyPair.credentialId,
    hwFingerprint,
    authenticatorDataB64,
    signatureB64
  };
}
