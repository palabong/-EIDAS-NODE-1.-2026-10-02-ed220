/**
 * Deterministic Headless CTAP2 Hardware Security Key Test Harness
 * Project Bilanx — TRL 6 Operational Pilot Sandbox
 * 
 * Provides an authentic, headless emulation of roaming CTAP2 / FIDO2 hardware security keys
 * (YubiKey 5 Series, Security Key NFC, etc.) for automated CI/CD testing without physical user gestures.
 * 
 * Features:
 * - Authentic ECDSA P-256 (ES256) keypair generation via WebCrypto (RFC 8152 COSE Key Map)
 * - YubiKey 5 Series AAGUID (ee882879-721c-4916-ad4e-57c7f15f6f19)
 * - Authentic packed self-attestation statements with authentic ECDSA P-256 signature
 * - Monotonic signature counter tracking (anti-cloning)
 * - UP (User Present) and UV (User Verified) flag simulation (PIN / biometric gesture)
 * - cross-platform authenticatorAttachment
 * - Anti-tampering test simulation methods (cloned counter, mutated signature, replay challenge)
 */

import { 
  bytesToBase64, 
  base64ToBytes,
  base64UrlToBytes, 
  bytesToHex, 
  encodeCborU8 
} from './encoding.ts';

export const YUBIKEY_5_SERIES_AAGUID = 'ee882879-721c-4916-ad4e-57c7f15f6f19';

export interface Ctap2KeyCredentials {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  credentialId: string;
  credentialIdBytes: Uint8Array;
  rpId: string;
  origin: string;
  counter: number;
  aaguid: string;
}

export interface Ctap2RegistrationResult {
  verified: boolean;
  credentialId: string;
  aaguid: string;
  deviceName: string;
  hwFingerprint: string;
  authenticatorAttachment: 'cross-platform';
  counter: number;
}

export interface Ctap2AssertionResult {
  verified: boolean;
  credentialId: string;
  counter: number;
  userVerified: boolean;
  hwFingerprint: string;
  authenticatorDataB64: string;
  signatureB64: string;
}

export class Ctap2HardwareKeyHarness {
  public aaguid: string;
  public aaguidBytes: Uint8Array;
  public counter: number;
  public keyCredentials?: Ctap2KeyCredentials;
  public authenticatorAttachment: 'cross-platform' = 'cross-platform';

  constructor(options?: { aaguid?: string; initialCounter?: number }) {
    this.aaguid = options?.aaguid || YUBIKEY_5_SERIES_AAGUID;
    this.counter = options?.initialCounter ?? 0;
    this.aaguidBytes = this.parseAaguidToBytes(this.aaguid);
  }

  private parseAaguidToBytes(uuid: string): Uint8Array {
    const clean = uuid.replace(/-/g, '');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      bytes[i] = parseInt(clean.substring(i * 2, i * 2 + 2), 16) || 0;
    }
    return bytes;
  }

  /**
   * Generates a new hardware credential (authenticatorMakeCredential).
   */
  async makeCredential(params: {
    challenge: string;
    rpId: string;
    origin: string;
    userVerified?: boolean;
    attestationFmt?: 'packed' | 'none' | string;
    x5c?: Uint8Array[];
    attestationPrivateKey?: CryptoKey;
    tamperAttestationSignature?: boolean;
    reuseCredentials?: boolean;
  }): Promise<{
    id: string;
    rawId: string;
    type: 'public-key';
    authenticatorAttachment: 'cross-platform';
    response: {
      clientDataJSON: string;
      attestationObject: string;
      authenticatorData: string;
    };
  }> {
    const { challenge, rpId, origin, userVerified = true, attestationFmt = 'packed' } = params;

    // 1. Generate or reuse ECDSA P-256 key pair inside simulated secure hardware
    const keyPair = (params.reuseCredentials && this.keyCredentials)
      ? { privateKey: this.keyCredentials.privateKey, publicKey: this.keyCredentials.publicKey }
      : await crypto.subtle.generateKey(
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['sign', 'verify']
        );

    // 2. Export public key to COSE Key map
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

    // 3. Generate or reuse credential ID (32 bytes)
    const credentialIdBytes = (params.reuseCredentials && this.keyCredentials)
      ? this.keyCredentials.credentialIdBytes
      : (() => {
          const b = new Uint8Array(32);
          crypto.getRandomValues(b);
          return b;
        })();
    const credentialId = bytesToBase64(credentialIdBytes);

    // 4. Construct AuthenticatorData (authData)
    // Layout: rpIdHash (32) + flags (1) + signCount (4) + aaguid (16) + credIdLen (2) + credId (32) + coseKey
    const rpIdHashBuf = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
    // Flags: UP (0x01), UV (0x04 if userVerified), AT (0x40)
    const flags = 0x01 | 0x40 | (userVerified ? 0x04 : 0x00);
    const credIdLen = credentialIdBytes.length;

    const authDataHeader = new Uint8Array(32 + 1 + 4 + 16 + 2);
    authDataHeader.set(rpIdHashBuf, 0);
    authDataHeader[32] = flags;
    // Initial counter 0 during registration
    authDataHeader[33] = 0;
    authDataHeader[34] = 0;
    authDataHeader[35] = 0;
    authDataHeader[36] = 0;
    authDataHeader.set(this.aaguidBytes, 37);
    authDataHeader[53] = (credIdLen >> 8) & 0xff;
    authDataHeader[54] = credIdLen & 0xff;

    const authData = new Uint8Array(authDataHeader.length + credentialIdBytes.length + coseKeyBuf.length);
    authData.set(authDataHeader, 0);
    authData.set(credentialIdBytes, authDataHeader.length);
    authData.set(coseKeyBuf, authDataHeader.length + credentialIdBytes.length);

    // 5. Construct clientDataJSON
    const clientData = {
      type: 'webauthn.create',
      challenge,
      origin,
      crossOrigin: false
    };
    const clientDataJSON = JSON.stringify(clientData);
    const clientDataBytes = new TextEncoder().encode(clientDataJSON);
    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));

    // 6. Build Attestation Object (packed, none, or custom)
    const attestationMap = new Map<string, any>();
    if (attestationFmt === 'packed') {
      const signedBytes = new Uint8Array(authData.length + clientDataHash.length);
      signedBytes.set(authData, 0);
      signedBytes.set(clientDataHash, authData.length);

      const signingKey = params.attestationPrivateKey || keyPair.privateKey;
      let rawSig = new Uint8Array(await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        signingKey,
        signedBytes
      ));

      if (params.tamperAttestationSignature) {
        rawSig = new Uint8Array(rawSig);
        rawSig[rawSig.length - 1] ^= 0xff;
      }

      const attStmt = new Map<string, any>();
      attStmt.set('alg', -7);
      attStmt.set('sig', rawSig);
      if (params.x5c && params.x5c.length > 0) {
        attStmt.set('x5c', params.x5c);
      }
      attestationMap.set('fmt', 'packed');
      attestationMap.set('attStmt', attStmt);
    } else if (attestationFmt === 'none') {
      attestationMap.set('fmt', 'none');
      attestationMap.set('attStmt', new Map());
    } else {
      attestationMap.set('fmt', attestationFmt);
      attestationMap.set('attStmt', new Map());
    }

    attestationMap.set('authData', authData);
    const attestationObjectBuf = encodeCborU8(attestationMap);

    this.keyCredentials = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
      credentialId,
      credentialIdBytes,
      rpId,
      origin,
      counter: 0,
      aaguid: this.aaguid
    };

    return {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: {
        clientDataJSON: bytesToBase64(clientDataBytes),
        attestationObject: bytesToBase64(attestationObjectBuf),
        authenticatorData: bytesToBase64(authData)
      }
    };
  }

  /**
   * Generates a signed assertion (authenticatorGetAssertion).
   */
  async getAssertion(params: {
    challenge: string;
    rpId?: string;
    origin?: string;
    userVerified?: boolean;
    incrementCounter?: boolean;
    overrideCounter?: number;
    tamperSignature?: boolean;
  }): Promise<{
    id: string;
    rawId: string;
    type: 'public-key';
    authenticatorAttachment: 'cross-platform';
    response: {
      clientDataJSON: string;
      authenticatorData: string;
      signature: string;
    };
  }> {
    if (!this.keyCredentials) {
      throw new Error('No credential registered in CTAP2 harness. Call makeCredential first.');
    }

    const { 
      challenge, 
      rpId = this.keyCredentials.rpId, 
      origin = this.keyCredentials.origin,
      userVerified = true,
      incrementCounter = true,
      overrideCounter,
      tamperSignature = false
    } = params;

    // Increment strictly monotonic counter (unless explicitly overridden or clone simulated)
    if (overrideCounter !== undefined) {
      this.counter = overrideCounter;
    } else if (incrementCounter) {
      this.counter += 1;
    }
    this.keyCredentials.counter = this.counter;

    // 1. Construct clientDataJSON
    const clientData = {
      type: 'webauthn.get',
      challenge,
      origin,
      crossOrigin: false
    };
    const clientDataJSON = JSON.stringify(clientData);
    const clientDataBytes = new TextEncoder().encode(clientDataJSON);
    const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));

    // 2. Construct authData (rpIdHash (32) + flags (1) + counter (4))
    const rpIdHashBuf = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)));
    // Flags: UP (0x01) | UV (0x04 if userVerified)
    const flags = 0x01 | (userVerified ? 0x04 : 0x00);

    const authData = new Uint8Array(32 + 1 + 4);
    authData.set(rpIdHashBuf, 0);
    authData[32] = flags;
    authData[33] = (this.counter >> 24) & 0xff;
    authData[34] = (this.counter >> 16) & 0xff;
    authData[35] = (this.counter >> 8) & 0xff;
    authData[36] = this.counter & 0xff;

    // 3. Sign authData || clientDataHash
    const signedBytes = new Uint8Array(authData.length + clientDataHash.length);
    signedBytes.set(authData, 0);
    signedBytes.set(clientDataHash, authData.length);

    let rawSig = new Uint8Array(await crypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      this.keyCredentials.privateKey,
      signedBytes
    ));

    if (tamperSignature) {
      rawSig = new Uint8Array(rawSig);
      rawSig[rawSig.length - 2] ^= 0xff; // flip bits
    }

    return {
      id: this.keyCredentials.credentialId,
      rawId: this.keyCredentials.credentialId,
      type: 'public-key',
      authenticatorAttachment: 'cross-platform',
      response: {
        clientDataJSON: bytesToBase64(clientDataBytes),
        authenticatorData: bytesToBase64(authData),
        signature: bytesToBase64(rawSig)
      }
    };
  }

  /**
   * Registers this CTAP2 key directly against the server endpoints.
   */
  async registerWithServer(params: {
    baseUrl: string;
    username?: string;
    displayName?: string;
    attestationFmt?: 'packed' | 'none' | string;
    x5c?: Uint8Array[];
    attestationPrivateKey?: CryptoKey;
    tamperAttestationSignature?: boolean;
    userVerified?: boolean;
    requireUserVerification?: boolean;
    reuseCredentials?: boolean;
    fetchFn?: typeof fetch;
  }): Promise<Ctap2RegistrationResult> {
    const localFetch = params.fetchFn || fetch;
    const username = params.username || 'yubikey-operator@bilanx.pilot';
    const displayName = params.displayName || 'YubiKey 5 Pilot Operator';
    const resolveUrl = (path: string) => `${params.baseUrl.replace(/\/$/, '')}${path}`;

    // 1. Fetch registration options
    const optRes = await localFetch(resolveUrl('/api/webauthn/register-options'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        displayName,
        authenticatorAttachment: 'cross-platform',
        userVerification: params.requireUserVerification ? 'required' : 'preferred'
      })
    });

    if (!optRes.ok) {
      throw new Error(`Failed to fetch WebAuthn registration options: ${optRes.statusText}`);
    }

    const options = await optRes.json();
    const parsedUrl = new URL(params.baseUrl);
    const rpId = options.rp?.id || parsedUrl.hostname;
    const origin = parsedUrl.origin;

    // 2. Generate hardware credential
    const credPayload = await this.makeCredential({
      challenge: options.challenge,
      rpId,
      origin,
      attestationFmt: params.attestationFmt || 'packed',
      x5c: params.x5c,
      attestationPrivateKey: params.attestationPrivateKey,
      tamperAttestationSignature: params.tamperAttestationSignature,
      userVerified: params.userVerified ?? true,
      reuseCredentials: params.reuseCredentials
    });

    // 3. Submit registration to server
    const regRes = await localFetch(resolveUrl('/api/webauthn/register-verify'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin },
      body: JSON.stringify({
        credential: credPayload,
        username,
        requireUserVerification: params.requireUserVerification
      })
    });

    const regData = await regRes.json();
    if (!regRes.ok || !regData.verified) {
      throw new Error(regData.error || 'Server rejected CTAP2 key registration');
    }

    const hwFingerprint = await this.deriveHardwareFingerprint(
      this.keyCredentials!.credentialIdBytes,
      base64ToBytes(credPayload.response.authenticatorData)
    );

    return {
      verified: true,
      credentialId: this.keyCredentials!.credentialId,
      aaguid: regData.credential?.aaguid || this.aaguid,
      deviceName: regData.credential?.deviceName || 'YubiKey 5 Series (NFC / USB)',
      hwFingerprint,
      authenticatorAttachment: 'cross-platform',
      counter: 0
    };
  }

  /**
   * Builds a fresh assertion and leaves server verification to the caller.
   * Clearance uses this so the UV flag and counter are checked in that request.
   */
  async prepareAssertion(params: {
    baseUrl: string;
    overrideCounter?: number;
    tamperSignature?: boolean;
    userVerified?: boolean;
    fetchFn?: typeof fetch;
  }): Promise<{
    credentialId: string;
    assertion: {
      id: string;
      rawId: string;
      type: 'public-key';
      authenticatorAttachment: 'cross-platform';
      response: {
        clientDataJSON: string;
        authenticatorData: string;
        signature: string;
      };
    };
  }> {
    if (!this.keyCredentials) throw new Error('CTAP2 key not registered');
    const localFetch = params.fetchFn || fetch;
    const resolveUrl = (path: string) => `${params.baseUrl.replace(/\/$/, '')}${path}`;
    const parsedUrl = new URL(params.baseUrl);
    const optRes = await localFetch(resolveUrl('/api/webauthn/authenticate-options'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credentialId: this.keyCredentials.credentialId })
    });
    if (!optRes.ok) {
      throw new Error(`Failed to fetch authentication options: ${optRes.statusText}`);
    }
    const options = await optRes.json();
    const assertion = await this.getAssertion({
      challenge: options.challenge,
      rpId: parsedUrl.hostname,
      origin: parsedUrl.origin,
      userVerified: params.userVerified ?? true,
      overrideCounter: params.overrideCounter,
      tamperSignature: params.tamperSignature
    });
    return { credentialId: this.keyCredentials.credentialId, assertion };
  }

  /**
   * Performs an assertion verification against the server endpoints.
   */
  async authenticateWithServer(params: {
    baseUrl: string;
    overrideCounter?: number;
    tamperSignature?: boolean;
    userVerified?: boolean;
    requireUserVerification?: boolean;
    fetchFn?: typeof fetch;
  }): Promise<Ctap2AssertionResult> {
    if (!this.keyCredentials) throw new Error('CTAP2 key not registered');
    const localFetch = params.fetchFn || fetch;
    const resolveUrl = (path: string) => `${params.baseUrl.replace(/\/$/, '')}${path}`;
    const parsedUrl = new URL(params.baseUrl);
    const origin = parsedUrl.origin;

    // 1. Fetch challenge
    const optRes = await localFetch(resolveUrl('/api/webauthn/authenticate-options'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credentialId: this.keyCredentials.credentialId })
    });

    if (!optRes.ok) {
      throw new Error(`Failed to fetch authentication options: ${optRes.statusText}`);
    }

    const options = await optRes.json();

    // 2. Sign assertion
    const assertionPayload = await this.getAssertion({
      challenge: options.challenge,
      rpId: parsedUrl.hostname,
      origin,
      userVerified: params.userVerified ?? true,
      overrideCounter: params.overrideCounter,
      tamperSignature: params.tamperSignature
    });

    // 3. Verify assertion on server
    const authRes = await localFetch(resolveUrl('/api/webauthn/authenticate-verify'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin },
      body: JSON.stringify({
        credentialId: this.keyCredentials.credentialId,
        assertion: assertionPayload,
        requireUserVerification: params.requireUserVerification
      })
    });

    const authData = await authRes.json();
    if (!authRes.ok || !authData.verified) {
      throw new Error(authData.error || 'Server rejected CTAP2 assertion verification');
    }

    const hwFingerprint = await this.deriveHardwareFingerprint(
      this.keyCredentials.credentialIdBytes,
      base64ToBytes(assertionPayload.response.authenticatorData)
    );

    return {
      verified: true,
      credentialId: this.keyCredentials.credentialId,
      counter: authData.counter ?? this.counter,
      userVerified: authData.userVerified ?? true,
      hwFingerprint,
      authenticatorDataB64: assertionPayload.response.authenticatorData,
      signatureB64: assertionPayload.response.signature
    };
  }

  /**
   * Derives authentic Hardware Security Key Fingerprint:
   * HW_FINGERPRINT = HE-YUBIKEY-${SHA-256(credId || authData)[0..12]}
   */
  async deriveHardwareFingerprint(
    credId: Uint8Array,
    authData: Uint8Array
  ): Promise<string> {
    const combined = new Uint8Array(credId.length + authData.length);
    combined.set(credId, 0);
    combined.set(authData, credId.length);
    const hashBuf = await crypto.subtle.digest('SHA-256', combined);
    const hex = bytesToHex(hashBuf);
    return `HE-YUBIKEY-${hex.slice(0, 12).toUpperCase()}`;
  }
}
