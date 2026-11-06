/**
 * Dual-Key Sovereign Validation System (DK-SVS)
 * TRL 6 Operational Pilot: Hardware Security Key & Enclave Binding via WebAuthn / FIDO2 / CTAP2
 * Interacts with Apple Secure Enclave / Android StrongBox / TPM 2.0 and YubiKey CTAP2 tokens.
 */

import { bytesToBase64, base64UrlToBytes } from './crypto/encoding';

export interface WebAuthnCredentialInfo {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject?: string;
    authenticatorData?: string;
    signature?: string;
    userHandle?: string;
  };
  authenticatorAttachment?: string;
  aaguid?: string;
  deviceName?: string;
  userVerified?: boolean;
}

export type BilanxAuthenticatorTransport = AuthenticatorTransport | 'smart-card';

export interface RegisterKeyOptions {
  authenticatorAttachment?: 'platform' | 'cross-platform';
  userVerification?: UserVerificationRequirement;
  residentKey?: ResidentKeyRequirement;
  requireResidentKey?: boolean;
  requireUserVerification?: boolean;
  baseUrl?: string;
  fetchFn?: typeof fetch;
}

export interface AuthenticateKeyOptions {
  transports?: BilanxAuthenticatorTransport[];
  userVerification?: UserVerificationRequirement;
  requireUserVerification?: boolean;
  baseUrl?: string;
  fetchFn?: typeof fetch;
}

/**
 * Checks if the current client device supports user-verifying platform authenticators (Touch ID, Face ID, Windows Hello).
 */
export async function isHardwareEnclaveAvailable(): Promise<boolean> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    return false;
  }
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Checks if cross-platform roaming security keys (YubiKey, CTAP2 USB/NFC) are supported in browser.
 */
export async function isCrossPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    return false;
  }
  return true;
}

/**
 * Generates a new hardware-bound WebAuthn credential inside the device's Secure Enclave, TPM, or YubiKey.
 */
export async function registerHardwareEnclaveKey(
  username: string = 'daniele.palagi92@gmail.com',
  displayName: string = 'Daniele Palagi',
  options?: RegisterKeyOptions
): Promise<WebAuthnCredentialInfo> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    throw new Error('WebAuthn / Hardware Enclave is not supported on this browser.');
  }

  const localFetch = options?.fetchFn || fetch;
  const baseUrl = options?.baseUrl || (window.location ? window.location.origin : '');
  const resolveUrl = (path: string) => baseUrl ? `${baseUrl.replace(/\/$/, '')}${path}` : path;
  const targetAttachment = options?.authenticatorAttachment || 'platform';

  // 1. Fetch challenge options from server
  const optRes = await localFetch(resolveUrl('/api/webauthn/register-options'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username,
      displayName,
      authenticatorAttachment: targetAttachment,
      residentKey: options?.residentKey || 'preferred',
      requireResidentKey: options?.requireResidentKey || false
    })
  });

  if (!optRes.ok) {
    throw new Error(`Failed to fetch WebAuthn registration options: ${optRes.statusText}`);
  }

  const serverOptions = await optRes.json();

  // Convert challenge string to Uint8Array
  const challengeBuffer = base64UrlToBytes(serverOptions.challenge);
  const userIdBuffer = new TextEncoder().encode(serverOptions.user.id);

  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge: challengeBuffer,
    rp: {
      name: serverOptions.rp.name || 'Project Bilanx Sovereign Node',
      id: window.location.hostname
    },
    user: {
      id: userIdBuffer,
      name: serverOptions.user.name,
      displayName: serverOptions.user.displayName
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },  // ES256 (ECDSA P-256)
      { alg: -257, type: 'public-key' } // RS256 (RSA SHA-256)
    ],
    authenticatorSelection: {
      authenticatorAttachment: targetAttachment,
      userVerification: options?.userVerification || 'preferred',
      residentKey: options?.residentKey || 'preferred',
      requireResidentKey: options?.requireResidentKey || false
    },
    timeout: 60000,
    attestation: 'direct'
  };

  // 2. Invoke WebAuthn API to trigger Secure Enclave or YubiKey prompt
  const credential = (await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error('WebAuthn credential creation was cancelled or failed.');
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  const rawIdB64 = bytesToBase64(new Uint8Array(credential.rawId));
  const clientDataJSONB64 = bytesToBase64(new Uint8Array(response.clientDataJSON));
  const attestationObjectB64 = bytesToBase64(new Uint8Array(response.attestationObject));

  const credentialInfo: WebAuthnCredentialInfo = {
    id: credential.id,
    rawId: rawIdB64,
    type: credential.type,
    response: {
      clientDataJSON: clientDataJSONB64,
      attestationObject: attestationObjectB64
    },
    authenticatorAttachment: credential.authenticatorAttachment || targetAttachment
  };

  // 3. Verify attestation on backend
  const verifyRes = await localFetch(resolveUrl('/api/webauthn/register-verify'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: credentialInfo, username })
  });

  const verifyData = await verifyRes.json();
  if (!verifyRes.ok || !verifyData.verified) {
    throw new Error(verifyData.error || 'Server WebAuthn attestation verification failed.');
  }

  if (verifyData.credential) {
    credentialInfo.aaguid = verifyData.credential.aaguid;
    credentialInfo.deviceName = verifyData.credential.deviceName;
    credentialInfo.userVerified = verifyData.credential.userVerified;
  }

  return credentialInfo;
}

/**
 * Registers an authentic cross-platform hardware security key (YubiKey 5 / CTAP2 Token).
 */
export async function registerCrossPlatformKey(
  username: string = 'daniele.palagi92@gmail.com',
  displayName: string = 'Daniele Palagi',
  options?: Omit<RegisterKeyOptions, 'authenticatorAttachment'>
): Promise<WebAuthnCredentialInfo> {
  return registerHardwareEnclaveKey(username, displayName, {
    ...options,
    authenticatorAttachment: 'cross-platform'
  });
}

/**
 * Signs a challenge using hardware Secure Enclave or YubiKey private key (WebAuthn assertion).
 */
export async function authenticateWithHardwareEnclave(
  credentialId: string,
  challengeId?: string,
  options?: AuthenticateKeyOptions
): Promise<WebAuthnCredentialInfo> {
  if (typeof window === 'undefined' || !window.PublicKeyCredential) {
    throw new Error('WebAuthn / Hardware Enclave is not supported on this browser.');
  }

  const localFetch = options?.fetchFn || fetch;
  const baseUrl = options?.baseUrl || (window.location ? window.location.origin : '');
  const resolveUrl = (path: string) => baseUrl ? `${baseUrl.replace(/\/$/, '')}${path}` : path;

  // 1. Fetch authentication options from server
  const optRes = await localFetch(resolveUrl('/api/webauthn/authenticate-options'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialId, challengeId })
  });

  if (!optRes.ok) {
    throw new Error(`Failed to fetch WebAuthn authentication options: ${optRes.statusText}`);
  }

  const serverOptions = await optRes.json();

  const challengeBuffer = base64UrlToBytes(serverOptions.challenge);
  const credentialIdBuffer = base64UrlToBytes(credentialId);

  const defaultTransports: BilanxAuthenticatorTransport[] = ['internal', 'usb', 'nfc', 'ble', 'hybrid'];

  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge: challengeBuffer,
    allowCredentials: [
      {
        id: credentialIdBuffer,
        type: 'public-key',
        transports: (options?.transports || defaultTransports) as AuthenticatorTransport[]
      }
    ],
    userVerification: options?.userVerification || 'preferred',
    timeout: 60000
  };

  // 2. Invoke WebAuthn assertion signature
  const assertion = (await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions
  })) as PublicKeyCredential;

  if (!assertion) {
    throw new Error('Hardware Enclave assertion signing was cancelled or failed.');
  }

  const response = assertion.response as AuthenticatorAssertionResponse;

  const rawIdB64 = bytesToBase64(new Uint8Array(assertion.rawId));
  const clientDataJSONB64 = bytesToBase64(new Uint8Array(response.clientDataJSON));
  const authenticatorDataB64 = bytesToBase64(new Uint8Array(response.authenticatorData));
  const signatureB64 = bytesToBase64(new Uint8Array(response.signature));

  const assertionInfo: WebAuthnCredentialInfo = {
    id: assertion.id,
    rawId: rawIdB64,
    type: assertion.type,
    response: {
      clientDataJSON: clientDataJSONB64,
      authenticatorData: authenticatorDataB64,
      signature: signatureB64,
      userHandle: response.userHandle ? bytesToBase64(new Uint8Array(response.userHandle)) : undefined
    },
    authenticatorAttachment: assertion.authenticatorAttachment || 'platform'
  };

  // 3. Verify assertion on backend
  const verifyRes = await localFetch(resolveUrl('/api/webauthn/authenticate-verify'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ 
      assertion: assertionInfo, 
      credentialId,
      requireUserVerification: options?.requireUserVerification 
    })
  });

  const verifyData = await verifyRes.json();
  if (!verifyRes.ok || !verifyData.verified) {
    throw new Error(verifyData.error || 'Server WebAuthn assertion verification failed.');
  }

  if (verifyData.credential) {
    assertionInfo.aaguid = verifyData.credential.aaguid;
    assertionInfo.deviceName = verifyData.credential.deviceName;
    assertionInfo.userVerified = verifyData.credential.userVerified;
  }

  return assertionInfo;
}

/**
 * Signs a challenge using a cross-platform roaming security key (YubiKey 5).
 */
export async function authenticateCrossPlatformKey(
  credentialId: string,
  challengeId?: string,
  options?: AuthenticateKeyOptions
): Promise<WebAuthnCredentialInfo> {
  return authenticateWithHardwareEnclave(credentialId, challengeId, {
    ...options,
    transports: options?.transports || ['usb', 'nfc', 'ble', 'hybrid', 'smart-card']
  });
}
