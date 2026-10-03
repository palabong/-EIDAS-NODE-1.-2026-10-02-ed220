/**
 * Dual-Key Sovereign Validation System (DK-SVS)
 * Phase 2 (TRL 5): Hardware Enclave Binding via WebAuthn / FIDO2
 * Interacts directly with Apple Secure Enclave / Android StrongBox / TPM 2.0 hardware.
 */

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
}

/**
 * Checks if the current client device supports hardware-backed authenticators (Touch ID, Face ID, YubiKey, TPM).
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
 * Generates a new hardware-bound WebAuthn credential inside the device's Secure Enclave / TPM.
 */
export async function registerHardwareEnclaveKey(
  username: string = 'daniele.palagi92@gmail.com',
  displayName: string = 'Daniele Palagi'
): Promise<WebAuthnCredentialInfo> {
  if (!window.PublicKeyCredential) {
    throw new Error('WebAuthn / Hardware Enclave is not supported on this browser.');
  }

  // 1. Fetch challenge options from server
  const optRes = await fetch('/api/webauthn/register-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, displayName })
  });

  if (!optRes.ok) {
    throw new Error(`Failed to fetch WebAuthn registration options: ${optRes.statusText}`);
  }

  const options = await optRes.json();

  // Convert challenge string to Uint8Array
  const challengeBuffer = Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const userIdBuffer = new TextEncoder().encode(options.user.id);

  const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
    challenge: challengeBuffer,
    rp: {
      name: options.rp.name || 'Project Bilanx Sovereign Node',
      id: window.location.hostname
    },
    user: {
      id: userIdBuffer,
      name: options.user.name,
      displayName: options.user.displayName
    },
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },  // ES256 (ECDSA P-256)
      { alg: -257, type: 'public-key' } // RS256 (RSA SHA-256)
    ],
    authenticatorSelection: {
      authenticatorAttachment: 'platform', // Forces Touch ID / Apple Secure Enclave / Windows Hello
      userVerification: 'preferred',
      residentKey: 'discouraged'
    },
    timeout: 60000,
    attestation: 'direct'
  };

  // 2. Invoke WebAuthn API to trigger Secure Enclave prompt
  const credential = (await navigator.credentials.create({
    publicKey: publicKeyCredentialCreationOptions
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error('WebAuthn credential creation was cancelled or failed.');
  }

  const response = credential.response as AuthenticatorAttestationResponse;

  const rawIdB64 = btoa(String.fromCharCode(...new Uint8Array(credential.rawId)));
  const clientDataJSONB64 = btoa(String.fromCharCode(...new Uint8Array(response.clientDataJSON)));
  const attestationObjectB64 = btoa(String.fromCharCode(...new Uint8Array(response.attestationObject)));

  const credentialInfo: WebAuthnCredentialInfo = {
    id: credential.id,
    rawId: rawIdB64,
    type: credential.type,
    response: {
      clientDataJSON: clientDataJSONB64,
      attestationObject: attestationObjectB64
    },
    authenticatorAttachment: credential.authenticatorAttachment || 'platform'
  };

  // 3. Verify attestation on backend
  const verifyRes = await fetch('/api/webauthn/register-verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credential: credentialInfo, username })
  });

  const verifyData = await verifyRes.json();
  if (!verifyRes.ok || !verifyData.verified) {
    throw new Error(verifyData.error || 'Server WebAuthn attestation verification failed.');
  }

  return credentialInfo;
}

/**
 * Signs a challenge using the hardware Secure Enclave private key (WebAuthn assertion).
 */
export async function authenticateWithHardwareEnclave(
  credentialId: string,
  challengeId?: string
): Promise<WebAuthnCredentialInfo> {
  if (!window.PublicKeyCredential) {
    throw new Error('WebAuthn / Hardware Enclave is not supported on this browser.');
  }

  // 1. Fetch authentication options from server
  const optRes = await fetch('/api/webauthn/authenticate-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ credentialId, challengeId })
  });

  if (!optRes.ok) {
    throw new Error(`Failed to fetch WebAuthn authentication options: ${optRes.statusText}`);
  }

  const options = await optRes.json();

  const challengeBuffer = Uint8Array.from(atob(options.challenge.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const credentialIdBuffer = Uint8Array.from(atob(credentialId.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));

  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge: challengeBuffer,
    allowCredentials: [
      {
        id: credentialIdBuffer,
        type: 'public-key',
        transports: ['internal']
      }
    ],
    userVerification: 'preferred',
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

  const rawIdB64 = btoa(String.fromCharCode(...new Uint8Array(assertion.rawId)));
  const clientDataJSONB64 = btoa(String.fromCharCode(...new Uint8Array(response.clientDataJSON)));
  const authenticatorDataB64 = btoa(String.fromCharCode(...new Uint8Array(response.authenticatorData)));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(response.signature)));

  const assertionInfo: WebAuthnCredentialInfo = {
    id: assertion.id,
    rawId: rawIdB64,
    type: assertion.type,
    response: {
      clientDataJSON: clientDataJSONB64,
      authenticatorData: authenticatorDataB64,
      signature: signatureB64,
      userHandle: response.userHandle ? btoa(String.fromCharCode(...new Uint8Array(response.userHandle))) : undefined
    },
    authenticatorAttachment: assertion.authenticatorAttachment || 'platform'
  };

  // 3. Verify assertion on backend
  const verifyRes = await fetch('/api/webauthn/authenticate-verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ assertion: assertionInfo, credentialId })
  });

  const verifyData = await verifyRes.json();
  if (!verifyRes.ok || !verifyData.verified) {
    throw new Error(verifyData.error || 'Server WebAuthn assertion verification failed.');
  }

  return assertionInfo;
}
