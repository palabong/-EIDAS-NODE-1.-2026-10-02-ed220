import { useState, useCallback, useEffect } from 'react';
import { KpiTelemetry } from '../../lib/KpiTelemetry';
import { useDualKeyResult } from '../context/DualKeyResultContext';
import { bufferToHex, base64ToBuffer, bufferToBase64Url, bytesToBase64 } from '../../lib/crypto/encoding';
import { clearanceMessage } from '../../lib/crypto/clearanceMessage';
import type { ClearanceEnvelope } from '../../lib/crypto/clearanceEnvelope';
import { Ctap2HardwareKeyHarness, YUBIKEY_5_SERIES_AAGUID } from '../../lib/crypto/ctap2Harness';
import { generateProof } from '../../lib/crypto/zkp/nizkp';

export type HandshakeState = 
  | 'IDLE' 
  | 'INITIATING' 
  | 'AWAITING_CHALLENGE' 
  | 'VERIFYING_SIGNATURES' 
  | 'COMPLETED' 
  | 'FAILED';

export interface WebAuthnClearanceAssertion {
  id?: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
  };
}

export interface DualKeyPayload {
  v: 1;
  challengeId: string;
  secondFactorHash: string;          // SHA-256 of the WebAuthn credential id
  userPublicKey: JsonWebKey;         // EC P-256, x + y only (no d)
  userSignature: string;             // base64url, no padding
  institutionalSignature?: string;   // base64 institutional signature over challengeId; not an acceptance input
  proofBase64?: string;              // 1,355-byte range proof, required for server clearance
  credentialId?: string;             // registered authenticator checked in this clearance
  webauthnAssertion?: WebAuthnClearanceAssertion;
  clientTs?: string;                 // optional, NOT part of signed message
}

export interface DualKeyValidationResult {
  success: boolean;
  state: HandshakeState;
  latencyMs: number;
  institutionalSignatureValid: boolean;
  userSignatureValid: boolean;
  bindingValid: boolean;
  payload?: DualKeyPayload;
  serverEnvelope?: ClearanceEnvelope;
  envelopeSignature?: string;
  sessionPolicyEnforced?: boolean;
  serverVerifyMs?: number;
  error?: string;
  logs?: string[];
  coreCryptoTime?: number;
}

interface InstitutionalChallengeResponse {
  success: boolean;
  challenge: string;
  signatureBase64: string;
  publicKeyJwk: JsonWebKey;
  keyId?: string;
  jurisdiction?: string;
  error?: string;
}

/**
 * The cryptographic algorithm used across the DK-SVS flow for both
 * Institutional and User key pairs.
 */
const ECDSA_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };

// ======================================================================
// INDEXEDDB KEY STORAGE
// ======================================================================
const DB_NAME = 'DKSVS_DB';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const USER_KEY_ID = 'dk-svs-user-keypair';

/**
 * Initializes and returns the IndexedDB instance.
 * Rejects if the browser doesn't support it or if opening fails.
 */
function getDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (typeof indexedDB === 'undefined') {
      return reject(new Error('IndexedDB is not supported in this environment'));
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
    request.onsuccess = (event) => resolve((event.target as IDBOpenDBRequest).result);
    request.onerror = (event) => reject((event.target as IDBOpenDBRequest).error);
  });
}

/**
 * Persists a CryptoKeyPair into IndexedDB using JWK format.
 * Returns true if successful, false otherwise.
 */
async function saveKeyPair(id: string, keyPair: CryptoKeyPair): Promise<boolean> {
  if (typeof indexedDB === 'undefined') return false;
  try {
    const db = await getDB();
    
    // Export keys to JWK format for safe storage
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

    return await new Promise<boolean>((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.put({ publicKeyJwk, privateKeyJwk }, id);
      
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => {
        console.error('DK-SVS Persistence: IndexedDB put request failed', tx.error);
        resolve(false);
      };
    });
  } catch (err) {
    console.warn('DK-SVS Persistence: IndexedDB unavailable for saving', err);
    return false;
  }
}

/**
 * Attempts to load and reconstruct a CryptoKeyPair from IndexedDB.
 * Returns null if not found, corrupted, or if IndexedDB is unavailable.
 */
async function loadKeyPair(id: string): Promise<CryptoKeyPair | null> {
  if (typeof indexedDB === 'undefined') return null;
  try {
    const db = await getDB();
    return await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const request = store.get(id);
      
      request.onsuccess = async () => {
        if (!request.result) {
          resolve(null);
          return;
        }
        
        try {
          const { publicKeyJwk, privateKeyJwk } = request.result;
          if (!publicKeyJwk || !privateKeyJwk) {
            throw new Error('Corrupted key pair in IndexedDB: missing JWK');
          }

          const publicKey = await crypto.subtle.importKey('jwk', publicKeyJwk, ECDSA_ALGO, true, ['verify']);
          const privateKey = await crypto.subtle.importKey('jwk', privateKeyJwk, ECDSA_ALGO, true, ['sign']);
          resolve({ publicKey, privateKey });
        } catch (e) {
          console.error('DK-SVS Persistence: Failed to reconstruct keys from JWK', e);
          resolve(null); // Fallback gracefully
        }
      };
      
      request.onerror = () => {
        console.error('DK-SVS Persistence: IndexedDB get request failed', tx.error);
        resolve(null); // Fallback instead of rejecting
      };
    });
  } catch (err) {
    console.warn('DK-SVS Persistence: IndexedDB unavailable or load failed', err);
    return null;
  }
}

/**
 * Removes a stored key pair from IndexedDB.
 * Returns true if successful, false otherwise.
 */
async function deleteKeyPair(id: string): Promise<boolean> {
  try {
    const db = await getDB();
    return await new Promise((resolve) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      store.delete(id);
      
      tx.oncomplete = () => resolve(true);
      tx.onerror = () => {
        console.error('DK-SVS Persistence: IndexedDB delete request failed', tx.error);
        resolve(false);
      };
    });
  } catch (err) {
    console.warn('DK-SVS Persistence: IndexedDB unavailable for deletion', err);
    return false;
  }
}

/**
 * useBilanxDualKeyValidationReal
 * 
 * A robust cryptographic implementation of the DK-SVS handshake using the Web Crypto API.
 * Uses ECDSA P-256 for asymmetric signing and verification.
 * Implements a strong cryptographic binding by hashing the second factor
 * before combining it with the institutional challenge.
 * 
 * NOTE: The User's key pair is now persisted in IndexedDB for demo realism,
 * surviving page reloads just like a Secure Enclave / TPM would in production.
 */
export async function performDualKeyHandshake(
  institutionId: string,
  secondFactorId: string,
  options?: {
    fetchFn?: typeof fetch;
    baseUrl?: string;
    proofBytes?: Uint8Array;
    productUid?: string;
    credentialId?: string;
    webauthnAssertion?: WebAuthnClearanceAssertion;
  } | typeof fetch
): Promise<DualKeyValidationResult & { coreCryptoTime: number }> {
  const localFetch = typeof options === 'function' ? options : (options?.fetchFn || fetch);
  const proofBytes = typeof options === 'object' ? options?.proofBytes : undefined;
  const productUid = typeof options === 'object' && typeof options?.productUid === 'string' && options.productUid.length > 0
    ? options.productUid
    : undefined;
  const suppliedCredentialId = typeof options === 'object' ? options?.credentialId : undefined;
  const suppliedAssertion = typeof options === 'object' ? options?.webauthnAssertion : undefined;
  const baseUrl = (typeof options === 'object' && options?.baseUrl) || (typeof window !== 'undefined' && window.location ? window.location.origin : '');
  const resolveUrl = (path: string) => baseUrl ? `${baseUrl.replace(/\/$/, '')}${path}` : path;

  const startTime = performance.now();
  let coreCryptoTime = 0;
  let t0 = 0;
  const logs: string[] = [];
  
  try {
    let userKeyPair = await loadKeyPair(USER_KEY_ID);
    let isUsingPersistentKeys = false;
    
    if (userKeyPair) {
      logs.push('User: Loaded persistent ECDSA P-256 key pair from IndexedDB.');
      isUsingPersistentKeys = true;
    } else {
      logs.push('User: Generating new ECDSA P-256 key pair...');
      t0 = performance.now();
      userKeyPair = await crypto.subtle.generateKey(ECDSA_ALGO, true, ['sign', 'verify']);
      coreCryptoTime += performance.now() - t0;
      
      logs.push('User: Attempting to save new key pair to IndexedDB...');
      const saved = await saveKeyPair(USER_KEY_ID, userKeyPair);
      if (saved) {
        logs.push('User: Successfully saved key pair to IndexedDB for future use.');
        isUsingPersistentKeys = true;
      } else {
        logs.push('User: Warning - Failed to save key pair. Using ephemerally for this session.');
      }
    }

    logs.push('Institution: Requesting cryptographic challenge from backend node...');
    logs.push('Institution: Waiting for institutional challenge from backend...');
    
    let challengeData: InstitutionalChallengeResponse;
    try {
      const response = await localFetch(resolveUrl('/api/institutional-challenge'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ institutionId })
      });
      
      challengeData = await response.json();
      
      if (!response.ok || !challengeData.success) {
        throw new Error(challengeData.error || `HTTP ${response.status}: Failed to fetch institutional challenge`);
      }

      if (!challengeData.challenge) {
        throw new Error('Backend response is missing the cryptographic challenge string.');
      }
      if (!challengeData.signatureBase64) {
        throw new Error('Backend response is missing the institutional signature.');
      }
      if (!challengeData.publicKeyJwk) {
        throw new Error('Backend response is missing the institutional public key.');
      }
    } catch (fetchErr: any) {
      logs.push(`Institution: ERROR - Failed to communicate with backend (${fetchErr.message})`);
      throw new Error(`Failed to securely communicate with the Institutional Node.`);
    }
    
    const challengeStr = challengeData.challenge;
    const challengeBuffer = new TextEncoder().encode(challengeStr);
    
    let instSignatureBuffer: ArrayBuffer;
    try {
      instSignatureBuffer = base64ToBuffer(challengeData.signatureBase64);
    } catch (e: any) {
      logs.push(`Institution: ERROR - ${e.message}`);
      throw new Error(`Received an invalid signature format from the Institutional Node.`);
    }
    
    logs.push('Institution: Successfully retrieved backend challenge. Importing public key...');
    let institutionPublicKey: CryptoKey;
    try {
      t0 = performance.now();
      institutionPublicKey = await crypto.subtle.importKey(
        'jwk', 
        challengeData.publicKeyJwk, 
        ECDSA_ALGO, 
        true, 
        ['verify']
      );
      coreCryptoTime += performance.now() - t0;
      logs.push('Institution: Public key imported successfully.');
    } catch (importErr: any) {
      logs.push(`Institution: ERROR - Failed to import backend public key (${importErr.message}).`);
      throw new Error(`The Institutional public key could not be processed.`);
    }
    
    logs.push('User: Received challenge. Preparing bound payload...');
    
    let credentialId = suppliedCredentialId;
    let webauthnAssertion = suppliedAssertion;
    if (!credentialId || !webauthnAssertion) {
      if (!baseUrl) {
        throw new Error('Clearance second factor requires the institutional node origin');
      }
      const factorKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      await factorKey.registerWithServer({
        baseUrl,
        username: `clearance-${crypto.randomUUID()}@bilanx.org`,
        fetchFn: localFetch,
      });
      const prepared = await factorKey.prepareAssertion({ baseUrl, fetchFn: localFetch });
      credentialId = prepared.credentialId;
      webauthnAssertion = prepared.assertion;
    }
    t0 = performance.now();
    const secondFactorHashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(credentialId));
    coreCryptoTime += performance.now() - t0;
    const secondFactorHashHex = bufferToHex(secondFactorHashBuffer);

    let proofSha256Hex = '';
    let proofBase64: string | undefined;
    if (proofBytes && proofBytes.byteLength > 0) {
      const proofDigest = await crypto.subtle.digest('SHA-256', proofBytes);
      proofSha256Hex = bufferToHex(proofDigest);
      proofBase64 = bytesToBase64(proofBytes);
    }

    const boundPayloadStr = proofSha256Hex
      ? clearanceMessage(challengeStr, secondFactorHashHex, proofSha256Hex)
      : `${challengeStr}:${secondFactorHashHex}`;
    const boundPayloadBuffer = new TextEncoder().encode(boundPayloadStr);
    
    logs.push('User: Signing the strongly bound payload...');
    t0 = performance.now();
    const userSignatureBuffer = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      userKeyPair.privateKey,
      boundPayloadBuffer
    );
    coreCryptoTime += performance.now() - t0;
    
    logs.push('Verifier: Checking Institutional signature...');
    t0 = performance.now();
    const isInstSigValid = await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      institutionPublicKey,
      instSignatureBuffer,
      challengeBuffer
    );
    coreCryptoTime += performance.now() - t0;
    
    let isUserSigValid = false;
    let isBindingValid = false;
    let payload: DualKeyPayload | undefined;
    
    let serverVerifyMs: number | undefined;
    let serverEnvelope: ClearanceEnvelope | undefined;
    let envelopeSignature: string | undefined;
    let sessionPolicyEnforced = false;
    let serverError: string | undefined;
    
    if (isInstSigValid) {
      const jwk = await crypto.subtle.exportKey('jwk', userKeyPair.publicKey);
      const publicJwk: JsonWebKey = {
        kty: jwk.kty,
        crv: jwk.crv,
        x: jwk.x,
        y: jwk.y,
        ext: jwk.ext
      };

      payload = {
        v: 1,
        challengeId: challengeStr,
        secondFactorHash: secondFactorHashHex,
        userPublicKey: publicJwk,
        userSignature: bufferToBase64Url(userSignatureBuffer),
        institutionalSignature: challengeData.signatureBase64,
        proofBase64,
        credentialId,
        webauthnAssertion,
        clientTs: new Date().toISOString()
      };

      if (!proofBase64) {
        logs.push('Verifier: Age proof missing. Local institutional check passed. Clearance was not submitted.');
        const endTime = performance.now();
        return {
          success: false,
          state: 'FAILED',
          latencyMs: Math.round(endTime - startTime),
          institutionalSignatureValid: true,
          userSignatureValid: false,
          bindingValid: false,
          payload,
          error: 'Clearance requires an age proof bound to the challenge.',
          logs,
          coreCryptoTime
        };
      }

      logs.push('Verifier: Sending payload to server for validation...');
      try {
        const verifyStart = performance.now();
        const verifyRes = await localFetch(resolveUrl('/api/v1/dual-key/verify'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          // productUid is catalog input. It is not part of the user-signed clearance message.
          body: JSON.stringify(productUid ? { ...payload, productUid } : payload)
        });
        serverVerifyMs = performance.now() - verifyStart;
        
        if (verifyRes.ok) {
          const verifyData = await verifyRes.json();
          if (verifyData.valid && verifyData.envelope && typeof verifyData.envelopeSignature === 'string') {
            isUserSigValid = true;
            isBindingValid = true;
            serverEnvelope = verifyData.envelope;
            envelopeSignature = verifyData.envelopeSignature;
            sessionPolicyEnforced = verifyData.sessionPolicyEnforced === true;
            logs.push(`Verifier: Cryptographic binding SUCCESSFUL (Server Verified in ${Math.round(serverVerifyMs)}ms).`);
          } else if (verifyData.valid) {
            serverError = 'Institutional node did not return a signed clearance envelope.';
            logs.push('Verifier: Server accepted the proof and did not return a signed envelope.');
          } else {
            serverError = typeof verifyData.reason === 'string' ? verifyData.reason : 'Clearance rejected by the institutional node';
            logs.push(`Verifier: Cryptographic binding FAILED (Server Rejected: ${serverError}).`);
          }
        } else {
          logs.push(`Verifier: Server error during verification (HTTP ${verifyRes.status}).`);
        }
      } catch (err: any) {
        logs.push(`Verifier: Network error during server verification: ${err.message}`);
      }
    } else {
      logs.push('Verifier: Cryptographic binding FAILED (Invalid Institutional Signature).');
    }
    
    const endTime = performance.now();
    const latencyMs = Math.round(endTime - startTime);

    KpiTelemetry.record('KPI-01', latencyMs, 'ms');
    KpiTelemetry.record('KPI-02', coreCryptoTime, 'ms');
    
    return {
      success: isBindingValid,
      state: isBindingValid ? 'COMPLETED' : 'FAILED',
      latencyMs,
      institutionalSignatureValid: isInstSigValid,
      userSignatureValid: isUserSigValid,
      bindingValid: isBindingValid,
      payload,
      serverEnvelope,
      envelopeSignature,
      sessionPolicyEnforced,
      serverVerifyMs,
      error: isBindingValid ? undefined : serverError,
      logs,
      coreCryptoTime
    };

  } catch (err: any) {
    console.error('Cryptographic handshake error:', err);
    const endTime = performance.now();
    const latencyMs = Math.round(endTime - startTime);
    
    KpiTelemetry.record('KPI-01', latencyMs, 'ms');
    KpiTelemetry.record('KPI-02', coreCryptoTime, 'ms');

    return {
      success: false,
      state: 'FAILED',
      latencyMs,
      institutionalSignatureValid: false,
      userSignatureValid: false,
      bindingValid: false,
      error: err.message || 'The cryptographic handshake could not be completed at this time.',
      logs,
      coreCryptoTime
    };
  }
}

export function useBilanxDualKeyValidationReal() {
  const { setResult: setContextResult } = useDualKeyResult();
  const [state, setState] = useState<HandshakeState>('IDLE');
  const [result, setResult] = useState<DualKeyValidationResult | null>(null);
  const [isUsingPersistentKeys, setIsUsingPersistentKeys] = useState(false);
  const [isKeyStorageReady, setIsKeyStorageReady] = useState(false);

  // Check if keys exist on mount safely
  useEffect(() => {
    let isMounted = true;
    
    loadKeyPair(USER_KEY_ID)
      .then(keyPair => {
        if (!isMounted) return;
        if (keyPair) {
          setIsUsingPersistentKeys(true);
        }
        setIsKeyStorageReady(true);
      })
      .catch((err) => {
        console.error('DK-SVS Persistence: Error during initial key load check', err);
        if (isMounted) setIsKeyStorageReady(true);
      });

    return () => { isMounted = false; };
  }, []);

  const resetKeys = useCallback(async () => {
    try {
      const deleted = await deleteKeyPair(USER_KEY_ID);
      if (deleted) {
        setIsUsingPersistentKeys(false);
        // Reset the active handshake state as well since the keys used for it are now gone
        setState('IDLE');
        setResult(null);
        if (setContextResult) setContextResult(null);
        console.log('DK-SVS Persistence: User key pair deleted successfully.');
      } else {
        console.error('DK-SVS Persistence: Failed to delete user key pair.');
      }
    } catch (err) {
      console.error('DK-SVS Persistence: Unexpected error during key reset', err);
    }
  }, [setContextResult]);

  const runDualKeyHandshake = useCallback(async (params: {
    institutionId: string;
    secondFactorId: string;
  }) => {
    setState('INITIATING');
    setResult(null);

    const proofBytes = await generateProof(18);
    const result = await performDualKeyHandshake(params.institutionId, params.secondFactorId, { proofBytes });
    
    setState(result.state);
    setResult(result);
    if (setContextResult) setContextResult(result);
  }, [setContextResult]);

  const reset = useCallback(() => {
    setState('IDLE');
    setResult(null);
    if (setContextResult) setContextResult(null);
  }, [setContextResult]);

  return { state, result, runDualKeyHandshake, reset, resetKeys, isUsingPersistentKeys };
}

