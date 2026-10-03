import { useState, useCallback, useEffect } from 'react';
import { KpiTelemetry } from '../../lib/KpiTelemetry';
import { useDualKeyResult } from '../context/DualKeyResultContext';

export type HandshakeState = 
  | 'IDLE' 
  | 'INITIATING' 
  | 'AWAITING_CHALLENGE' 
  | 'VERIFYING_SIGNATURES' 
  | 'COMPLETED' 
  | 'FAILED';

export interface DualKeyPayload {
  v: 1;
  challengeId: string;
  secondFactorHash: string;          // hex lowercase SHA-256
  userPublicKey: JsonWebKey;         // EC P-256, x + y only (no d)
  userSignature: string;             // base64url, no padding
  institutionalSignature?: string;   // base64 institutional signature over challengeId
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
  error?: string;
}

/**
 * The cryptographic algorithm used across the DK-SVS flow for both
 * Institutional and User key pairs.
 */
const ECDSA_ALGO = { name: 'ECDSA', namedCurve: 'P-256' };

/**
 * Helper function to convert an ArrayBuffer to a Hex String
 */
function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Helper function to convert a Base64 string to an ArrayBuffer.
 * Includes basic validation to prevent common decoding errors.
 */
function base64ToBuffer(base64: string): ArrayBuffer {
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('Invalid Base64 input');
  }
  try {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (error) {
    throw new Error('Failed to decode Base64 string');
  }
}

/**
 * Helper function to convert a Buffer or ArrayBuffer to base64url (no padding)
 */
function bufferToBase64Url(buffer: ArrayBuffer): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(buffer).toString('base64url');
  }
  const bytes = new Uint8Array(buffer);
  let binaryString = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  const base64 = window.btoa(binaryString);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

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
  secondFactorId: string
): Promise<DualKeyValidationResult & { coreCryptoTime: number }> {
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
      const response = await fetch('/api/institutional-challenge', {
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
    
    const secondFactorBuffer = new TextEncoder().encode(secondFactorId);
    t0 = performance.now();
    const secondFactorHashBuffer = await crypto.subtle.digest('SHA-256', secondFactorBuffer);
    coreCryptoTime += performance.now() - t0;
    const secondFactorHashHex = bufferToHex(secondFactorHashBuffer);
    
    const boundPayloadStr = `${challengeStr}:${secondFactorHashHex}`;
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
        clientTs: new Date().toISOString()
      };

      logs.push('Verifier: Sending payload to server for validation...');
      try {
        const verifyStart = performance.now();
        const verifyRes = await fetch('/api/v1/dual-key/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        serverVerifyMs = performance.now() - verifyStart;
        
        if (verifyRes.ok) {
          const verifyData = await verifyRes.json();
          if (verifyData.valid) {
            isUserSigValid = true;
            isBindingValid = true;
            logs.push(`Verifier: Cryptographic binding SUCCESSFUL (Server Verified in ${Math.round(serverVerifyMs)}ms).`);
          } else {
            logs.push(`Verifier: Cryptographic binding FAILED (Server Rejected: ${verifyData.reason || 'Unknown'}).`);
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
      serverVerifyMs,
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

    const result = await performDualKeyHandshake(params.institutionId, params.secondFactorId);
    
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

