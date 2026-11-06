/**
 * One clearance record: a live nonce, a user signature over
 * challenge:factor:proofDigest, and a range proof whose threshold byte
 * equals the server policy. The nonce is consumed only after both checks pass.
 */

import { webcrypto } from 'crypto';
import { bytesToHex } from '../lib/crypto/encoding.ts';
import {
  AGE_GATE_POLICY_THRESHOLD,
  clearanceMessage,
} from '../lib/crypto/clearanceMessage.ts';
import { verifyBitwiseRangeProof } from '../lib/crypto/zkp/range_b2.ts';
import { decodeBitwiseRangeProof } from '../lib/crypto/zkp/range_b2_codec.ts';

export { AGE_GATE_POLICY_THRESHOLD, clearanceMessage };

export const CHALLENGE_TTL_MS = 60_000;
export const MAX_ACTIVE_INSTITUTIONAL_CHALLENGES = 5_000;

export interface ActiveChallengeRecord {
  issuedAt: number;
  consumed: boolean;
  inflight: boolean;
  signatureBase64: string;
  institutionId: string;
}

export const activeChallenges = new Map<string, ActiveChallengeRecord>();

export function purgeExpiredInstitutionalChallenges(): void {
  const now = Date.now();
  for (const [key, record] of activeChallenges.entries()) {
    if (now - record.issuedAt > CHALLENGE_TTL_MS) {
      activeChallenges.delete(key);
    }
  }
  if (activeChallenges.size > MAX_ACTIVE_INSTITUTIONAL_CHALLENGES) {
    const toDelete = activeChallenges.size - MAX_ACTIVE_INSTITUTIONAL_CHALLENGES;
    let deleted = 0;
    for (const key of activeChallenges.keys()) {
      activeChallenges.delete(key);
      deleted++;
      if (deleted >= toDelete) break;
    }
  }
}

export async function verifyAgeProof(
  proofBytes: Uint8Array,
  threshold: number
): Promise<{ ok: boolean; reason?: string }> {
  let proof;
  try {
    proof = decodeBitwiseRangeProof(proofBytes);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    return { ok: false, reason };
  }
  if (proof.threshold !== threshold) {
    return {
      ok: false,
      reason: `Threshold ${proof.threshold} is not the policy threshold ${threshold}`,
    };
  }
  const mathOk = await verifyBitwiseRangeProof(proof);
  if (!mathOk) {
    return { ok: false, reason: 'Verification failed' };
  }
  return { ok: true };
}

export interface IssuedChallenge {
  challenge: string;
  signatureBase64: string;
  publicKeyJwk: webcrypto.JsonWebKey;
}

export async function issueInstitutionalChallenge(
  institutionId: string,
  keyPair: webcrypto.CryptoKeyPair
): Promise<IssuedChallenge> {
  const timestamp = Date.now();
  const nonce = webcrypto.randomUUID();
  const challenge = `CHALLENGE-${nonce}-${institutionId}-${timestamp}`;
  const challengeBuffer = new TextEncoder().encode(challenge);
  const instSignatureBuffer = await webcrypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    keyPair.privateKey,
    challengeBuffer
  );
  const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
  const signatureBase64 = Buffer.from(instSignatureBuffer).toString('base64');

  activeChallenges.set(challenge, {
    issuedAt: timestamp,
    consumed: false,
    inflight: false,
    signatureBase64,
    institutionId,
  });
  purgeExpiredInstitutionalChallenges();

  return { challenge, signatureBase64, publicKeyJwk };
}

export interface ClearanceHttpResult {
  status: number;
  body: Record<string, unknown>;
}

function rejected(status: number, fields: Record<string, unknown>): ClearanceHttpResult {
  return { status, body: { valid: false, ...fields } };
}

function release(record: ActiveChallengeRecord): void {
  if (!record.consumed) {
    record.inflight = false;
  }
}

/**
 * Synchronous challenge claim happens before the first await.
 * A second caller sees inflight and is a replay. A failed check clears inflight.
 */
export async function verifyClearance(
  payload: unknown,
  keyPair: webcrypto.CryptoKeyPair
): Promise<ClearanceHttpResult> {
  if (!payload || typeof payload !== 'object' || Buffer.isBuffer(payload)) {
    return rejected(400, { error: 'Missing required payload fields' });
  }

  const body = payload as Record<string, unknown>;
  if (body.v !== 1) {
    return rejected(400, { error: 'Invalid payload or unsupported version' });
  }

  const { challengeId, secondFactorHash, userPublicKey, userSignature, proofBase64 } = body;
  if (
    typeof challengeId !== 'string' || challengeId.length === 0 ||
    typeof secondFactorHash !== 'string' || secondFactorHash.length === 0 ||
    typeof userSignature !== 'string' || userSignature.length === 0 ||
    typeof proofBase64 !== 'string' || proofBase64.length === 0 ||
    !userPublicKey || typeof userPublicKey !== 'object'
  ) {
    return rejected(400, { error: 'Missing required payload fields' });
  }

  const jwk = userPublicKey as webcrypto.JsonWebKey;
  if (jwk.crv !== 'P-256' || jwk.kty !== 'EC') {
    return rejected(400, { error: 'Unsupported key type' });
  }

  let proofBytes: Uint8Array;
  try {
    proofBytes = new Uint8Array(Buffer.from(proofBase64, 'base64'));
  } catch {
    return rejected(400, { error: 'Invalid base64 string' });
  }
  if (proofBytes.length === 0) {
    return rejected(400, { error: 'Empty proof' });
  }

  purgeExpiredInstitutionalChallenges();
  const record = activeChallenges.get(challengeId);
  if (!record) {
    return rejected(200, {
      reason: 'Challenge not found or untracked by institutional node',
      proofByteLength: proofBytes.length,
    });
  }
  if (record.consumed || record.inflight) {
    return rejected(200, {
      reason: 'Replay detected: challenge already consumed',
      proofByteLength: proofBytes.length,
    });
  }
  if (Date.now() - record.issuedAt > CHALLENGE_TTL_MS) {
    activeChallenges.delete(challengeId);
    return rejected(200, {
      reason: 'Challenge expired',
      proofByteLength: proofBytes.length,
    });
  }

  record.inflight = true;

  const t0 = performance.now();
  try {
    const digest = await webcrypto.subtle.digest('SHA-256', proofBytes);
    const proofSha256Hex = bytesToHex(new Uint8Array(digest));
    const message = clearanceMessage(challengeId, secondFactorHash, proofSha256Hex);
    const messageBuffer = new TextEncoder().encode(message);

    const b64 = userSignature.replace(/-/g, '+').replace(/_/g, '/');
    const signatureBuffer = Buffer.from(b64, 'base64');

    let importedKey: webcrypto.CryptoKey;
    try {
      importedKey = await webcrypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify']
      );
    } catch {
      release(record);
      return rejected(400, { error: 'Invalid JWK format', proofByteLength: proofBytes.length });
    }

    let signatureOk = false;
    try {
      signatureOk = await webcrypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        importedKey,
        signatureBuffer,
        messageBuffer
      );
    } catch {
      signatureOk = false;
    }

    const verify_ms = performance.now() - t0;
    if (!signatureOk) {
      release(record);
      return rejected(200, {
        reason: 'Signature verification failed',
        verify_ms,
        proofByteLength: proofBytes.length,
      });
    }

    const age = await verifyAgeProof(proofBytes, AGE_GATE_POLICY_THRESHOLD);
    if (!age.ok) {
      release(record);
      return rejected(200, {
        reason: age.reason || 'Verification failed',
        verify_ms: performance.now() - t0,
        proofByteLength: proofBytes.length,
      });
    }

    record.consumed = true;
    record.inflight = false;
    return {
      status: 200,
      body: {
        valid: true,
        verify_ms: performance.now() - t0,
        proofByteLength: proofBytes.length,
      },
    };
  } catch (err) {
    release(record);
    const reason = err instanceof Error ? err.message : String(err);
    return rejected(500, { error: reason });
  }
}
