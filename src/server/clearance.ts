/**
 * One clearance record: a live nonce, a user signature over
 * challenge:factor:proofDigest, and a range proof whose threshold byte
 * equals the server policy. The nonce is consumed only after both checks pass.
 */

import { createHash, timingSafeEqual, webcrypto } from 'crypto';
import { CapacityExceededError } from './httpShared.ts';
import { bindDurableStore, openDurableMap, type DurableStore } from './durableStore.ts';
import { boundedMs, recordClearanceAudit } from './clearanceAudit.ts';
import { getInstitutionalKey, jurisdictionForInstitution } from './institutionalKey.ts';
import { bytesToHex } from '../lib/crypto/encoding.ts';
import { signClearanceEnvelope, type ClearanceProductCategory } from '../lib/crypto/clearanceEnvelope.ts';
import { verifyStockRequest, type StockReason } from './rfidCatalog.ts';
import { verifyWebAuthnAssertion } from './webauthnServer.ts';
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
  keyId?: string;
}

const institutionalChallengeSlot: { current: DurableStore<ActiveChallengeRecord> } = {
  current: openDurableMap<ActiveChallengeRecord>('institutional-challenges'),
};

export const activeChallenges = bindDurableStore(() => institutionalChallengeSlot.current);

export function replaceInstitutionalChallengeStore(
  next: DurableStore<ActiveChallengeRecord>
): DurableStore<ActiveChallengeRecord> {
  const previous = institutionalChallengeSlot.current;
  institutionalChallengeSlot.current = next;
  return previous;
}

export function purgeExpiredInstitutionalChallenges(): void {
  const now = Date.now();
  for (const [key, record] of activeChallenges.entries()) {
    if (now - record.issuedAt > CHALLENGE_TTL_MS) {
      activeChallenges.delete(key);
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
  keyId: string;
}

export async function issueInstitutionalChallenge(
  institutionId: string,
  keyPair: webcrypto.CryptoKeyPair,
  keyId: string
): Promise<IssuedChallenge> {
  purgeExpiredInstitutionalChallenges();
  if (activeChallenges.size >= MAX_ACTIVE_INSTITUTIONAL_CHALLENGES) {
    throw new CapacityExceededError('Institutional challenge capacity exceeded');
  }

  const timestamp = Date.now();
  const nonce = webcrypto.randomUUID();
  const challenge = `CHALLENGE-${nonce}-${institutionId}-${timestamp}.kid.${keyId}`;
  const reserved: ActiveChallengeRecord = {
    issuedAt: timestamp,
    consumed: false,
    inflight: false,
    signatureBase64: '',
    institutionId,
    keyId,
  };
  // Reserve the slot before the first await so concurrent issuers cannot pass the cap.
  activeChallenges.set(challenge, reserved);

  try {
    const challengeBuffer = new TextEncoder().encode(challenge);
    const instSignatureBuffer = await webcrypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-256' } },
      keyPair.privateKey,
      challengeBuffer
    );
    const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', keyPair.publicKey);
    const signatureBase64 = Buffer.from(instSignatureBuffer).toString('base64');
    reserved.signatureBase64 = signatureBase64;
    activeChallenges.commit(challenge);
    recordClearanceAudit({
      event: 'challenge_issued',
      jurisdiction: jurisdictionForInstitution(institutionId),
      keyId,
      reason: 'issued',
    });
    return { challenge, signatureBase64, publicKeyJwk, keyId };
  } catch (err) {
    if (!reserved.consumed) activeChallenges.delete(challenge);
    throw err;
  }
}

export interface ClearanceHttpResult {
  status: number;
  body: Record<string, unknown>;
}

function rejected(status: number, fields: Record<string, unknown>): ClearanceHttpResult {
  return { status, body: { valid: false, ...fields } };
}

function release(challengeId: string, record: ActiveChallengeRecord): void {
  if (!record.consumed) {
    record.inflight = false;
    activeChallenges.commit(challengeId);
  }
}

export interface ClearanceSessionClaims {
  levelOfAssurance?: string;
  isOver18?: boolean;
}

/** present is true when the request carried a session token. claims is null when that token did not resolve. */
export interface ClearanceSessionGate {
  present: boolean;
  claims: ClearanceSessionClaims | null;
}

function sessionLoa(value: string | undefined): 'high' | 'substantial' | 'low' | 'unknown' {
  const loa = (value || '').toLowerCase();
  if (loa.includes('substantial')) return 'substantial';
  if (loa.includes('high')) return 'high';
  if (loa.includes('low')) return 'low';
  return 'unknown';
}

function sessionPolicyReason(
  jurisdiction: 'CH' | 'IT',
  gate: ClearanceSessionGate
): 'session_required' | 'session_invalid' | 'session_underage' | 'loa_insufficient' | null {
  if (!gate.present) return 'session_required';
  if (!gate.claims) return 'session_invalid';
  if (gate.claims.isOver18 !== true) return 'session_underage';
  if (jurisdiction === 'IT' && sessionLoa(gate.claims.levelOfAssurance) !== 'high') return 'loa_insufficient';
  return null;
}

function sessionPolicyMessage(
  reason: 'session_required' | 'session_invalid' | 'session_underage' | 'loa_insufficient'
): string {
  if (reason === 'session_required') return 'Session is required';
  if (reason === 'session_invalid') return 'Session is missing or expired';
  if (reason === 'session_underage') return 'Session age gate rejected the clearance';
  return 'Italian LoA High is required';
}

export interface ClearanceRequestContext {
  origin: string | null;
  rpId: string;
}

/** SHA-256 of the UTF-8 credential id. The same digest is what the client signs. */
export function credentialSecondFactorHash(credentialId: string): string {
  return createHash('sha256').update(credentialId).digest('hex');
}

function bindSecondFactor(
  body: Record<string, unknown>,
  secondFactorHash: string,
  requestContext: ClearanceRequestContext
): { ok: true } | { ok: false; reason: 'second_factor_unbound' | 'second_factor_rejected'; message: string } {
  const credentialId = typeof body.credentialId === 'string' ? body.credentialId : '';
  const assertion = body.webauthnAssertion;
  const response = assertion && typeof assertion === 'object'
    ? ((assertion as { response?: unknown }).response && typeof (assertion as { response?: unknown }).response === 'object'
      ? (assertion as { response: Record<string, unknown> }).response
      : assertion as Record<string, unknown>)
    : null;
  if (
    !credentialId ||
    !response ||
    typeof response.clientDataJSON !== 'string' ||
    typeof response.authenticatorData !== 'string' ||
    typeof response.signature !== 'string'
  ) {
    return {
      ok: false,
      reason: 'second_factor_unbound',
      message: 'Second factor is not bound to a verified authenticator',
    };
  }
  if (!requestContext.origin) {
    return { ok: false, reason: 'second_factor_rejected', message: 'Origin mismatch or untrusted origin' };
  }
  const verified = verifyWebAuthnAssertion({
    credentialId,
    clientDataJSONB64: response.clientDataJSON,
    authenticatorDataB64: response.authenticatorData,
    signatureB64: response.signature,
    expectedOrigin: requestContext.origin,
    expectedRpId: requestContext.rpId,
    requireUserVerification: true,
  });
  if (!verified.verified) {
    return {
      ok: false,
      reason: 'second_factor_rejected',
      message: verified.error || 'Second factor assertion was rejected',
    };
  }
  const expected = credentialSecondFactorHash(credentialId);
  const expectedBytes = Buffer.from(expected);
  const presentedBytes = Buffer.from(secondFactorHash);
  if (expectedBytes.length !== presentedBytes.length || !timingSafeEqual(expectedBytes, presentedBytes)) {
    return {
      ok: false,
      reason: 'second_factor_rejected',
      message: 'Second factor hash does not match the verified credential',
    };
  }
  return { ok: true };
}

function productRejectionMessage(reason: StockReason): string {
  if (reason === 'signature_rejected') return 'Manufacturer signature rejected';
  if (reason === 'unsigned') return 'Manufacturer signature is missing';
  if (reason === 'counterfeit' || reason === 'recalled') return 'Product is blocked';
  return 'Product is not in the institutional catalog';
}

/**
 * Synchronous challenge claim happens before the first await.
 * A second caller sees inflight and is a replay. A failed check clears inflight.
 * Every clearance requires a resolved session. The age gate must pass, and IT also requires LoA High.
 * Those results are written into the signed envelope. A missing cookie is rejected.
 */
export async function verifyClearance(
  payload: unknown,
  keyPair: webcrypto.CryptoKeyPair,
  session: ClearanceSessionGate = { present: false, claims: null },
  requestContext: ClearanceRequestContext = { origin: null, rpId: '' }
): Promise<ClearanceHttpResult> {
  const started = performance.now();
  const prove_ms = boundedMs(
    payload && typeof payload === 'object' && !Buffer.isBuffer(payload)
      ? (payload as Record<string, unknown>).proveMs
      : undefined
  );
  const audit = (
    event: 'replay_rejected' | 'proof_failure' | 'clearance_success' | 'clearance_failure',
    reason: string,
    extra?: { jurisdiction?: 'CH' | 'IT'; verify_ms?: number; keyId?: string }
  ): void => {
    recordClearanceAudit({
      event,
      reason,
      prove_ms,
      total_ms: performance.now() - started,
      ...extra,
    });
  };

  if (!payload || typeof payload !== 'object' || Buffer.isBuffer(payload)) {
    audit('clearance_failure', 'invalid_payload');
    return rejected(400, { error: 'Missing required payload fields' });
  }

  const body = payload as Record<string, unknown>;
  if (body.v !== 1) {
    audit('clearance_failure', 'invalid_payload');
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
    audit('clearance_failure', 'invalid_payload');
    return rejected(400, { error: 'Missing required payload fields' });
  }

  const jwk = userPublicKey as webcrypto.JsonWebKey;
  if (jwk.crv !== 'P-256' || jwk.kty !== 'EC') {
    audit('clearance_failure', 'invalid_payload');
    return rejected(400, { error: 'Unsupported key type' });
  }

  let proofBytes: Uint8Array;
  try {
    proofBytes = new Uint8Array(Buffer.from(proofBase64, 'base64'));
  } catch {
    audit('clearance_failure', 'invalid_payload');
    return rejected(400, { error: 'Invalid base64 string' });
  }
  if (proofBytes.length === 0) {
    audit('clearance_failure', 'invalid_payload');
    return rejected(400, { error: 'Empty proof' });
  }

  purgeExpiredInstitutionalChallenges();
  const record = activeChallenges.get(challengeId);
  const jurisdiction = jurisdictionForInstitution(record?.institutionId || '');
  if (!record) {
    audit('clearance_failure', 'challenge_not_found');
    return rejected(200, {
      reason: 'Challenge not found or untracked by institutional node',
      proofByteLength: proofBytes.length,
    });
  }
  if (record.consumed || record.inflight) {
    audit('replay_rejected', 'challenge_consumed', { jurisdiction });
    return rejected(200, {
      reason: 'Replay detected: challenge already consumed',
      proofByteLength: proofBytes.length,
    });
  }
  if (Date.now() - record.issuedAt > CHALLENGE_TTL_MS) {
    activeChallenges.delete(challengeId);
    audit('clearance_failure', 'challenge_expired', { jurisdiction });
    return rejected(200, {
      reason: 'Challenge expired',
      proofByteLength: proofBytes.length,
    });
  }

  record.inflight = true;
  activeChallenges.commit(challengeId);

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
      release(challengeId, record);
      audit('clearance_failure', 'invalid_payload', { jurisdiction });
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
      release(challengeId, record);
      audit('clearance_failure', 'signature_rejected', { jurisdiction, verify_ms });
      return rejected(200, {
        reason: 'Signature verification failed',
        verify_ms,
        proofByteLength: proofBytes.length,
      });
    }

    const age = await verifyAgeProof(proofBytes, AGE_GATE_POLICY_THRESHOLD);
    if (!age.ok) {
      release(challengeId, record);
      const failedVerifyMs = performance.now() - t0;
      audit('proof_failure', 'proof_rejected', { jurisdiction, verify_ms: failedVerifyMs });
      return rejected(200, {
        reason: age.reason || 'Verification failed',
        verify_ms: failedVerifyMs,
        proofByteLength: proofBytes.length,
      });
    }

    const policyReason = sessionPolicyReason(jurisdiction, session);
    if (policyReason) {
      release(challengeId, record);
      const failedVerifyMs = performance.now() - t0;
      audit('clearance_failure', policyReason, { jurisdiction, verify_ms: failedVerifyMs });
      return rejected(200, {
        reason: sessionPolicyMessage(policyReason),
        verify_ms: failedVerifyMs,
        proofByteLength: proofBytes.length,
      });
    }

    const requestedProductUid = typeof body.productUid === 'string' ? body.productUid : '';
    let verifiedProduct: {
      productUid: string;
      productCategory: ClearanceProductCategory;
      productStatus: 'authentic';
      excise: number;
    } | undefined;
    if (requestedProductUid.length > 0) {
      const stock = await verifyStockRequest({ hardwareUid: requestedProductUid });
      const category = stock.category;
      const categoryAllowed = category === 'Tobacco'
        || category === 'Alcohol'
        || category === 'Vaporizer'
        || category === 'Cannabinoids'
        || category === 'Restricted Hardware';
      const exciseAllowed = typeof stock.exciseRecovered === 'number'
        && Number.isFinite(stock.exciseRecovered)
        && stock.exciseRecovered >= 0;
      if (
        stock.ok !== true ||
        stock.signatureVerified !== true ||
        stock.status !== 'authentic' ||
        stock.hardwareUid !== requestedProductUid ||
        !categoryAllowed ||
        !exciseAllowed
      ) {
        release(challengeId, record);
        const failedVerifyMs = performance.now() - t0;
        audit('clearance_failure', 'product_rejected', { jurisdiction, verify_ms: failedVerifyMs });
        return rejected(200, {
          reason: productRejectionMessage(stock.reason),
          verify_ms: failedVerifyMs,
          proofByteLength: proofBytes.length,
        });
      }
      verifiedProduct = {
        productUid: stock.hardwareUid,
        productCategory: category,
        productStatus: 'authentic',
        excise: stock.exciseRecovered as number,
      };
    }

    const factor = bindSecondFactor(body, secondFactorHash, requestContext);
    if (factor.ok === false) {
      release(challengeId, record);
      const failedVerifyMs = performance.now() - t0;
      audit('clearance_failure', factor.reason, { jurisdiction, verify_ms: failedVerifyMs });
      return rejected(200, {
        reason: factor.message,
        verify_ms: failedVerifyMs,
        proofByteLength: proofBytes.length,
      });
    }

    const material = await getInstitutionalKey(jurisdiction);
    const signed = await signClearanceEnvelope(
      {
        keyId: material.keyId,
        jurisdiction,
        proofSha256: proofSha256Hex,
        secondFactorHash,
        ...verifiedProduct,
      },
      material.privateKey
    );

    record.consumed = true;
    record.inflight = false;
    activeChallenges.commit(challengeId);
    const successVerifyMs = performance.now() - t0;
    audit('clearance_success', 'verified', { jurisdiction, verify_ms: successVerifyMs, keyId: material.keyId });
    return {
      status: 200,
      body: {
        valid: true,
        verify_ms: successVerifyMs,
        proofByteLength: proofBytes.length,
        envelope: signed.envelope,
        envelopeSignature: signed.envelopeSignature,
        sessionPolicyEnforced: session.present && session.claims !== null,
      },
    };
  } catch (err) {
    release(challengeId, record);
    audit('clearance_failure', 'verification_error', { jurisdiction });
    const reason = err instanceof Error ? err.message : String(err);
    return rejected(500, { error: reason });
  }
}
