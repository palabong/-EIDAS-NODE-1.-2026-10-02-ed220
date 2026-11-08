/**
 * Local institutional key seam.
 *
 * EnvFileKeySource reads INSTITUTIONAL_KEY_JSON / INSTITUTIONAL_KEY_PATH
 * and the optional Italian pair INSTITUTIONAL_KEY_JSON_IT / INSTITUTIONAL_KEY_PATH_IT.
 * When the Italian pair is unset, the primary key signs both jurisdictions and
 * the key id records that fact.
 *
 * A KMS or HSM adapter implements InstitutionalKeySource.load. Select it with
 * INSTITUTIONAL_KEY_SOURCE=kms. No adapter is shipped. That setting fails closed
 * instead of silently signing with the local key.
 * rotateInstitutionalKey replaces one slot and does not touch the nonce store.
 * The previous public key stays published until the clearance envelope TTL ends,
 * so a till can still verify an envelope signed just before the rotation.
 */

import fs from 'fs/promises';
import path from 'path';
import { webcrypto } from 'crypto';
import { getErrorMessage } from './httpShared.ts';
import { CLEARANCE_ENVELOPE_TTL_MS } from '../lib/crypto/clearanceEnvelope.ts';

export type InstitutionalJurisdiction = 'CH' | 'IT';

export interface InstitutionalKeyMaterial {
  keyId: string;
  jurisdiction: InstitutionalJurisdiction;
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
  publicKeyJwk: webcrypto.JsonWebKey;
  origin: 'env' | 'file' | 'ephemeral' | 'rotation';
}

export interface InstitutionalKeySource {
  load(
    jurisdiction: InstitutionalJurisdiction,
    env: InstitutionalKeyEnv
  ): Promise<InstitutionalKeyMaterial | null>;
}

export type InstitutionalKeyEnv = Record<string, string | undefined>;

const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ECDSA_P256 = { name: 'ECDSA', namedCurve: 'P-256' };

const slots: Record<InstitutionalJurisdiction, InstitutionalKeyMaterial | null> = {
  CH: null,
  IT: null,
};

/** Public verification material. `retiredAt` is absent while the key is the active signer. */
export interface PublishedInstitutionalKey {
  keyId: string;
  jurisdiction: InstitutionalJurisdiction;
  publicKey: webcrypto.CryptoKey;
  publicKeyJwk: webcrypto.JsonWebKey;
  retiredAt?: number;
}

const retiredKeys: PublishedInstitutionalKey[] = [];

function asPublished(material: InstitutionalKeyMaterial, retiredAt?: number): PublishedInstitutionalKey {
  const published: PublishedInstitutionalKey = {
    keyId: material.keyId,
    jurisdiction: material.jurisdiction,
    publicKey: material.publicKey,
    publicKeyJwk: material.publicKeyJwk,
  };
  if (retiredAt !== undefined) published.retiredAt = retiredAt;
  return published;
}

function pruneRetiredKeys(now: number): void {
  for (let i = retiredKeys.length - 1; i >= 0; i--) {
    const retiredAt = retiredKeys[i].retiredAt;
    if (retiredAt === undefined || now >= retiredAt + CLEARANCE_ENVELOPE_TTL_MS) {
      retiredKeys.splice(i, 1);
    }
  }
}

function retainRetiredKey(material: InstitutionalKeyMaterial, retiredAt: number): void {
  pruneRetiredKeys(retiredAt);
  const published = asPublished(material, retiredAt);
  const existing = retiredKeys.findIndex((key) => key.keyId === material.keyId);
  if (existing >= 0) retiredKeys[existing] = published;
  else retiredKeys.push(published);
}

function forgetRetired(keyId: string): void {
  const existing = retiredKeys.findIndex((key) => key.keyId === keyId);
  if (existing >= 0) retiredKeys.splice(existing, 1);
}

/**
 * Test seam. Moves a retired key's publication time so a harness can prove
 * the TTL cutoff without waiting. Production verification does not call this.
 */
export function backdateRetiredInstitutionalKey(keyId: string, retiredAt: number): boolean {
  const found = retiredKeys.find((key) => key.keyId === keyId);
  if (!found) return false;
  found.retiredAt = retiredAt;
  return true;
}

export function assertKeyId(keyId: string): string {
  if (!KEY_ID_PATTERN.test(keyId)) {
    throw new Error(`Invalid institutional key id '${keyId}'`);
  }
  return keyId;
}

export function jurisdictionForInstitution(institutionId: string): InstitutionalJurisdiction {
  const id = institutionId.toUpperCase();
  if (id.includes('AGCOM') || id.includes('-IT-') || id.includes('ITAL')) return 'IT';
  return 'CH';
}

export function missingInstitutionalKeyError(): Error {
  return new Error(
    '[FATAL] Production configuration error: Institutional key pair not found. ' +
    'Set INSTITUTIONAL_KEY_JSON or INSTITUTIONAL_KEY_PATH in environment variables.'
  );
}

export function kmsAdapterMissingError(): Error {
  return new Error(
    '[FATAL] INSTITUTIONAL_KEY_SOURCE=kms is selected, and no KMS adapter is registered. ' +
    'Implement InstitutionalKeySource.load and register it before boot. Refusing to sign with the local key.'
  );
}

async function keyIdFromPublicJwk(jwk: webcrypto.JsonWebKey): Promise<string> {
  const canonical = `${jwk.crv}|${jwk.x}|${jwk.y}`;
  const digest = await webcrypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return `p256-${Buffer.from(digest).toString('hex').slice(0, 16)}`;
}

async function importMaterial(
  input: { publicKeyJwk: webcrypto.JsonWebKey; privateKeyJwk: webcrypto.JsonWebKey; keyId?: string },
  jurisdiction: InstitutionalJurisdiction,
  origin: InstitutionalKeyMaterial['origin']
): Promise<InstitutionalKeyMaterial> {
  if (!input.publicKeyJwk || !input.privateKeyJwk) {
    throw new Error("Missing 'publicKeyJwk' or 'privateKeyJwk'.");
  }
  const publicKey = await webcrypto.subtle.importKey('jwk', input.publicKeyJwk, ECDSA_P256, true, ['verify']);
  const privateKey = await webcrypto.subtle.importKey('jwk', input.privateKeyJwk, ECDSA_P256, true, ['sign']);
  const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', publicKey);
  const keyId = input.keyId ? assertKeyId(input.keyId) : await keyIdFromPublicJwk(publicKeyJwk);
  return { keyId, jurisdiction, publicKey, privateKey, publicKeyJwk, origin };
}

function explicitKeyId(jurisdiction: InstitutionalJurisdiction, env: InstitutionalKeyEnv, parsedKeyId: unknown): string | undefined {
  const fromEnv = jurisdiction === 'IT' ? env.INSTITUTIONAL_KEY_ID_IT : env.INSTITUTIONAL_KEY_ID;
  if (typeof fromEnv === 'string' && fromEnv.trim()) return fromEnv.trim();
  if (typeof parsedKeyId === 'string' && parsedKeyId.trim()) return parsedKeyId.trim();
  return undefined;
}

async function materialFromJson(
  raw: string,
  jurisdiction: InstitutionalJurisdiction,
  env: InstitutionalKeyEnv,
  origin: 'env' | 'file'
): Promise<InstitutionalKeyMaterial> {
  const parsed = JSON.parse(raw) as {
    publicKeyJwk?: webcrypto.JsonWebKey;
    privateKeyJwk?: webcrypto.JsonWebKey;
    keyId?: string;
  };
  return importMaterial(
    {
      publicKeyJwk: parsed.publicKeyJwk as webcrypto.JsonWebKey,
      privateKeyJwk: parsed.privateKeyJwk as webcrypto.JsonWebKey,
      keyId: explicitKeyId(jurisdiction, env, parsed.keyId),
    },
    jurisdiction,
    origin
  );
}

/** Env and file loader. Returns null when that jurisdiction has no configured key. */
export class EnvFileKeySource implements InstitutionalKeySource {
  async load(
    jurisdiction: InstitutionalJurisdiction,
    env: InstitutionalKeyEnv
  ): Promise<InstitutionalKeyMaterial | null> {
    const jsonEnv = jurisdiction === 'IT' ? env.INSTITUTIONAL_KEY_JSON_IT : env.INSTITUTIONAL_KEY_JSON;
    if (jsonEnv && jsonEnv.trim()) {
      try {
        return await materialFromJson(jsonEnv, jurisdiction, env, 'env');
      } catch (err: unknown) {
        const message = getErrorMessage(err);
        console.error(`[InstitutionalKey] Failed to import ${jurisdiction} key from JSON env:`, message);
        if (env.NODE_ENV === 'production' || jurisdiction === 'IT') {
          throw new Error(`[FATAL] Invalid institutional key JSON for ${jurisdiction}: ${message}`);
        }
      }
    }

    const configuredPath = jurisdiction === 'IT' ? env.INSTITUTIONAL_KEY_PATH_IT : env.INSTITUTIONAL_KEY_PATH;
    // A detached env object must not fall through to the developer's institutional-key.json.
    const defaultPath = jurisdiction === 'CH' && env === process.env
      ? path.join(process.cwd(), 'institutional-key.json')
      : '';
    const filePath = configuredPath || defaultPath;
    if (!filePath) return null;

    try {
      const fileData = await fs.readFile(filePath, 'utf-8');
      return await materialFromJson(fileData, jurisdiction, env, 'file');
    } catch (err: unknown) {
      const isEnoent = err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT';
      if (configuredPath && !isEnoent) {
        console.warn(`[InstitutionalKey] Warning reading ${filePath}:`, getErrorMessage(err));
      }
      if (configuredPath && env.NODE_ENV === 'production') {
        throw new Error(`[FATAL] Institutional key file for ${jurisdiction} is not readable at ${filePath}.`);
      }
      return null;
    }
  }
}

export const envFileKeySource = new EnvFileKeySource();

/**
 * Pure loader used by boot and by the harness. Empty env with allowEphemeral
 * false throws the production fail-closed error and does not read the developer's key file.
 */
export async function loadPrimaryKeyOrThrow(
  env: InstitutionalKeyEnv,
  options: { allowEphemeral: boolean }
): Promise<InstitutionalKeyMaterial> {
  const found = await envFileKeySource.load('CH', env);
  if (found) return found;
  if (!options.allowEphemeral) throw missingInstitutionalKeyError();
  console.warn('[InstitutionalKey] NOTICE: Generating ephemeral in-memory ECDSA P-256 key pair for development/sandbox. Challenges will not persist across restarts.');
  const pair = await webcrypto.subtle.generateKey(ECDSA_P256, true, ['sign', 'verify']);
  const publicKeyJwk = await webcrypto.subtle.exportKey('jwk', pair.publicKey);
  const privateKeyJwk = await webcrypto.subtle.exportKey('jwk', pair.privateKey);
  return importMaterial({ publicKeyJwk, privateKeyJwk }, 'CH', 'ephemeral');
}

async function persistEphemeral(material: InstitutionalKeyMaterial, env: InstitutionalKeyEnv): Promise<void> {
  if (env.PERSIST_DEV_KEYS !== 'true' || material.origin !== 'ephemeral') return;
  const keyFilePath = env.INSTITUTIONAL_KEY_PATH || path.join(process.cwd(), 'institutional-key.json');
  try {
    const privateKeyJwk = await webcrypto.subtle.exportKey('jwk', material.privateKey);
    await fs.writeFile(
      keyFilePath,
      JSON.stringify({ publicKeyJwk: material.publicKeyJwk, privateKeyJwk, keyId: material.keyId }, null, 2),
      { mode: 0o600 }
    );
    console.log(`[InstitutionalKey] Persisted development key pair to ${keyFilePath}.`);
  } catch (err: unknown) {
    console.warn('[InstitutionalKey] Could not persist development key pair to disk (ignoring in dev):', getErrorMessage(err));
  }
}

export async function getInstitutionalKey(
  jurisdiction: InstitutionalJurisdiction
): Promise<InstitutionalKeyMaterial> {
  if (process.env.INSTITUTIONAL_KEY_SOURCE === 'kms') {
    throw kmsAdapterMissingError();
  }
  const cached = slots[jurisdiction];
  if (cached) return cached;

  if (jurisdiction === 'IT') {
    const configured = await envFileKeySource.load('IT', process.env);
    if (configured) {
      slots.IT = configured;
      console.log(`[InstitutionalKey] Italian jurisdiction uses key ${configured.keyId}.`);
      return configured;
    }
    const primary = await getInstitutionalKey('CH');
    return primary;
  }

  const primary = await loadPrimaryKeyOrThrow(process.env, {
    allowEphemeral: process.env.NODE_ENV !== 'production',
  });
  slots.CH = primary;
  await persistEphemeral(primary, process.env);
  if (primary.origin !== 'ephemeral') {
    console.log(`[InstitutionalKey] Primary key ${primary.keyId} loaded from ${primary.origin}.`);
  }
  return primary;
}

export async function getInstitutionalKeyPair(): Promise<webcrypto.CryptoKeyPair> {
  const material = await getInstitutionalKey('CH');
  return { publicKey: material.publicKey, privateKey: material.privateKey };
}

/**
 * Active verification keys plus public keys retired inside the envelope TTL.
 * A till uses this set. Private key material is not included.
 */
export async function listPublishedInstitutionalKeys(now: number = Date.now()): Promise<PublishedInstitutionalKey[]> {
  pruneRetiredKeys(now);
  const primary = await getInstitutionalKey('CH');
  const italian = await getInstitutionalKey('IT');
  const current = [asPublished(primary)];
  if (italian.keyId !== primary.keyId) current.push(asPublished(italian));
  const seen = new Set(current.map((key) => key.keyId));
  const published = current.slice();
  for (const retired of retiredKeys) {
    if (seen.has(retired.keyId)) continue;
    seen.add(retired.keyId);
    published.push(retired);
  }
  return published;
}

export async function findPublishedInstitutionalKey(
  keyId: string,
  now: number = Date.now()
): Promise<PublishedInstitutionalKey | null> {
  const published = await listPublishedInstitutionalKeys(now);
  return published.find((key) => key.keyId === keyId) ?? null;
}

/**
 * Replace the signing key for one jurisdiction.
 * In-flight nonces stay in the challenge store. Callers keep verifying those
 * challenges with the key that signed them. The outgoing public key stays
 * published for one envelope TTL.
 */
export async function rotateInstitutionalKey(
  jurisdiction: InstitutionalJurisdiction,
  input: { publicKeyJwk: webcrypto.JsonWebKey; privateKeyJwk: webcrypto.JsonWebKey; keyId?: string }
): Promise<InstitutionalKeyMaterial> {
  const material = await importMaterial(input, jurisdiction, 'rotation');
  const outgoing = slots[jurisdiction];
  if (outgoing && outgoing.keyId !== material.keyId) {
    retainRetiredKey(outgoing, Date.now());
    console.log(`[InstitutionalKey] Rotated ${jurisdiction} key to ${material.keyId}. In-flight nonces were kept. Previous public key ${outgoing.keyId} stays published for the envelope TTL.`);
  } else {
    console.log(`[InstitutionalKey] Rotated ${jurisdiction} key to ${material.keyId}. In-flight nonces were kept.`);
  }
  forgetRetired(material.keyId);
  slots[jurisdiction] = material;
  return material;
}

export function releaseInstitutionalKey(jurisdiction: InstitutionalJurisdiction): void {
  slots[jurisdiction] = null;
}
