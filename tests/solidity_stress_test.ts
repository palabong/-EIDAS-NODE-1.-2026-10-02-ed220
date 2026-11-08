/**
 * Solidity stress matrix for the current pilot node.
 * Boots an ephemeral server on 127.0.0.1:0. Does not call access-log clear:
 * that handler truncates the shared data/access_logs.json file.
 *
 * Run: npx tsx tests/solidity_stress_test.ts
 */

import { createServer, type Server } from 'http';
import type { AddressInfo } from 'net';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createApp } from '../src/server/app.ts';
import {
  activeChallenges,
  credentialSecondFactorHash,
  MAX_ACTIVE_INSTITUTIONAL_CHALLENGES,
} from '../src/server/clearance.ts';
import {
  activeWebAuthnChallenges,
  MAX_ACTIVE_WEBAUTHN_CHALLENGES,
  MAX_STORED_CREDENTIALS,
  registeredWebAuthnCredentials,
} from '../src/server/webauthnServer.ts';
import { FileDurableMap, MemoryDurableMap } from '../src/server/durableStore.ts';
import { getInstitutionalKey, loadPrimaryKeyOrThrow } from '../src/server/institutionalKey.ts';
import { globalSessionStore } from '../src/server/sessionManager.ts';
import { getAccessLogs } from '../src/server/accessLogDb.ts';
import { Ctap2HardwareKeyHarness, YUBIKEY_5_SERIES_AAGUID } from '../src/lib/crypto/ctap2Harness.ts';
import { generateProof } from '../src/lib/crypto/zkp/nizkp.ts';
import { clearanceMessage } from '../src/lib/crypto/clearanceMessage.ts';
import { bytesToBase64, bytesToHex } from '../src/lib/crypto/encoding.ts';
import { canonicalClearanceEnvelope, type ClearanceEnvelope } from '../src/lib/crypto/clearanceEnvelope.ts';

type Status = 'PASS' | 'FAIL' | 'FINDING';

interface Row {
  id: string;
  category: string;
  status: Status;
  detail: string;
}

const rows: Row[] = [];
const crashes: string[] = [];

function add(id: string, category: string, status: Status, detail: string): void {
  rows.push({ id, category, status, detail });
  const mark = status === 'PASS' ? 'PASS' : status === 'FAIL' ? 'FAIL' : 'FINDING';
  console.log(`[${mark}] ${id} ${detail}`);
}

function pct(values: number[], p: number): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index];
}

function summarize(values: number[]): string {
  if (values.length === 0) return 'n=0';
  const sum = values.reduce((total, value) => total + value, 0);
  return `n=${values.length} avg=${Math.round(sum / values.length)}ms p50=${Math.round(pct(values, 50))}ms p95=${Math.round(pct(values, 95))}ms max=${Math.round(pct(values, 100))}ms`;
}

async function readBody(res: Response): Promise<{ status: number; text: string; json: any }> {
  const text = await res.text();
  let json: any = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { status: res.status, text, json };
}

async function main(): Promise<void> {
  const auditDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-stress-audit-'));
  const auditPath = path.join(auditDir, 'audit.log');
  const previousAudit = process.env.AUDIT_LOG_PATH;
  process.env.AUDIT_LOG_PATH = auditPath;
  const accessLogDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-stress-access-'));
  const previousAccessLog = process.env.ACCESS_LOG_PATH;
  process.env.ACCESS_LOG_PATH = path.join(accessLogDir, 'access_logs.json');
  const sharedAccessLog = path.join(process.cwd(), 'data', 'access_logs.json');
  const sharedAccessBefore = fs.existsSync(sharedAccessLog) ? fs.readFileSync(sharedAccessLog) : null;

  const app = createApp({ isTest: true });
  const server: Server = createServer(app);
  server.on('clientError', (err) => {
    crashes.push(`clientError: ${err.message}`);
  });
  await new Promise<void>((resolve) => {
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const origin = new URL(baseUrl).origin;
  console.log(`[stress] node ${baseUrl}`);

  const proofStarted = performance.now();
  const adultProof = await generateProof(32, 18);
  const proofMs = performance.now() - proofStarted;
  const proofB64 = bytesToBase64(adultProof);
  const proofHash = bytesToHex(new Uint8Array(await crypto.webcrypto.subtle.digest('SHA-256', adultProof)));
  console.log(`[stress] one adult proof ${Math.round(proofMs)}ms, ${adultProof.byteLength} bytes`);

  const userKey = await crypto.webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const userJwk = await crypto.webcrypto.subtle.exportKey('jwk', userKey.publicKey);

  async function sessionCookie(preset: string): Promise<string> {
    const acs = await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset }),
    });
    const setCookie = typeof acs.headers.getSetCookie === 'function' ? acs.headers.getSetCookie() : [];
    const cookie = setCookie.map((line) => line.split(';', 1)[0]).join('; ');
    if (!acs.ok || !cookie.includes('session_token=')) {
      throw new Error(`ACS ${preset} failed (${acs.status})`);
    }
    return cookie;
  }

  async function issue(institutionId: string): Promise<{ status: number; body: any }> {
    const res = await fetch(`${baseUrl}/api/institutional-challenge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ institutionId }),
    });
    const body = await res.json().catch(() => null);
    return { status: res.status, body };
  }

  const factorKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
  await factorKey.registerWithServer({
    baseUrl,
    username: `stress-${crypto.randomUUID()}@bilanx.org`,
  });

  async function freshFactor(): Promise<{ credentialId: string; assertion: any; secondFactorHash: string }> {
    const prepared = await factorKey.prepareAssertion({ baseUrl });
    return {
      credentialId: prepared.credentialId,
      assertion: prepared.assertion,
      secondFactorHash: credentialSecondFactorHash(prepared.credentialId),
    };
  }

  async function newIsolatedFactor(): Promise<{ credentialId: string; assertion: any; secondFactorHash: string }> {
    const key = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await key.registerWithServer({
      baseUrl,
      username: `parallel-${crypto.randomUUID()}@bilanx.org`,
    });
    const prepared = await key.prepareAssertion({ baseUrl });
    return {
      credentialId: prepared.credentialId,
      assertion: prepared.assertion,
      secondFactorHash: credentialSecondFactorHash(prepared.credentialId),
    };
  }

  async function signedPayload(
    challenge: string,
    secondFactorHash: string,
    factor?: { credentialId: string; assertion: any }
  ): Promise<Record<string, unknown>> {
    const message = clearanceMessage(challenge, secondFactorHash, proofHash);
    const signature = await crypto.webcrypto.subtle.sign(
      { name: 'ECDSA', hash: 'SHA-256' },
      userKey.privateKey,
      new TextEncoder().encode(message)
    );
    const payload: Record<string, unknown> = {
      v: 1,
      challengeId: challenge,
      secondFactorHash,
      userPublicKey: { kty: userJwk.kty, crv: userJwk.crv, x: userJwk.x, y: userJwk.y },
      userSignature: Buffer.from(signature).toString('base64url'),
      proofBase64: proofB64,
      fullName: 'Stress Sentinel Name',
      dateOfBirth: '1900-01-01',
      age: 32,
    };
    if (factor) {
      payload.credentialId = factor.credentialId;
      payload.webauthnAssertion = factor.assertion;
    }
    return payload;
  }

  async function postClearance(payload: unknown, cookie?: string): Promise<{ status: number; json: any; text: string; ms: number }> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (cookie) headers.Cookie = cookie;
    const started = performance.now();
    let res: Response;
    try {
      res = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
        method: 'POST',
        headers,
        body: typeof payload === 'string' ? payload : JSON.stringify(payload),
      });
    } catch (err) {
      crashes.push(`clearance fetch: ${err instanceof Error ? err.message : String(err)}`);
      return { status: 0, json: null, text: '', ms: performance.now() - started };
    }
    const parsed = await readBody(res);
    if (parsed.status >= 500) crashes.push(`clearance ${parsed.status}: ${parsed.text.slice(0, 240)}`);
    return { status: parsed.status, json: parsed.json, text: parsed.text, ms: performance.now() - started };
  }

  try {
    const health = await fetch(`${baseUrl}/api/health`);
    add('A0', 'boot', health.ok ? 'PASS' : 'FAIL', `GET /api/health ${health.status}; proof setup ${Math.round(proofMs)}ms`);

    const swissCookie = await sessionCookie('swiss_adult');
    const minorCookie = await sessionCookie('minor_luca');
    const substantialCookie = await sessionCookie('it_adult_substantial');
    const italianCookie = await sessionCookie('it_adult_high');

    // --- D. Security controls that must reject ---
    const noCookieIssued = await issue('BILANX-CH-EIDAS-NODE-01');
    const noCookieFactor = await freshFactor();
    const noCookie = await postClearance(
      await signedPayload(noCookieIssued.body.challenge, noCookieFactor.secondFactorHash, noCookieFactor)
    );
    add(
      'D1',
      'security',
      noCookie.json?.valid === false && noCookie.json?.reason === 'Session is required' && noCookie.json?.envelope === undefined
        ? 'PASS'
        : 'FAIL',
      `clearance without cookie: ${noCookie.status} ${noCookie.json?.reason}`
    );

    const underIssued = await issue('BILANX-CH-EIDAS-NODE-01');
    const underFactor = await freshFactor();
    const under = await postClearance(
      await signedPayload(underIssued.body.challenge, underFactor.secondFactorHash, underFactor),
      minorCookie
    );
    add(
      'D2',
      'security',
      under.json?.valid === false && under.json?.reason === 'Session age gate rejected the clearance'
        ? 'PASS'
        : 'FAIL',
      `adult proof + underage session: ${under.json?.reason}`
    );

    const loaIssued = await issue('BILANX-IT-AGCOM-NODE-01');
    const loaFactor = await freshFactor();
    const loa = await postClearance(
      await signedPayload(loaIssued.body.challenge, loaFactor.secondFactorHash, loaFactor),
      substantialCookie
    );
    add(
      'D3',
      'security',
      loa.json?.valid === false && loa.json?.reason === 'Italian LoA High is required'
        ? 'PASS'
        : 'FAIL',
      `IT LoA Substantial: ${loa.json?.reason} jurisdiction on challenge ${loaIssued.body?.jurisdiction}`
    );

    const unboundIssued = await issue('BILANX-CH-EIDAS-NODE-01');
    const unbound = await postClearance(
      await signedPayload(unboundIssued.body.challenge, 'client-chosen-factor'),
      swissCookie
    );
    const unboundText = JSON.stringify(unbound.json);
    add(
      'D4',
      'security',
      unbound.json?.valid === false &&
      unbound.json?.reason === 'Second factor is not bound to a verified authenticator' &&
      !unboundText.includes('client-chosen-factor') &&
      !unboundText.includes('Stress Sentinel')
        ? 'PASS'
        : 'FAIL',
      `unbound second factor: ${unbound.json?.reason}`
    );

    const goodIssued = await issue('BILANX-CH-EIDAS-NODE-01');
    const goodFactor = await freshFactor();
    const goodPayload = await signedPayload(goodIssued.body.challenge, goodFactor.secondFactorHash, goodFactor);
    goodPayload.productUid = 'UID-7701-AUTH-118';
    const good = await postClearance(goodPayload, swissCookie);
    const envelope = good.json?.envelope as ClearanceEnvelope | undefined;
    const envelopeText = JSON.stringify(good.json?.envelope ?? {});
    const goodOk = good.json?.valid === true
      && envelope?.sessionAgeGatePassed === true
      && envelope?.loaHigh === false
      && envelope?.retailSale === true
      && envelope?.productUid === 'UID-7701-AUTH-118'
      && envelope?.excise === 3.85
      && !envelopeText.includes('Stress Sentinel')
      && !envelopeText.includes('1900-01-01')
      && !envelopeText.includes('"age"');
    add('D5', 'security', goodOk ? 'PASS' : 'FAIL', `retail clearance valid=${good.json?.valid} excise=${envelope?.excise} ${Math.round(good.ms)}ms`);

    const replay = await postClearance(goodPayload, swissCookie);
    add(
      'D6',
      'security',
      replay.json?.valid === false && String(replay.json?.reason).includes('Replay detected') ? 'PASS' : 'FAIL',
      `consumed nonce replay: ${replay.json?.reason}`
    );

    if (envelope && typeof good.json?.envelopeSignature === 'string') {
      const forged = { ...envelope, excise: 0, productCategory: 'Tobacco' };
      const forgedRes = await readBody(await fetch(`${baseUrl}/api/v1/envelope/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: forged, envelopeSignature: good.json.envelopeSignature }),
      }));
      const receiptForged = { ...envelope, receiptSha256: 'ab'.repeat(32) };
      const receiptRes = await readBody(await fetch(`${baseUrl}/api/v1/envelope/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: receiptForged, envelopeSignature: good.json.envelopeSignature }),
      }));
      const canonical = canonicalClearanceEnvelope(envelope);
      const jwks = await (await fetch(`${baseUrl}/api/v1/jwks`)).json() as { keys?: Array<{ kid?: string; kty?: string; crv?: string; x?: string; y?: string; d?: string }> };
      const jwk = (jwks.keys || []).find((key) => key.kid === envelope.keyId);
      let local = false;
      if (jwk?.kty && jwk.crv && jwk.x && jwk.y) {
        const tillKey = await crypto.webcrypto.subtle.importKey(
          'jwk',
          { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
          { name: 'ECDSA', namedCurve: 'P-256' },
          true,
          ['verify']
        );
        local = await crypto.webcrypto.subtle.verify(
          { name: 'ECDSA', hash: 'SHA-256' },
          tillKey,
          Buffer.from(good.json.envelopeSignature, 'base64'),
          new TextEncoder().encode(canonical)
        );
      }
      const verifyOk = await readBody(await fetch(`${baseUrl}/api/v1/envelope/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ envelope: canonical, envelopeSignature: good.json.envelopeSignature }),
      }));
      add(
        'E1',
        'integrity',
        local && verifyOk.json?.valid === true && verifyOk.json?.retailSale === true && jwk?.d === undefined ? 'PASS' : 'FAIL',
        `JWKS local verify=${local} http valid=${verifyOk.json?.valid} retailSale=${verifyOk.json?.retailSale} private d published=${jwk?.d !== undefined}`
      );
      add(
        'D7',
        'security',
        forgedRes.json?.valid === false && forgedRes.json?.reason === 'signature_rejected'
          && receiptRes.json?.valid === false
          ? 'PASS'
          : 'FAIL',
        `forged excise/category=${forgedRes.json?.reason} forged receipt=${receiptRes.json?.reason}`
      );
    } else {
      add('E1', 'integrity', 'FAIL', 'no envelope to verify');
      add('D7', 'security', 'FAIL', 'no envelope to tamper');
    }

    const stockCases: Array<{ id: string; body: Record<string, unknown>; reason: string }> = [
      { id: 'D8a', body: { hardwareUid: 'UID-0000-NO-SUCH' }, reason: 'unknown_uid' },
      { id: 'D8b', body: { hardwareUid: 'UID-0000-BADSIG-1' }, reason: 'signature_rejected' },
      { id: 'D8c', body: { hardwareUid: 'UID-0000-UNSIGNED-1' }, reason: 'unsigned' },
      { id: 'D8d', body: { hardwareUid: 'UID-1102-FAKE-881' }, reason: 'counterfeit' },
      { id: 'D8e', body: { hardwareUid: 'UID-3221-RECALLED-60' }, reason: 'recalled' },
      { id: 'D8f', body: {}, reason: 'missing_uid' },
    ];
    for (const stockCase of stockCases) {
      const stock = await readBody(await fetch(`${baseUrl}/api/v1/stock/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(stockCase.body),
      }));
      const leaked = stock.text.includes('AAAA') || stock.text.includes('XLzvVVZCqNdPSny_whZHeiu9YwVMbGFSKJgul4FNVN0');
      add(
        stockCase.id,
        'security',
        stock.json?.ok === false && stock.json?.reason === stockCase.reason && !leaked ? 'PASS' : 'FAIL',
        `stock ${JSON.stringify(stockCase.body)} -> ${stock.json?.reason} ok=${stock.json?.ok}`
      );
    }

    const staleKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await staleKey.registerWithServer({ baseUrl, username: `stale-${crypto.randomUUID()}@bilanx.org` });
    const firstAssertion = await staleKey.prepareAssertion({ baseUrl, overrideCounter: 1 });
    const secondAssertion = await staleKey.prepareAssertion({ baseUrl, overrideCounter: 2 });
    const postAssertion = async (assertion: typeof firstAssertion.assertion, credentialId: string) => readBody(await fetch(`${baseUrl}/api/webauthn/authenticate-verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: origin },
      body: JSON.stringify({ credentialId, assertion, requireUserVerification: true }),
    }));
    const higherFirst = await postAssertion(secondAssertion.assertion, secondAssertion.credentialId);
    const lowerAfter = await postAssertion(firstAssertion.assertion, firstAssertion.credentialId);
    add(
      'D9',
      'security',
      higherFirst.json?.verified === true && lowerAfter.json?.verified === false && String(lowerAfter.json?.error).includes('Cloned authenticator')
        ? 'FINDING'
        : higherFirst.json?.verified === true && lowerAfter.json?.verified === false
          ? 'PASS'
          : 'FAIL',
      `out-of-order counters: counter 2 verified=${higherFirst.json?.verified}, counter 1 verified=${lowerAfter.json?.verified} error=${lowerAfter.json?.error}`
    );

    const sameKey = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
    await sameKey.registerWithServer({ baseUrl, username: `replay-factor-${crypto.randomUUID()}@bilanx.org` });
    const once = await sameKey.prepareAssertion({ baseUrl });
    const replayPair = await Promise.all([
      postAssertion(once.assertion, once.credentialId),
      postAssertion(once.assertion, once.credentialId),
    ]);
    const replayWins = replayPair.filter((item) => item.json?.verified === true).length;
    add(
      'A2',
      'concurrency',
      replayWins === 1 ? 'PASS' : 'FAIL',
      `parallel duplicate WebAuthn assertion successes=${replayWins}/2 statuses=${replayPair.map((item) => item.status).join(',')}`
    );

    // --- A. Same nonce stampede ---
    const raceIssued = await issue('BILANX-CH-EIDAS-NODE-01');
    const raceFactor = await freshFactor();
    const racePayload = await signedPayload(raceIssued.body.challenge, raceFactor.secondFactorHash, raceFactor);
    const raceStarted = performance.now();
    const raceResults = await Promise.all(Array.from({ length: 25 }, () => postClearance(racePayload, swissCookie)));
    const raceMs = performance.now() - raceStarted;
    const raceValid = raceResults.filter((item) => item.json?.valid === true).length;
    const raceReplay = raceResults.filter((item) => String(item.json?.reason || '').includes('Replay detected')).length;
    const race500 = raceResults.filter((item) => item.status >= 500 || item.status === 0).length;
    add(
      'A1',
      'concurrency',
      raceValid === 1 && raceReplay === 24 && race500 === 0 ? 'PASS' : 'FAIL',
      `25-way same nonce: valid=${raceValid} replay=${raceReplay} http500=${race500} wall=${Math.round(raceMs)}ms`
    );

    // --- A. Parallel stock + clearance ---
    const mixStarted = performance.now();
    const mixStock = await Promise.all(Array.from({ length: 40 }, async (_, index) => readBody(await fetch(`${baseUrl}/api/v1/stock/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hardwareUid: index % 2 === 0 ? 'UID-7701-AUTH-118' : 'UID-1102-FAKE-881' }),
    }))));
    const mixClearIssued = await Promise.all([
      issue('BILANX-CH-EIDAS-NODE-01'),
      issue('BILANX-IT-AGCOM-NODE-01'),
      issue('BILANX-CH-EIDAS-NODE-01'),
      issue('BILANX-CH-EIDAS-NODE-01'),
    ]);
    const mixFactors = [];
    for (let i = 0; i < 4; i += 1) mixFactors.push(await newIsolatedFactor());
    const mixPayloads = await Promise.all(mixFactors.map(async (factor, index) => {
      const payload = await signedPayload(mixClearIssued[index].body.challenge, factor.secondFactorHash, factor);
      if (index === 0) payload.productUid = 'UID-7701-AUTH-118';
      if (index === 1) payload.productUid = 'UID-4408-AUTH-018';
      return payload;
    }));
    const mixCookies = [swissCookie, italianCookie, swissCookie, swissCookie];
    const mixClear = await Promise.all(mixPayloads.map((payload, index) => postClearance(payload, mixCookies[index])));
    const mixWall = performance.now() - mixStarted;
    const stockOk = mixStock.filter((item) => item.json?.hardwareUid === 'UID-7701-AUTH-118' && item.json?.ok === true).length;
    const stockFake = mixStock.filter((item) => item.json?.reason === 'counterfeit').length;
    const mixClearOk = mixClear.filter((item) => item.json?.valid === true).length;
    const itEnvelope = mixClear[1].json?.envelope;
    add(
      'A3',
      'concurrency',
      stockOk === 20 && stockFake === 20 && mixClearOk === 4 && itEnvelope?.loaHigh === true && itEnvelope?.jurisdiction === 'IT' && itEnvelope?.excise === 0
        ? 'PASS'
        : 'FAIL',
      `parallel stock authentic=${stockOk}/20 counterfeit=${stockFake}/20 clearances=${mixClearOk}/4 IT loaHigh=${itEnvelope?.loaHigh} excise=${itEnvelope?.excise} wall=${Math.round(mixWall)}ms`
    );

    // --- A/B. Sessions ---
    const sessionStarted = performance.now();
    const sessionResponses = await Promise.all(Array.from({ length: 12 }, () => fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset: 'swiss_adult' }),
    })));
    const sessionOk = sessionResponses.filter((res) => res.ok).length;
    const sessionTokens = new Set<string>();
    for (const res of sessionResponses) {
      const body = await res.json();
      if (typeof body.sessionToken === 'string') sessionTokens.add(body.sessionToken);
    }
    add(
      'A4',
      'concurrency',
      sessionOk === 12 && sessionTokens.size === 12 ? 'PASS' : 'FAIL',
      `12 parallel ACS: httpOk=${sessionOk} distinct tokens=${sessionTokens.size} wall=${Math.round(performance.now() - sessionStarted)}ms`
    );

    const beforeSessions = globalSessionStore.size();
    for (let i = 0; i < 1000; i += 1) {
      globalSessionStore.createSession({
        uid: `load-${i}`,
        email: 'verified@eidas.europa.eu',
        name: 'eIDAS User',
        authMethod: 'eidas_saml',
        role: 'CASHIER',
        permissions: [],
        levelOfAssurance: 'HIGH',
        isOver18: true,
        authenticatedAt: new Date().toISOString(),
      });
    }
    const grown = globalSessionStore.size();
    const short = globalSessionStore.createSession({
      uid: 'ttl',
      email: 'verified@eidas.europa.eu',
      name: 'eIDAS User',
      authMethod: 'eidas_saml',
      role: 'CASHIER',
      permissions: [],
      levelOfAssurance: 'HIGH',
      isOver18: true,
      authenticatedAt: new Date().toISOString(),
    }, 40);
    await new Promise((resolve) => setTimeout(resolve, 60));
    const expired = globalSessionStore.getSession(short.token);
    const pruned = globalSessionStore.pruneExpiredSessions();
    add(
      'B3',
      'load',
      grown === beforeSessions + 1000 && expired === null ? 'FINDING' : 'FAIL',
      `session map grew by ${grown - beforeSessions} with no cap (size=${grown}). short TTL lookup=${expired === null ? 'expired' : 'still-live'} pruned=${pruned}`
    );

    // --- B. Sustained clearances, one reused proof, one credential, fresh nonces ---
    const sequentialMs: number[] = [];
    let sequentialOk = 0;
    const sequentialN = 20;
    for (let i = 0; i < sequentialN; i += 1) {
      const issued = await issue('BILANX-CH-EIDAS-NODE-01');
      const factor = await freshFactor();
      const payload = await signedPayload(issued.body.challenge, factor.secondFactorHash, factor);
      const result = await postClearance(payload, swissCookie);
      sequentialMs.push(result.ms);
      if (result.json?.valid === true) sequentialOk += 1;
    }
    add(
      'B2a',
      'load',
      sequentialOk === sequentialN ? 'PASS' : 'FAIL',
      `sequential clearances ${sequentialOk}/${sequentialN} ${summarize(sequentialMs)}`
    );

    const parallelN = 16;
    const parallelIssued = [];
    for (let i = 0; i < parallelN; i += 1) parallelIssued.push(await issue('BILANX-CH-EIDAS-NODE-01'));
    const parallelFactors = [];
    for (let i = 0; i < parallelN; i += 1) parallelFactors.push(await newIsolatedFactor());
    const parallelPayloads = await Promise.all(parallelFactors.map((factor, index) =>
      signedPayload(parallelIssued[index].body.challenge, factor.secondFactorHash, factor)
    ));
    const parallelStarted = performance.now();
    const parallelResults = await Promise.all(parallelPayloads.map((payload) => postClearance(payload, swissCookie)));
    const parallelWall = performance.now() - parallelStarted;
    const parallelOk = parallelResults.filter((item) => item.json?.valid === true).length;
    const parallelTimes = parallelResults.map((item) => item.ms);
    add(
      'B2b',
      'load',
      parallelOk === parallelN ? 'PASS' : 'FAIL',
      `parallel clearances ${parallelOk}/${parallelN} wall=${Math.round(parallelWall)}ms throughput=${(parallelN / (parallelWall / 1000)).toFixed(2)} req/s ${summarize(parallelTimes)}`
    );

    // --- C. Malformed and oversized ---
    const malformed: Array<{ id: string; path: string; body: string; accept: (status: number, json: any) => boolean; note: string }> = [
      { id: 'C1a', path: '/api/v1/dual-key/verify', body: '{', accept: (status) => status === 400, note: 'invalid JSON' },
      { id: 'C1b', path: '/api/v1/dual-key/verify', body: 'null', accept: (status) => status === 400, note: 'JSON null rejected by the parser' },
      { id: 'C1c', path: '/api/v1/dual-key/verify', body: JSON.stringify({ v: 1 }), accept: (status, json) => status === 400, note: 'missing fields' },
      { id: 'C1d', path: '/api/v1/dual-key/verify', body: JSON.stringify({ v: '1', challengeId: 1, secondFactorHash: 2, userPublicKey: 'nope', userSignature: false, proofBase64: null }), accept: (status) => status === 400, note: 'wrong types' },
      { id: 'C1e', path: '/api/v1/stock/verify', body: JSON.stringify({ hardwareUid: { uid: 'UID-7701-AUTH-118' }, category: 'Alcohol', signature: 'AAAA' }), accept: (status, json) => status === 200 && json?.reason === 'missing_uid', note: 'object UID cannot smuggle a signature' },
      { id: 'C1f', path: '/api/v1/envelope/verify', body: JSON.stringify({ envelope: [], envelopeSignature: 12 }), accept: (status, json) => status === 200 && (json?.reason === 'unsigned' || json?.reason === 'malformed'), note: 'wrong envelope types' },
      { id: 'C1g', path: '/api/webauthn/register-options', body: JSON.stringify({}), accept: (status) => status === 400, note: 'missing username' },
      { id: 'C1h', path: '/saml/acs', body: JSON.stringify({ preset: ['swiss_adult'] }), accept: (status) => status === 400, note: 'preset array' },
      { id: 'C1i', path: '/saml/acs', body: JSON.stringify({ xml_content: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' }), accept: (status, json) => status >= 400 && json?.success === false, note: 'DTD payload' },
    ];
    for (const item of malformed) {
      const res = await fetch(`${baseUrl}${item.path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: item.body,
      });
      const parsed = await readBody(res);
      if (parsed.status >= 500) crashes.push(`${item.id} ${parsed.status} ${parsed.text.slice(0, 180)}`);
      add(item.id, 'edge', item.accept(parsed.status, parsed.json) && parsed.status < 500 ? 'PASS' : 'FAIL', `${item.note}: HTTP ${parsed.status} ${parsed.json?.reason || parsed.json?.error || parsed.text.slice(0, 80)}`);
    }

    const oversized = await fetch(`${baseUrl}/api/v1/dual-key/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ blob: 'A'.repeat(180_000) }),
    });
    const oversizedText = await oversized.text();
    const afterOversize = await fetch(`${baseUrl}/api/health`);
    add(
      'C2',
      'edge',
      oversized.status === 413 && afterOversize.ok ? 'PASS' : oversized.status >= 500 ? 'FAIL' : 'FINDING',
      `180KB JSON -> HTTP ${oversized.status}; health after=${afterOversize.status}; body starts ${oversizedText.slice(0, 60).replace(/\s+/g, ' ')}`
    );

    const controller = new AbortController();
    const aborted = fetch(`${baseUrl}/api/v1/stock/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hardwareUid: 'UID-7701-AUTH-118' }),
      signal: controller.signal,
    }).then(() => 'completed').catch((err: unknown) => err instanceof Error ? err.name : 'error');
    controller.abort();
    const abortName = await aborted;
    const afterAbort = await fetch(`${baseUrl}/api/health`);
    add('C3', 'edge', afterAbort.ok ? 'PASS' : 'FAIL', `aborted client request (${abortName}); health after=${afterAbort.status}`);

    // --- C. Key and store edges ---
    let missingKey = '';
    try {
      await loadPrimaryKeyOrThrow({}, { allowEphemeral: false });
    } catch (err) {
      missingKey = err instanceof Error ? err.message : String(err);
    }
    add('C4', 'edge', missingKey.includes('[FATAL]') && missingKey.includes('INSTITUTIONAL_KEY_JSON') ? 'PASS' : 'FAIL', `production missing key: ${missingKey.slice(0, 140)}`);

    process.env.INSTITUTIONAL_KEY_SOURCE = 'kms';
    let kmsMessage = '';
    try {
      await getInstitutionalKey('CH');
    } catch (err) {
      kmsMessage = err instanceof Error ? err.message : String(err);
    }
    delete process.env.INSTITUTIONAL_KEY_SOURCE;
    const keyStillThere = await getInstitutionalKey('CH');
    add('C5', 'edge', kmsMessage.includes('no KMS adapter') && keyStillThere.keyId.length > 0 ? 'PASS' : 'FAIL', `KMS source: ${kmsMessage.slice(0, 120)}`);

    const storeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bilanx-stress-store-'));
    const storePath = path.join(storeDir, 'nonces.json');
    const writer = new FileDurableMap<string>(storePath);
    writer.set('keep', 'yes');
    const reloaded = new FileDurableMap<string>(storePath);
    const memory = new MemoryDurableMap<string>();
    memory.set('keep', 'yes');
    const freshMemory = new MemoryDurableMap<string>();
    add(
      'C6',
      'edge',
      reloaded.get('keep') === 'yes' && freshMemory.get('keep') === undefined ? 'PASS' : 'FAIL',
      `file reload has keep=${reloaded.get('keep')}; new memory map has keep=${String(freshMemory.get('keep'))}`
    );

    fs.writeFileSync(path.join(storeDir, 'corrupt.json'), '{not json');
    let corruptMessage = '';
    try {
      new FileDurableMap<string>(path.join(storeDir, 'corrupt.json'));
    } catch (err) {
      corruptMessage = err instanceof Error ? err.message : String(err);
    }
    add('C7', 'edge', corruptMessage.includes('Refusing to open corrupt security store') ? 'PASS' : 'FAIL', corruptMessage);

    const left = new FileDurableMap<string>(path.join(storeDir, 'clobber.json'));
    const right = new FileDurableMap<string>(path.join(storeDir, 'clobber.json'));
    left.set('left', 'L');
    right.set('right', 'R');
    const afterClobber = new FileDurableMap<string>(path.join(storeDir, 'clobber.json'));
    const lostLeft = afterClobber.get('left') === undefined && afterClobber.get('right') === 'R';
    add(
      'A5',
      'concurrency',
      lostLeft ? 'FINDING' : afterClobber.get('left') === 'L' && afterClobber.get('right') === 'R' ? 'PASS' : 'FAIL',
      `two FileDurableMap writers: left=${String(afterClobber.get('left'))} right=${String(afterClobber.get('right'))}`
    );

    const oneWriter = new FileDurableMap<number>(path.join(storeDir, 'one.json'));
    await Promise.all(Array.from({ length: 40 }, (_, index) => Promise.resolve().then(() => {
      oneWriter.set(`k${index}`, index);
    })));
    const oneReloaded = new FileDurableMap<number>(path.join(storeDir, 'one.json'));
    const oneCount = Array.from(oneReloaded.keys()).length;
    add('A6', 'concurrency', oneCount === 40 ? 'PASS' : 'FAIL', `one FileDurableMap, 40 queued writers, reloaded keys=${oneCount}`);

    const secondStore = new (globalSessionStore.constructor as typeof globalSessionStore.constructor)();
    add(
      'C8',
      'edge',
      secondStore.size() === 0 && globalSessionStore.size() > 0 ? 'FINDING' : 'FAIL',
      `a new SessionStore does not see the ${globalSessionStore.size()} live sessions`
    );

    // --- D. Unauthenticated routes ---
    const requestEmail = 'leak-sentinel@example.test';
    const requestName = 'Leak Sentinel';
    const beforeLogs = await getAccessLogs({ limit: 1 });
    const logs = await readBody(await fetch(`${baseUrl}/api/access-logs`));
    const metrics = await readBody(await fetch(`${baseUrl}/api/metrics`));
    const exportRes = await fetch(`${baseUrl}/api/access-logs/export`, { headers: { Cookie: swissCookie } });
    const exportText = await exportRes.text();
    const swissList = await readBody(await fetch(`${baseUrl}/api/access-logs`, { headers: { Cookie: swissCookie } }));
    const swissClear = await readBody(await fetch(`${baseUrl}/api/access-logs/clear`, {
      method: 'POST',
      headers: { Cookie: swissCookie },
    }));
    const highSession = await readBody(await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: italianCookie } }));
    const highExport = await fetch(`${baseUrl}/api/access-logs/export`, { headers: { Cookie: italianCookie } });
    await highExport.arrayBuffer();
    const unauthExport = await fetch(`${baseUrl}/api/access-logs/export`);
    await unauthExport.arrayBuffer();
    const unauthClear = await readBody(await fetch(`${baseUrl}/api/access-logs/clear`, { method: 'POST' }));
    const unauthStats = await readBody(await fetch(`${baseUrl}/api/access-logs/stats`));
    const swissStats = await readBody(await fetch(`${baseUrl}/api/access-logs/stats`, { headers: { Cookie: swissCookie } }));
    const swissSession = await readBody(await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: swissCookie } }));
    const recordEvent = await readBody(await fetch(`${baseUrl}/api/auth/record-event`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: { uid: 'stress-guest', email: requestEmail, name: requestName },
        action: 'APP_ACCESS',
        metadata: { note: 'unauthenticated write' },
      }),
    }));
    const afterRejected = await getAccessLogs({ search: requestEmail, limit: 5 });
    const afterRejectedName = await getAccessLogs({ search: requestName, limit: 5 });
    const afterRejectedTotal = await getAccessLogs({ limit: 1 });
    const rejectedWriteMissed = afterRejected.total === 0
      && afterRejectedName.total === 0
      && afterRejectedTotal.total === beforeLogs.total
      && !recordEvent.text.includes(requestEmail)
      && !exportText.includes(requestEmail)
      && !swissList.text.includes(requestEmail);
    const operator = globalSessionStore.createSession({
      uid: 'stress-audit-operator',
      email: 'operator@bilanx.test',
      name: 'Audit Operator',
      authMethod: 'eidas_saml',
      role: 'OPERATOR',
      authenticatedAt: new Date().toISOString(),
    });
    const operatorCookie = `session_token=${encodeURIComponent(operator.token)}`;
    const operatorList = await readBody(await fetch(`${baseUrl}/api/access-logs`, { headers: { Cookie: operatorCookie } }));
    const operatorExport = await fetch(`${baseUrl}/api/access-logs/export`, { headers: { Cookie: operatorCookie } });
    const operatorExportType = operatorExport.headers.get('content-type') || '';
    const operatorExportText = await operatorExport.text();
    const operatorClear = await readBody(await fetch(`${baseUrl}/api/access-logs/clear`, {
      method: 'POST',
      headers: { Cookie: operatorCookie },
    }));
    const afterOperatorClear = await getAccessLogs({ limit: 1 });
    const logoutAcs = await readBody(await fetch(`${baseUrl}/saml/acs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ preset: 'swiss_adult' }),
    }));
    const logoutToken = typeof logoutAcs.json?.sessionToken === 'string' ? logoutAcs.json.sessionToken : '';
    const logoutEvent = await readBody(await fetch(`${baseUrl}/api/auth/record-event`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${logoutToken}`,
      },
      body: JSON.stringify({
        user: { uid: 'stress-guest', email: requestEmail, name: requestName },
        action: 'LOGOUT',
        metadata: { sessionDurationSeconds: 1 },
      }),
    }));
    const logoutSession = await readBody(await fetch(`${baseUrl}/saml/session`, {
      headers: { Authorization: `Bearer ${logoutToken}` },
    }));
    const storedRequestEmail = await getAccessLogs({ search: requestEmail, limit: 5 });
    const sessionStillActive = await readBody(await fetch(`${baseUrl}/saml/session`, { headers: { Cookie: swissCookie } }));
    add('D10', 'security', logs.status === 401 ? 'PASS' : 'FAIL', `GET /api/access-logs without cookie -> ${logs.status}`);
    add(
      'D11',
      'security',
      metrics.status === 200 && metrics.json?.clearance?.events ? 'FINDING' : 'FAIL',
      `GET /api/metrics without cookie -> ${metrics.status} successEvents=${metrics.json?.clearance?.events?.clearance_success}`
    );
    add(
      'D12',
      'security',
      exportRes.status === 403
        && swissList.status === 403
        && swissClear.status === 403
        && highExport.status === 403
        && highSession.json?.user?.role === 'STORE_MANAGER'
        && Array.isArray(highSession.json?.user?.permissions)
        && highSession.json.user.permissions.includes('ELEVATED_AUDIT_LOG_EXPORT')
        && swissSession.json?.user?.role === 'STORE_MANAGER'
        && swissSession.json?.active === true
        ? 'PASS'
        : 'FAIL',
      `demo sessions denied access-log list/export/clear swiss=${swissList.status}/${exportRes.status}/${swissClear.status} highLoaExport=${highExport.status} highRole=${highSession.json?.user?.role}`
    );
    add(
      'D12b',
      'security',
      unauthExport.status === 401 && unauthClear.status === 401 && unauthStats.status === 401 && swissStats.status === 200
        ? 'PASS'
        : 'FAIL',
      `unauth export/clear/stats=${unauthExport.status}/${unauthClear.status}/${unauthStats.status} swiss stats=${swissStats.status}`
    );
    add(
      'D12c',
      'security',
      operatorList.status === 200
        && Array.isArray(operatorList.json?.logs)
        && operatorExport.status === 200
        && operatorExportType.includes('text/csv')
        && operatorExportText.includes('Email')
        && operatorClear.status === 200
        && afterOperatorClear.total === 0
        ? 'PASS'
        : 'FAIL',
      `operator list/export/clear=${operatorList.status}/${operatorExport.status}/${operatorClear.status} rows after clear=${afterOperatorClear.total}`
    );
    add(
      'D13',
      'security',
      recordEvent.status === 401 && recordEvent.json?.log === undefined && rejectedWriteMissed ? 'PASS' : 'FAIL',
      `POST /api/auth/record-event without a session -> ${recordEvent.status} stored=${afterRejected.total} rows=${afterRejectedTotal.total}`
    );
    add(
      'D13b',
      'security',
      logoutAcs.status === 200
        && logoutEvent.status === 200
        && logoutEvent.json?.log?.email === logoutAcs.json?.user?.email
        && logoutEvent.json?.log?.email !== requestEmail
        && logoutEvent.json?.log?.name !== requestName
        && logoutSession.status === 401
        && storedRequestEmail.total === 0
        && sessionStillActive.json?.active === true
        && !logoutEvent.text.includes(requestEmail)
        ? 'PASS'
        : 'FAIL',
      `session record-event status=${logoutEvent.status} logout invalidates bearer=${logoutSession.status} original session active=${sessionStillActive.json?.active}`
    );
    const sharedNow = fs.existsSync(sharedAccessLog) ? fs.readFileSync(sharedAccessLog) : null;
    const sharedUntouched = sharedAccessBefore === null
      ? sharedNow === null
      : sharedNow !== null && sharedNow.equals(sharedAccessBefore);
    add(
      'D13c',
      'security',
      sharedUntouched && (sharedNow === null || !sharedNow.includes(requestEmail)) ? 'PASS' : 'FAIL',
      `shared access log untouched by the isolated access-log cases bytesMatch=${sharedUntouched}`
    );

    const previousNodeEnv = process.env.NODE_ENV;
    const token = decodeURIComponent((swissCookie.split('session_token=')[1] || '').split(';')[0]);
    const prodIssued = await issue('BILANX-CH-EIDAS-NODE-01');
    const prodPayload = await signedPayload(prodIssued.body.challenge, (await freshFactor()).secondFactorHash);
    process.env.NODE_ENV = 'production';
    const prodQuery = await postClearance(prodPayload);
    const prodQueryWithToken = await fetch(`${baseUrl}/saml/session?token=${encodeURIComponent(token)}`);
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previousNodeEnv;
    const devQuery = await fetch(`${baseUrl}/saml/session?token=${encodeURIComponent(token || '')}`);
    const devQueryBody = await devQuery.json();
    add(
      'D14',
      'security',
      prodQuery.json?.reason === 'Session is required' && prodQueryWithToken.status === 401 && devQueryBody.active === true ? 'FINDING' : 'FAIL',
      `query token session lookup production=${prodQueryWithToken.status} development=${devQuery.status} active=${devQueryBody.active}. Clearance without cookie under production env reason=${prodQuery.json?.reason}`
    );

    // --- E. Audit allow-list ---
    const auditText = fs.readFileSync(auditPath, 'utf8');
    const auditLines = auditText.split('\n').filter((line) => line.trim().length > 0).map((line) => JSON.parse(line) as Record<string, unknown>);
    const allowed = new Set(['event', 'jurisdiction', 'prove_ms', 'verify_ms', 'total_ms', 'reason', 'keyId']);
    const onlyAllowed = auditLines.every((line) => Object.keys(line).every((key) => allowed.has(key)));
    const leakedAudit = auditText.includes('Stress Sentinel') || auditText.includes('1900-01-01') || auditText.includes('"age"') || auditText.includes(proofB64.slice(0, 40));
    const metricsText = JSON.stringify(metrics.json);
    add(
      'E2',
      'integrity',
      onlyAllowed && !leakedAudit && auditLines.some((line) => line.event === 'clearance_success') && auditLines.some((line) => line.reason === 'session_required')
        && !metricsText.includes('Stress Sentinel')
        ? 'PASS'
        : 'FAIL',
      `audit lines=${auditLines.length} allow-listed=${onlyAllowed} leakedSentinel=${leakedAudit}`
    );

    // --- B. Capacity. This consumes the process caps. Keep it last. ---
    const savedCredentialId = factorKey ? (await freshFactor()).credentialId : '';
    const credBefore = registeredWebAuthnCredentials.size;
    while (registeredWebAuthnCredentials.size < MAX_STORED_CREDENTIALS) {
      const id = `filler-${registeredWebAuthnCredentials.size}`;
      registeredWebAuthnCredentials.set(id, {
        credentialId: id,
        publicKeyPem: 'filler',
        username: 'filler',
        counter: 0,
        createdAt: new Date().toISOString(),
        authenticatorAttachment: 'platform',
      });
    }
    let register429 = 0;
    try {
      const overflow = new Ctap2HardwareKeyHarness({ aaguid: YUBIKEY_5_SERIES_AAGUID });
      await overflow.registerWithServer({ baseUrl, username: `overflow-${crypto.randomUUID()}@bilanx.org` });
    } catch (err) {
      register429 = err instanceof Error && err.message.includes('capacity') ? 429 : 0;
      if (!register429) crashes.push(`credential overflow: ${err instanceof Error ? err.message : String(err)}`);
    }
    const credAfter = registeredWebAuthnCredentials.size;
    const stillThere = registeredWebAuthnCredentials.get(savedCredentialId);
    add(
      'B1a',
      'load',
      credBefore < MAX_STORED_CREDENTIALS && credAfter === MAX_STORED_CREDENTIALS && register429 === 429 && stillThere !== undefined
        ? 'PASS'
        : 'FAIL',
      `credential cap ${credBefore} -> ${credAfter}/${MAX_STORED_CREDENTIALS}, overflow=${register429}, pre-existing credential kept=${stillThere !== undefined}`
    );

    let webauthn429 = 0;
    let webauthnIssued = 0;
    while (webauthn429 === 0 && webauthnIssued < MAX_ACTIVE_WEBAUTHN_CHALLENGES + 5) {
      const res = await fetch(`${baseUrl}/api/webauthn/authenticate-options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      webauthnIssued += 1;
      if (res.status === 429) {
        webauthn429 = 429;
        break;
      }
      if (res.status >= 500) {
        crashes.push(`webauthn options ${res.status}`);
        break;
      }
    }
    add(
      'B1b',
      'load',
      webauthn429 === 429 && activeWebAuthnChallenges.size === MAX_ACTIVE_WEBAUTHN_CHALLENGES ? 'PASS' : 'FAIL',
      `WebAuthn challenge HTTP calls=${webauthnIssued} status429=${webauthn429} size=${activeWebAuthnChallenges.size}/${MAX_ACTIVE_WEBAUTHN_CHALLENGES}`
    );

    const firstChallenge = await issue('BILANX-CH-EIDAS-NODE-01');
    const keptId = firstChallenge.body?.challenge as string;
    let nonce429 = 0;
    let nonceIssued = activeChallenges.size;
    const fillStarted = performance.now();
    while (activeChallenges.size < MAX_ACTIVE_INSTITUTIONAL_CHALLENGES) {
      const res = await issue('BILANX-CH-EIDAS-NODE-01');
      nonceIssued += 1;
      if (res.status === 429) {
        nonce429 = 429;
        break;
      }
      if (res.status >= 500) {
        crashes.push(`challenge ${res.status} ${JSON.stringify(res.body).slice(0, 160)}`);
        break;
      }
    }
    const overflowIssue = await issue('BILANX-CH-EIDAS-NODE-01');
    const fillMs = performance.now() - fillStarted;
    const kept = activeChallenges.get(keptId);
    add(
      'B1c',
      'load',
      overflowIssue.status === 429 && activeChallenges.size === MAX_ACTIVE_INSTITUTIONAL_CHALLENGES && kept !== undefined && kept.consumed === false
        ? 'PASS'
        : 'FAIL',
      `institutional nonce fill status=${overflowIssue.status} size=${activeChallenges.size}/${MAX_ACTIVE_INSTITUTIONAL_CHALLENGES} early nonce kept=${kept !== undefined} consumed=${kept?.consumed} wall=${Math.round(fillMs)}ms issues=${nonceIssued} mid429=${nonce429}`
    );

    if (kept) {
      kept.issuedAt = Date.now() - 70_000;
      activeChallenges.commit(keptId);
    }
    const reclaimed = await issue('BILANX-CH-EIDAS-NODE-01');
    add(
      'C9',
      'edge',
      reclaimed.status === 200 && activeChallenges.has(keptId) === false && activeChallenges.size === MAX_ACTIVE_INSTITUTIONAL_CHALLENGES
        ? 'PASS'
        : 'FAIL',
      `expired nonce reclaimed: new status=${reclaimed.status} old gone=${activeChallenges.has(keptId) === false} size=${activeChallenges.size}`
    );

    const finalHealth = await fetch(`${baseUrl}/api/health`);
    add('E3', 'integrity', finalHealth.ok && crashes.length === 0 ? 'PASS' : 'FAIL', `health after the matrix=${finalHealth.status}; unexpected 500s=${crashes.length}`);
  } catch (err) {
    crashes.push(err instanceof Error ? err.stack || err.message : String(err));
    add('Z', 'crash', 'FAIL', err instanceof Error ? err.message : String(err));
  } finally {
    if (previousAudit === undefined) delete process.env.AUDIT_LOG_PATH;
    else process.env.AUDIT_LOG_PATH = previousAudit;
    if (previousAccessLog === undefined) delete process.env.ACCESS_LOG_PATH;
    else process.env.ACCESS_LOG_PATH = previousAccessLog;
    fs.rmSync(accessLogDir, { recursive: true, force: true });
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  const counts = {
    pass: rows.filter((row) => row.status === 'PASS').length,
    fail: rows.filter((row) => row.status === 'FAIL').length,
    finding: rows.filter((row) => row.status === 'FINDING').length,
    crashes,
  };
  console.log(JSON.stringify({ counts, rows, crashes }, null, 2));
  console.log(`STRESS_DONE pass=${counts.pass} fail=${counts.fail} finding=${counts.finding} crashes=${crashes.length}`);
  if (counts.fail > 0 || crashes.length > 0) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
