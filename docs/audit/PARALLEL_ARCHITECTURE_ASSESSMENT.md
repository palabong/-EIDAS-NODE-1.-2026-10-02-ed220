# Parallel Architecture Assessment

**Tree:** this repository, working copy on 6 October 2026  
**Sources read as the claim set:** `docs/audit/GROUNDED_EVIDENCE_PACK.md`, `COMMENT_DRIFT.md`, `snapshots/`, `CRYPTO_VALIDATION_BENCHMARKS.ipynb`  
**Check:** those claims were compared with the current source, `npx tsc --noEmit`, and `npm test` from this same working copy.

This note sits beside the audit pack. On 6 October 2026 the pack, snapshots, comment-drift line numbers, and the crypto notebook were realigned to this tree after `npm test`, `npm run build`, and `npm run dev`. §2 lists what that alignment changed. The age-gate threshold gap in §4 is a row in `GROUNDED_EVIDENCE_PACK.md`.

---

## Verdict

The pack’s maturity call is the right one. The integrated system is **TRL 4**: lab components on fixtures, an in-memory server, and a software authenticator. `COMMENT_DRIFT.md` is right that TRL 5 and TRL 6 strings in the UI, PDF, and test banners are labels, not evidence.

The pack is also right about the shape of the crypto, the WebAuthn checks, the RFID catalog, and the absence of an HSM, PKCS#11, a live IdP, and a reader.

The pack, the snapshots, and the notebook were updated in the same pass so those documents match this tree. The open code gap is the age-gate threshold, and the pack now records it.

---

## 1. Claims that still match the tree

| Pack claim | Current code |
| :--- | :--- |
| Point multiply is `@noble/curves`, not WebCrypto | `pedersen.ts` uses `G.multiply` and `H.multiply`. `H` is `hashToCurve` of `Bilanx NUMS H Generator`. |
| Wire layout is 1,355 bytes | `range_b2_codec.ts` allocates that buffer: version, threshold, 33-byte `C`, eight 161-byte bit tuples, 32-byte `r_diff`. B2 harness T11/T13 still require 1,355. |
| Dual-key message is `challenge:secondFactorHash` | Client signs that string in `useBilanxDualKeyValidation.real.ts`. Server rebuilds it in `/api/v1/dual-key/verify` and consumes the nonce in a `Map` before the signature check. |
| WebAuthn checks origin, RP ID hash, and counter | `webauthnServer.ts` `KNOWN_AAGUIDS` matches the snapshot, including the all-zero simulator id. `timingSafeEqual` on the RP ID hash and `signCount <= cred.counter` are present. No MDS client exists. |
| RFID Step 0 is a constant catalog | `DEFAULT_UHD_RFID_ASSERTIONS` in `src/data.ts`. No LLRP or reader driver. |
| SAML trust is local fixtures | `fixtures.py` and `saml_engine/certs/`. Parser is expat DOCTYPE/entity handlers, then `ElementTree`. |
| Dead ends | No PKCS#11, no SPID/CIE client, no payment gateway. `Dockerfile` and `fly.toml` are present. Sessions, challenges, and WebAuthn credentials are process `Map`s. Access log is `data/access_logs.json`. |
| Demonstrator “quarantine” is a local object | `runSwissDemonstration.ts` still assigns `serverLeakageBytes: 0`. The QR object carries `age18`, LoA, digests, and ids. It does not carry the preset name or date of birth. |

`npm test` on 6 October 2026 exited 0: Python SAML 32, SAML HTTP 16, B2 14 rows (prove 204.79 ms, verify 235.18 ms), dual-key 7, WebAuthn 11, Swiss 48, adversarial 25, pilot 95 (one Swiss clearance 1084 ms). `npm run build` exited 0. `npm run dev` answered `GET /api/health` with HTTP 200.

---

## 2. Alignment applied

The pack and snapshots now match this tree on the points that had drifted:

- Inventory names `SwissUnifiedPoCDemo`. `EidasNodeLab.tsx` and `UnifiedLabDemo.tsx` are recorded as absent. `src/sandbox/README.md` still mentions `UnifiedLabDemo`; that is listed in `COMMENT_DRIFT.md` and the README itself was left unchanged.
- `snapshots/pii_path.md` matches the ACS that stores age and placeholder identity in `data/access_logs.json`. Name fields are still extracted in `mapping.py` and dropped before the session and the HTTP body.
- `snapshots/saml_parser.md` quotes the current expat gate and the current XSW checks. Canonicalization is still `ET.canonicalize` of a re-serialized element.
- Pedersen excerpt uses `C.toBytes(true)`. QR excerpt uses `v` and `env`. RFID excerpt includes the recalled UID. B2 count in the pack is 14.
- `CRYPTO_VALIDATION_BENCHMARKS.ipynb` states the sum-check as implemented, labels KPI-01 and KPI-02 as handshake timers, and records this run's B2 prove 204.79 ms and verify 235.18 ms. The notebook cells were not executed; the numbers are copied from `npm test`.

## 4. Age-gate gap, now recorded in the pack

`/api/v1/age-gate/verify` calls `verifyProof` and returns the boolean. `verifyProof` enforces version `0x01` and length 1,355. It checks the OR-challenge and the sum-check against the threshold **in the buffer**. It does not require that byte to be 18.

On this copy, with the functions the server imports:

| Call | Threshold byte | `verifyProof` |
| :--- | ---: | :--- |
| `generateProof(5, 0)` | 0 | true |
| `generateProof(18, 18)` | 18 | true |

The pilot and Swiss tests refuse a minor by reading the preset age before they build a proof. That refusal is not the HTTP verifier’s policy. A client that can call the age-gate route can submit a well-formed proof for threshold 0.

The dual-key transcript is not an input to `generateBitwiseRangeProof`. SAML `DateOfBirth` is not the committed secret. WebAuthn attests a key created in the browser or in `Ctap2HardwareKeyHarness`; the harness selects the YubiKey 5 AAGUID that `KNOWN_AAGUIDS` then names. `COMMENT_DRIFT.md` already says that path is a simulator. The pack’s boundary table agrees: no live external system is contacted.

Italian LoA High remains the string on a preset in `pilotProfiles.ts`. The pilot assertion compares that string.

---

## 5. TRL, using the pack’s own boundaries

| Subsystem | TRL | Pack boundary this rests on |
| :--- | :---: | :--- |
| Range proof as a lab primitive | 4 | In-process `@noble/curves`. Harness rejects tampered bytes. Threshold at the HTTP boundary is the prover’s. |
| Dual-key handshake | 4 | In-memory nonce map, local institutional key. |
| WebAuthn ceremony | 4 | Origin, RP ID, counter, packed cert checks on certificates presented in the ceremony. Static AAGUID table. |
| SAML engine | 4 | Fixture certificates, expat gate, openssl verify. No national proxy. |
| Jurisdiction table | 3 | `pilotProfiles.ts` only. |
| Product scan | 3 for the branch on `status`, 2 for a physical RFID claim | `src/data.ts` catalog. |
| Integrated demonstrator | 4 | One process, presets, PDF. Google sign-in is a separate front door. |

TRL 6 in the product copy remains the drift list in `COMMENT_DRIFT.md`.

---

## 6. Still open in the code

The audit now describes the threshold gap. Closing it is a code change: `/api/v1/age-gate/verify` must reject a proof whose threshold byte is not the policy threshold, and the committed age must be bound to a verified date of birth or to the dual-key challenge.

`src/sandbox/README.md` still names `UnifiedLabDemo`. The comment-drift list records that. The source comments and UI strings listed in `COMMENT_DRIFT.md` were not rewritten.

No deployed Fly machine and no hardware token were part of this check.
