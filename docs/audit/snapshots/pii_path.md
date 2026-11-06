```typescript
// Path: src/sandbox/lib/e2e/runSwissDemonstration.ts
// Lines: 282-290
// Client memory quarantine object. serverLeakageBytes is assigned 0 here; it is not a measured wire count.

  // Quarantined PII Record (Strict 0-byte server leakage)
  const quarantinedPii: QuarantinedPiiData = {
    fullName: citizen.fullName,
    dateOfBirth: citizen.dateOfBirth,
    userId: citizen.userId,
    nationality: citizen.nationality,
    status: 'QUARANTINED_CLIENT_ONLY',
    serverLeakageBytes: 0
  };
```

```typescript
// Path: src/server/app.ts
// Lines: 691-744
// SAML ACS. Python mapping.py still extracts family name, given name, and date of birth
// into pos_context. This handler does not copy those fields onto the session, the JSON
// access log, or the HTTP body. Age, LoA, role, and the over-age flags are persisted.
// The log file is data/access_logs.json (not SQLite). Firestore is attempted only when
// K_SERVICE, FIRESTORE_DATABASE_ID, or USE_FIRESTORE is set.

      const sessionUser: SessionUser = {
        uid: 'session-user',
        email: 'verified@eidas.europa.eu',
        name: 'eIDAS User',
        authMethod: 'eidas_saml',
        role: posContext.role,
        permissions: posContext.permissions,
        levelOfAssurance: posContext.level_of_assurance,
        age: posContext.age,
        isOver18: posContext.is_over_18,
        isOver21: posContext.is_over_21,
        authenticatedAt: new Date().toISOString(),
        expiresAt: Date.now() + 4 * 60 * 60 * 1000,
        issuer: claims.issuer,
      };

      const { token: sessionToken } = globalSessionStore.createSession(sessionUser);
      sessionUser.uid = sessionToken; // use session token as uid for logs
      setSessionCookie(res, sessionToken);

      await recordAccessLog({
        userId: sessionToken,
        email: 'verified@eidas.europa.eu',
        name: 'eIDAS User',
        authMethod: 'eidas_saml',
        action: 'LOGIN_SUCCESS',
        ipAddress: clientIp,
        userAgent,
        status: 'SUCCESS',
        metadata: {
          loa: sessionUser.levelOfAssurance,
          role: sessionUser.role,
          age: sessionUser.age,
          isOver18: sessionUser.isOver18,
          permissions: sessionUser.permissions,
        },
      });

      const safePosContext = {
        role: posContext.role,
        permissions: posContext.permissions,
        level_of_assurance: posContext.level_of_assurance,
        age: posContext.age,
        is_over_18: posContext.is_over_18,
        is_over_21: posContext.is_over_21,
      };
```

```typescript
// Path: src/sandbox/lib/e2e/runSwissDemonstration.ts
// Lines: 677-692
// QR payload. No preset name or date of birth. Fields are v and env (not envId).

  const qrPayloadObj = {
    v: '1.0',
    env: envelopeId,
    jur: jurisdictionKey,
    t: now.toISOString(),
    status: 'APPROVED',
    claims: { age18: true, loa: citizen.levelOfAssurance },
    receipt: {
      chId: challengeId,
      hwFp: hwFingerprint,
      zkp: zkpProofDigest,
      bytes: zkpProofBytes.length,
      auditHash: auditReceiptHash
    }
  };
  const qrPayload = JSON.stringify(qrPayloadObj);
```
