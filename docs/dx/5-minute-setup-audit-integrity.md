# 5-Minute Setup — jCustos Audit Integrity (V00.80)

Give your audit trail tamper evidence in five minutes. Konzept goal 7: the
Security Event Bus signature protects an event in TRANSPORT; the audit hash
chain below is the tamper-resistant HISTORICAL record. It complements the
V00.70 persistent audit — it does not replace it.

## 1. Dependencies

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-audit-integrity</artifactId>
  <version>00.80.00</version>
</dependency>
<!-- production store (restart-safe): -->
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-audit-integrity-persistence-eclipsestore</artifactId>
  <version>00.80.00</version>
</dependency>
```

## 2. Open the chain and wire the two feeds

```java
// Restart-safe store (owner-only-hardened storage tree, JS-SEC-037).
var storage = EclipseStoreAuditChainStorage.openAt(Path.of("/var/lib/jsentinel/audit-chain"));
var appender = new AuditChainAppender(storage.chainStore());

// Feed 1 — bus events: NOTICE-or-worse plus all authentication /
// authorization / admin / integrity events (override via AuditRelevancePolicy).
new AuditIntegrityListener(appender).subscribeTo(bus);

// Feed 2 — core audit events: register NEXT TO your existing sinks, the
// V00.70 audit path keeps working and gains chaining on top.
var audit = new DefaultCompositeAuditService(
    new RingBufferAuditSink(),
    new HashChainingAuditSink(appender));
```

Every chained entry links to its predecessor through a length-prefixed
SHA-256 base (`jsentinel-audit-chain/v1`): mutating any stored entry breaks
its own hash, replacing one breaks its successor's link. Both feeds are
strictly isolated — a full chain store never breaks event dispatch or the
audit fan-out (it is logged as `audit-integrity/append-failed`).

## 3. Verify — the forensic check

```java
AuditChainVerificationResult result =
    new AuditIntegrityVerifier().verify(storage.chainStore());
switch (result) {
  case Valid v -> log.info("chain intact: {} entries, head {}", v.entryCount(), v.headHash());
  case Empty e -> log.info("virgin chain");
  case Broken b -> alert("TAMPER at index " + b.atIndex() + ": " + b.reason() + " — " + b.detail());
}
```

The verifier recomputes every entry with the digest recorded IN that entry
(algorithm agility) and fails closed on unavailable digests. The chain
survives restarts: entries written before and after a close/reopen verify
as one chain.

## 4. Export — signed, independently verifiable

```java
var signer = new AuditBatchSigner(signingKeys);       // the events key SPI —
                                                      // one signing home, no second stack
var export = new AuditExportService(storage.chainStore(), signer)
    .exportRange(0, 999);
String ndjson = new AuditExportNdjsonCodec().encode(export);   // application/x-ndjson
```

The auditor on the other side needs nothing but the NDJSON text and public
key material:

```java
var decoded = new AuditExportNdjsonCodec().decode(ndjson);
AuditBatchVerificationResult verdict = new AuditBatchVerifier(
    verificationKeyResolver, SignatureAlgorithms.defaults())
    .verify(decoded.batch(), decoded.entries());
// Valid | ChainBroken(atIndex…) | RangeMismatch | UnknownKey | KeyRevoked | SignatureInvalid
```

The batch signature covers the range endpoints plus the head hash — because
the entries are hash-chained, that binds every entry in the range. Keys
rotated out (`ACCEPTED_FOR_VERIFICATION`/`EXPIRED`) still verify — history
stays checkable after rotation; revoked keys do not.

## Notes

- Dev/test store: `new InMemoryAuditChainStore()` (throws when full —
  evicting would sever the genesis anchor).
- Store implementations run the shared `AuditChainStoreContract` from
  `jCustos-audit-integrity-testkit`.
- One chain per store in V1; per-tenant chains are a candidate for a later
  release.
