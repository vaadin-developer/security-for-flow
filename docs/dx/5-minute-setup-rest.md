# 5-Minute Setup — REST

V00.73 fluent bootstrap for the REST adapter. The V00.72 carve-out is
gone: `.audit(...)`, `.policies(...)`, `.roles(...)` and
`.credentials(...)` are real. `.sessions(...)` on REST consumes
`SessionPolicy` / `JSentinelVersionStore` / `SubjectIdResolver` only;
`.storeBacked(...)` records the INFO code `rest/session-store-unused`.

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-rest</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-dx-rest</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-autoservice-annotations</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
```

```xml
<annotationProcessorPaths>
  <path>
    <groupId>com.svenruppert</groupId>
    <artifactId>security-autoservice-processor</artifactId>
    <version>${security-for-flow.version}</version>
  </path>
  <path>
    <groupId>com.svenruppert</groupId>
    <artifactId>security-autoservice-annotations</artifactId>
    <version>${security-for-flow.version}</version>
  </path>
</annotationProcessorPaths>
```

```java
@JSentinelAutoService(AuthenticationService.class)
public final class TokenAuth implements AuthenticationService<Token, User> { /* ... */ }

@JSentinelAutoService(AuthorizationService.class)
public final class Authz implements AuthorizationService<User> { /* ... */ }

@JSentinelAutoService(RestSubjectResolver.class)
public final class HeaderResolver implements RestSubjectResolver { /* ... */ }
```

```java
import com.svenruppert.jsentinel.dx.rest.bootstrap.RestSecurity;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;

var runtime = RestSecurity.bootstrap()
    .mode(JSentinelBootstrapMode.PRODUCTION)
    .audit(a -> a.logging().ringBuffer(256))
    .policies(p -> p.register(myDocumentPolicy()))
    .install();
System.out.println(runtime.log());
```

Handlers stay as before — the resolver and decision mapper auto-defaults
to `HttpStatusDecisionMapper` and a generic-strings error body strategy.

## Optional sub-builders

| Sub-builder | REST behaviour |
|---|---|
| `.audit(...)` | Full — composes `LoggingAuditSink`, `RingBufferAuditSink`, `StoreBackedJSentinelAuditService` as in Vaadin |
| `.policies(...)` | Full — registers policies and resource resolvers into `PolicyRegistry` |
| `.roles(...)` | `.hierarchy(...)` only (V00.73 deliberately keeps `RolePermissionMapping` out) |
| `.credentials(...)` | Full — `.passwordHasher(...)` (legacy resolver), `.hashing(...)` / `.pepper(...)` / `.credentialStore(...)` (V00.71 pipeline). `.modern()` requires `security-crypto-bc` |
| `.sessions(...)` | `SessionPolicy` / `JSentinelVersionStore` / `SubjectIdResolver` only. `.storeBacked(...)` records `rest/session-store-unused` INFO — REST has no concept of a session store |

## STRICT mode

`mode(STRICT)` breaks on the three V00.72-to-V00.73 promotions
(`secure-route/unknown-policy`,
`session-management-view-without-session-store`,
`security-version-without-subject-id-resolver`) plus every new V00.73
sub-builder validation code (`audit/missing-service`,
`sessions/missing-store`, `credentials/modern-without-bc`, …).
