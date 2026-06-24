# 5-Minute Setup — REST

V00.73 fluent bootstrap for the REST adapter. The V00.72 carve-out is
gone: `.audit(...)`, `.policies(...)`, `.roles(...)` and
`.credentials(...)` are real. `.sessions(...)` on REST consumes
`SessionPolicy` / `JSentinelVersionStore` / `SubjectIdResolver` only;
`.storeBacked(...)` records the INFO code `rest/session-store-unused`.

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-rest</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-dx-rest</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-autoservice-annotations</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
```

```xml
<annotationProcessorPaths>
  <path>
    <groupId>com.svenruppert.jsentinel</groupId>
    <artifactId>jSentinel-autoservice-processor</artifactId>
    <version>${jsentinel.version}</version>
  </path>
  <path>
    <groupId>com.svenruppert.jsentinel</groupId>
    <artifactId>jSentinel-autoservice-annotations</artifactId>
    <version>${jsentinel.version}</version>
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
| `.credentials(...)` | Full — `.passwordHasher(...)` (legacy resolver), `.hashing(...)` / `.pepper(...)` / `.credentialStore(...)` (V00.71 pipeline). `.modern()` requires `jSentinel-crypto-bc` |
| `.sessions(...)` | `SessionPolicy` / `JSentinelVersionStore` / `SubjectIdResolver` only. `.storeBacked(...)` records `rest/session-store-unused` INFO — REST has no concept of a session store |

## STRICT mode

`mode(STRICT)` breaks on the three V00.72-to-V00.73 promotions
(`secure-route/unknown-policy`,
`session-management-view-without-session-store`,
`security-version-without-subject-id-resolver`) plus every new V00.73
sub-builder validation code (`audit/missing-service`,
`sessions/missing-store`, `credentials/modern-without-bc`, …).

## Programmatic health (V00.74.10)

For a minimal `/health` REST handler, use the V00.74.10 tooling methods
on the `runtime` returned by `install()` — no JSON library on the
classpath required, the encoder is internal:

```java
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.dependencies.core.net.MediaType;

public final class HealthHandler implements RestHandler {
  private final JSentinelRuntime runtime;
  public HealthHandler(JSentinelRuntime runtime) {
    this.runtime = runtime;
  }
  @Override public void handle(RestRequest req, RestResponse resp) {
    var health = runtime.healthCheck();
    resp.setStatusCode(health.hasErrors()
        ? HttpStatus.SERVICE_UNAVAILABLE
        : HttpStatus.OK);
    resp.setContentType(MediaType.APPLICATION_JSON);
    resp.write(runtime.toJson());
  }
}
```

`runtime.summary()` is the single-line companion for boot banners;
`runtime.toMap()` returns the same data as `toJson()` but as an
unmodifiable, insertion-ordered `Map<String, Object>` so you can route
through any serialiser already on your classpath. All four methods
are marked `@ExperimentalJSentinelApi` until V00.76.

## Persistence pair (V00.74.20)

When the REST service should persist audit / sessions / application
domain data, open a `JSentinelStoragePair` at startup and feed its
framework half into the bootstrap:

```java
JSentinelStoragePair pair = JSentinelStorageFactory.openAt(Path.of("data"));
Runtime.getRuntime().addShutdownHook(new Thread(pair::close, "jsentinel-pair-close"));

RestSecurity.bootstrap()
    .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
    .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
    .install();

// pair.app() holds the application's own EmbeddedStorageManager —
// use pair.app().root() / setRoot(…) / store(…) for domain data.
```

The pair's two-phase `close()` shuts app first, framework second; the
framework close-attempt always runs so its lock file is released
even if app shutdown throws.
