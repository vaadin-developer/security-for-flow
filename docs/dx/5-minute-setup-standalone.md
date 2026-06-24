# 5-Minute Setup — Standalone (CLI / desktop / batch)

V00.73 fluent bootstrap for the Standalone adapter.
`.audit(...)`, `.policies(...)`, `.roles(...)` and `.credentials(...)`
are real. `.sessions(...)` is recorded but the install path emits the
INFO code `standalone/sessions-not-applicable` — Standalone has no
session concept (`StandaloneLoginFlow` binds straight into the
thread-local `SubjectStore`).

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-standalone</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-dx-standalone</artifactId>
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
public final class DemoAuthenticationService
    implements AuthenticationService<Credentials, User> { /* ... */ }

@JSentinelAutoService(AuthorizationService.class)
public final class DemoAuthorizationService
    implements AuthorizationService<User> { /* ... */ }
```

```java
import com.svenruppert.jsentinel.dx.standalone.bootstrap.StandaloneSecurity;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;

var runtime = StandaloneSecurity.bootstrap()
    .mode(JSentinelBootstrapMode.DEVELOPMENT)
    .audit(a -> a.logging().ringBuffer(128))
    .install();
System.out.println(runtime.log());
```

The default `SubjectStore` is `ThreadLocalSubjectStore` — set a custom
one with `.subjectStore(...)` if you have background workers.

## Method-level security and the wrapper index

Method-level security on a concrete class without an interface uses the
compile-time `<Type>Secured` wrapper (`@Secured` + `jSentinel-processor`).
V00.73 completes the wrapper-index pipeline: `jSentinel-processor` now
writes `META-INF/jsentinel/generated-wrappers.idx` after each
compile (the V00.72 reader path was already in place). One line per
generated wrapper, format
`sourceFqn:generatedFqn:processor:proxyBuilderVer:method1,method2,...`.

`JSentinelDiagnostics.inspect()` reports every generated wrapper visible
through that file. Running `./mvnw -pl :demo-standalone -am compile`
produces an entry for `MemberDirectorySecured`.

## STRICT mode

`mode(STRICT)` breaks on the three V00.72-to-V00.73 promotions and the
new V00.73 sub-builder validation codes (`audit/missing-service`,
`credentials/modern-without-bc`, …). `.sessions(...)` on Standalone
records INFO only and never blocks the bootstrap.

## Programmatic health (V00.74.10)

For CLI boot banners and machine-readable status, use the V00.74.10
tooling methods on the `runtime` returned by `install()`:

```java
System.out.println(runtime.summary());
// → "OK | 8 services | 0 errors | 0 warnings | 2 INFO"

var health = runtime.healthCheck();
if (health.hasErrors()) {
  System.err.println("Refusing to start: " + runtime.toJson());
  System.exit(1);
}
```

`healthCheck()` classifies any `ERROR` finding as `FAILED`, any
`WARNING` (without errors) as `DEGRADED`, and `INFO`-only or empty as
`HEALTHY` — `INFO` findings intentionally do not degrade. The
`toJson()` encoder is internal — no Jackson, Gson or `org.json`
dependency lands on the standalone classpath. All four methods are
marked `@ExperimentalJSentinelApi` until V00.76.

## Persistence pair (V00.74.20)

When the CLI / desktop app needs Eclipse-Store persistence (audit log
+ sessions + application data), open a `JSentinelStoragePair` once
and feed its framework half into the bootstrap:

```java
JSentinelStoragePair pair = JSentinelStorageFactory.openAt(Path.of("data"));
Runtime.getRuntime().addShutdownHook(new Thread(pair::close, "jsentinel-pair-close"));

StandaloneSecurity.bootstrap()
    .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
    .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
    .install();

// pair.app() is your domain-data EmbeddedStorageManager — use it via
// pair.app().root() / setRoot(…) / store(…).
```

The pair's two-phase `close()` shuts the app storage down first and
the framework storage second; the framework close-attempt always
runs so its lock file is released even if app shutdown throws.
