# 5-Minute Setup — Standalone (CLI / desktop / batch)

V00.73 fluent bootstrap for the Standalone adapter.
`.audit(...)`, `.policies(...)`, `.roles(...)` and `.credentials(...)`
are real. `.sessions(...)` is recorded but the install path emits the
INFO code `standalone/sessions-not-applicable` — Standalone has no
session concept (`StandaloneLoginFlow` binds straight into the
thread-local `SubjectStore`).

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-standalone</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-dx-standalone</artifactId>
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
@SecurityAutoService(AuthenticationService.class)
public final class DemoAuthenticationService
    implements AuthenticationService<Credentials, User> { /* ... */ }

@SecurityAutoService(AuthorizationService.class)
public final class DemoAuthorizationService
    implements AuthorizationService<User> { /* ... */ }
```

```java
import com.svenruppert.vaadin.security.dx.standalone.bootstrap.StandaloneSecurity;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;

var runtime = StandaloneSecurity.bootstrap()
    .mode(SecurityBootstrapMode.DEVELOPMENT)
    .audit(a -> a.logging().ringBuffer(128))
    .install();
System.out.println(runtime.log());
```

The default `SubjectStore` is `ThreadLocalSubjectStore` — set a custom
one with `.subjectStore(...)` if you have background workers.

## Method-level security and the wrapper index

Method-level security on a concrete class without an interface uses the
compile-time `<Type>Secured` wrapper (`@Secured` + `security-processor`).
V00.73 completes the wrapper-index pipeline: `security-processor` now
writes `META-INF/security-for-flow/generated-wrappers.idx` after each
compile (the V00.72 reader path was already in place). One line per
generated wrapper, format
`sourceFqn:generatedFqn:processor:proxyBuilderVer:method1,method2,...`.

`SecurityDiagnostics.inspect()` reports every generated wrapper visible
through that file. Running `./mvnw -pl :demo-standalone -am compile`
produces an entry for `MemberDirectorySecured`.

## STRICT mode

`mode(STRICT)` breaks on the three V00.72-to-V00.73 promotions and the
new V00.73 sub-builder validation codes (`audit/missing-service`,
`credentials/modern-without-bc`, …). `.sessions(...)` on Standalone
records INFO only and never blocks the bootstrap.
