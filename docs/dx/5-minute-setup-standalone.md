# 5-Minute Setup — Standalone (CLI / desktop / batch)

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

var runtime = StandaloneSecurity.bootstrap()
    .mode(SecurityBootstrapMode.DEVELOPMENT)
    .install();
System.out.println(runtime.log());
```

The default `SubjectStore` is `ThreadLocalSubjectStore` — set a custom one
with `.subjectStore(...)` if you have background workers.

Method-level security on a concrete class without an interface still uses
the compile-time `<Type>Secured` wrapper (`@Secured` + `security-processor`).
The `SecurityDiagnostics.inspect()` report surfaces every generated
wrapper visible through `META-INF/security-for-flow/generated-wrappers.idx`.
