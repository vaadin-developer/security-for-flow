# 5-Minute Setup — REST

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
@SecurityAutoService(AuthenticationService.class)
public final class TokenAuth implements AuthenticationService<Token, User> { /* ... */ }

@SecurityAutoService(AuthorizationService.class)
public final class Authz implements AuthorizationService<User> { /* ... */ }

@SecurityAutoService(RestSubjectResolver.class)
public final class HeaderResolver implements RestSubjectResolver { /* ... */ }
```

```java
import com.svenruppert.vaadin.security.dx.rest.bootstrap.RestSecurity;

var runtime = RestSecurity.bootstrap()
    .mode(SecurityBootstrapMode.PRODUCTION)
    .install();
System.out.println(runtime.log());
```

Handlers stay as before — the resolver and decision mapper auto-defaults
to `HttpStatusDecisionMapper` and a generic-strings error body strategy.
