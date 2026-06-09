# Before / After — manual `META-INF/services` vs `@JSentinelAutoService`

A concrete diff from `demo-standalone` introduced in V00.72/014.
The `@JSentinelAutoService` annotation, the processor and the
`META-INF/services/...` emission are unchanged in V00.73.

## Before

```text
demo-standalone/src/main/resources/META-INF/services/
  ├── com.svenruppert.jsentinel.authentication.AuthenticationService
  └── com.svenruppert.jsentinel.authorization.api.AuthorizationService
```

```text
# com.svenruppert.jsentinel.authentication.AuthenticationService
com.svenruppert.jsentinel.demo.standalone.DemoAuthenticationService
```

```text
# com.svenruppert.jsentinel.authorization.api.AuthorizationService
com.svenruppert.jsentinel.demo.standalone.DemoAuthorizationService
```

## After

The two files above are deleted. The two classes carry an annotation:

```java
@JSentinelAutoService(AuthenticationService.class)
public final class DemoAuthenticationService
    implements AuthenticationService<Credentials, User> { /* ... */ }

@JSentinelAutoService(AuthorizationService.class)
public final class DemoAuthorizationService
    implements AuthorizationService<User> { /* ... */ }
```

`demo-standalone/pom.xml` declares the annotations module on the compile
classpath and the processor on the `annotationProcessorPath`. At compile
time, `target/classes/META-INF/services/...AuthenticationService` and
`...AuthorizationService` reappear — identical content, but generated.

## Why this matters

- Rename refactor:  before — rename the class *and* edit the file by hand;
  after — IDE rename handles both because the annotation references the
  SPI by `Class<?>` literal.
- Forgotten file:   before — `ServiceLoader.load(...)` silently returns
  empty; after — compile fails (`autoservice/not-assignable`) or the
  diagnostics layer flags the missing entry.
- New developer:    before — find five `META-INF/services` files and the
  exact FQNs; after — annotate the class, let the build emit it.
