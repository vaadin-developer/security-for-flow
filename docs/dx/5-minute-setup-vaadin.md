# 5-Minute Setup — Vaadin

Goal: a Vaadin Flow application that uses `jSentinel` V00.73 with
the fluent bootstrap, `@JSentinelAutoService` and the Vaadin starter.
V00.73 closes the two V00.72 carve-outs — the `.audit(...)` /
`.sessions(...)` / `.policies(...)` / `.roles(...)` / `.credentials(...)`
sub-builders are real, and `SecuredUi.requiresPolicy(...)` /
`@SecureRoute(policy = ...)` evaluate registered policies through
`PolicyRegistry`.

## 1. Add dependencies

```xml
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-vaadin</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-vaadin-starter</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert.jsentinel</groupId>
  <artifactId>jSentinel-autoservice-annotations</artifactId>
  <version>${jsentinel.version}</version>
</dependency>
```

```xml
<plugin>
  <artifactId>maven-compiler-plugin</artifactId>
  <configuration>
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
  </configuration>
</plugin>
```

## 2. Annotate your SPI implementations

```java
import com.svenruppert.jsentinel.autoservice.api.JSentinelAutoService;

@JSentinelAutoService(AuthenticationService.class)
public final class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser> { /* ... */ }

@JSentinelAutoService(AuthorizationService.class)
public final class MyAuthorizationService
    implements AuthorizationService<MyUser> { /* ... */ }
```

## 3. Bootstrap the app

```java
import com.svenruppert.jsentinel.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.jsentinel.policy.api.Policy;
import com.svenruppert.jsentinel.policy.api.SubjectPredicates;
import com.svenruppert.jsentinel.starter.profile.VaadinJSentinelStarter;

public final class JSentinelInit {
  public static void install() {
    var runtime = VaadinSecurity.bootstrap()
        .use(VaadinJSentinelStarter.developmentDefaults())
        .subjectType(MyUser.class)
        .policies(p -> p
            .register(Policy.named("documents.editor-or-admin")
                .allowIf(SubjectPredicates.hasAnyRole("ROLE_ADMIN", "ROLE_EDITOR"))
                .deny("must be ADMIN or EDITOR")
                .build()))
        .install();
    System.out.println(runtime.log());
  }
}
```

The full V00.73 sub-builder set is `.audit(...)`, `.sessions(...)`,
`.policies(...)`, `.roles(...)`, `.credentials(...)`. Each method's
JavaDoc lists the validation codes (e.g. `audit/missing-service`,
`sessions/missing-store`, `credentials/modern-without-bc`).

## 4. Guard a route

```java
@SecureRoute(roles = "ADMIN")
@Route("admin")
public final class AdminView extends VerticalLayout { /* ... */ }

@SecureRoute(policy = "documents.editor-or-admin")
@Route("editor")
public final class EditorView extends VerticalLayout { /* ... */ }
```

V00.73 evaluates the named policy through `PolicyRegistry`. An unknown
policy returns `Forbidden` at runtime; in `STRICT` mode with
`.discoverSecureRoutes(true)` the mismatch becomes a deterministic boot
failure (`secure-route/unknown-policy`).

## 5. Done

`runtime.log()` prints every registered service and any diagnostic
warning. Switch to `VaadinJSentinelStarter.productionDefaults()` (or
`.strictDefaults()`) when going to production. STRICT now breaks on the
three V00.72-to-V00.73 promoted codes
(`secure-route/unknown-policy`,
`session-management-view-without-session-store`,
`security-version-without-subject-id-resolver`) — clean those up before
flipping the mode.

## 6. Programmatic health (V00.74.10)

For `/health` endpoints, monitoring dashboards or boot banners use the
V00.74.10 tooling methods on the same `runtime` instance — they expose a
structured view of the snapshot without parsing `log()`:

```java
runtime.summary();
// "OK | 8 services | 0 errors | 1 warnings | 2 INFO"

runtime.healthCheck();
// HealthStatus(overall=DEGRADED, findings=[...],
//              registeredServices=8, inspectedAt=...)

runtime.toJson();
// {"mode":"PRODUCTION","serviceCount":8,"services":[...],
//  "warningCount":3,"warnings":[...]}
```

`healthCheck()` classifies any `ERROR` finding as `FAILED`, any
`WARNING` (without errors) as `DEGRADED`, and `INFO`-only or empty as
`HEALTHY` — `INFO` findings intentionally do not degrade. The
`toJson()` encoder is jSentinel's own — Maven Enforcer on
`jSentinel-dx` blocks Jackson, Gson and `org.json` on compile/runtime
scope so consumer projects do not inherit a JSON library through the
DX classpath. All four methods are marked
`@ExperimentalJSentinelApi` until V00.76 confirms the shape.

## 7. Persistence pair (V00.74.20)

When you also want Eclipse-Store persistence (audit log + sessions +
your own domain data), open a `JSentinelStoragePair` at process start
and feed its framework half into the bootstrap. The pair manages both
storages — framework + app — under one parent directory with a single
two-phase shutdown:

```java
try (JSentinelStoragePair pair = JSentinelStorageFactory.openAt(Path.of("data"))) {
  VaadinSecurity.bootstrap()
      .audit(a    -> a.storeBacked(pair.framework().auditEventStore()))
      .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
      .install();
  // pair.app() is your application's own EmbeddedStorageManager —
  // use pair.app().root() / setRoot(…) / store(…) for domain data.
}
```

The pair's `close()` shuts the app storage down first, the framework
storage second, and the framework close-attempt always runs (so a
buggy app shutdown cannot leave the framework's lock file held).