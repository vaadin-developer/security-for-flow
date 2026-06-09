# 5-Minute Setup — Vaadin

Goal: a Vaadin Flow application that uses `security-for-flow` V00.73 with
the fluent bootstrap, `@JSentinelAutoService` and the Vaadin starter.
V00.73 closes the two V00.72 carve-outs — the `.audit(...)` /
`.sessions(...)` / `.policies(...)` / `.roles(...)` / `.credentials(...)`
sub-builders are real, and `SecuredUi.requiresPolicy(...)` /
`@SecureRoute(policy = ...)` evaluate registered policies through
`PolicyRegistry`.

## 1. Add dependencies

```xml
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-vaadin-starter</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
<dependency>
  <groupId>com.svenruppert</groupId>
  <artifactId>security-autoservice-annotations</artifactId>
  <version>${security-for-flow.version}</version>
</dependency>
```

```xml
<plugin>
  <artifactId>maven-compiler-plugin</artifactId>
  <configuration>
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