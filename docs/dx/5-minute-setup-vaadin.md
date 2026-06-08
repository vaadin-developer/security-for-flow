# 5-Minute Setup — Vaadin

Goal: a Vaadin Flow application that uses `security-for-flow` V00.72 with
the new fluent bootstrap, `@SecurityAutoService` and the Vaadin starter.

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
import com.svenruppert.vaadin.security.autoservice.api.SecurityAutoService;

@SecurityAutoService(AuthenticationService.class)
public final class MyAuthenticationService
    implements AuthenticationService<Credentials, MyUser> { /* ... */ }

@SecurityAutoService(AuthorizationService.class)
public final class MyAuthorizationService
    implements AuthorizationService<MyUser> { /* ... */ }
```

## 3. Bootstrap the app

```java
import com.svenruppert.vaadin.security.dx.vaadin.bootstrap.VaadinSecurity;
import com.svenruppert.vaadin.security.starter.profile.VaadinSecurityStarter;

public final class SecurityInit {
  public static void install() {
    var runtime = VaadinSecurity.bootstrap()
        .use(VaadinSecurityStarter.developmentDefaults())
        .subjectType(MyUser.class)
        .install();
    System.out.println(runtime.log());
  }
}
```

## 4. Guard a route

```java
@SecureRoute(roles = "ADMIN")
@Route("admin")
public final class AdminView extends VerticalLayout { /* ... */ }
```

## 5. Done

`runtime.log()` prints every registered service and any diagnostic
warning. Switch to `VaadinSecurityStarter.productionDefaults()` (or
`.strictDefaults()`) when going to production.
