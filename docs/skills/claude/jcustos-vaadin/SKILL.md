---
name: jcustos-vaadin
description: Battle-tested integration of jCustos (V00.73+) into a Vaadin Flow application. Wires the full security stack — V00.73 fluent `VaadinSecurity.bootstrap()` + `@JCustosAutoService`-registered `AuthenticationService` / `AuthorizationService` + pre-seeded in-memory admin + regular user + `LoginView` extending `eu.jsentinel.jcustos.authorization.LoginView` + `LoginListener` + AppLayout `MainLayout` shell hosting both **public** and **private** routes: a `PublicHomeView` at `/` reachable without login + a `DashboardView` at `/dashboard` (`@VisibleFor(USER)`) after login + the admin views as further children via `@Route(layout = MainLayout.class)`. Drawer uses a plain `RouterLink` for public entries and `SecuredUi.link().hideWhenDenied()` for private ones — anonymous visitors see only "Home", logged-in users see Dashboard + permission-granted admin areas. Navbar carries a dynamic Sign in / Sign out button rebuilt via `BeforeEnterObserver`. Admin views: audit (`SecurityAuditService.query` over a ring-buffer / store-backed sink, filterable by type / subject / from-to DateTimePicker) + sessions (`SessionManagementView` over an `InMemorySessionStore`) + role management (`@RequiresPermission("admin:roles")`). Includes `HomeButton` helper that conditionally renders a back-to-`/` button only when a view is standalone (`@Route(layout = UI.class)`). Use PROACTIVELY when the project shows Vaadin Flow signals (`vaadin-core`, `@Route`, `VerticalLayout`, `AppLayout`, `Composite`) AND the user mentions jCustos, integrate jCustos, jCustos einbauen, secure my Vaadin app, Vaadin Security, security-for-flow, add login + roles, wire authentication, `VaadinSecurity.bootstrap`, `@SecureRoute`, `SecuredUi`, `JCustosServiceResolver`, `JCustosSubject`, audit view, session inventory, admin roles UI. Also applies when the user asks to "bootstrap jCustos in a fresh Vaadin app", "seed admin + regular user", "add Audit + Session admin views", "give me a complete jCustos integration", or wants the full V00.73 fluent surface (`audit / sessions / policies / roles / credentials` sub-builders) rather than the legacy hand-written `META-INF/services` recipe. Provides the 5-step recipe (POM patch → typed slot extraction → source generation → bootstrap-init listener registration → verify with `mvn compile` + dev-run), 17 ready-to-render `.java.tmpl` templates with placeholder substitution, the discipline of "Authn + Authz via `@JCustosAutoService`, LoginListener + AccessEvaluator + VaadinServiceInitListener via `META-INF/services`", and the pitfall catalog (annotation processor path order, `optimizeBundle=false`, subject type leakage, audit sink failure swallowing). Does NOT cover token-based first-admin bootstrap (`BootstrapWiring` / `SetupView`), credential persistence (use `jCustos-persistence-eclipsestore`), or REST/Standalone integration (separate skills).
---

# jCustos ↦ Vaadin Flow — full integration

This skill drops the complete jCustos security stack into a Vaadin
Flow application. The end state is a working app with:

- a `LoginView` (extending the framework's pre-built form)
- a pre-seeded in-memory user directory with **one admin** and **one
  regular user** (`admin / admin`, `user / user`)
- role + permission catalog (`ADMIN`, `USER` × `audit:read`,
  `admin:sessions`, `admin:roles`, `app:view`)
- a fluent `VaadinSecurity.bootstrap()` chain run once at Vaadin
  service init (V00.73 surface — `audit / credentials / policies`
  sub-builders)
- an AppLayout `MainLayout` shell (drawer, navbar, logout via
  `VaadinLogoutService`) hosting both a **public** `PublicHomeView`
  at `/` (no auth required) and a **private** `DashboardView` at
  `/dashboard` (`@VisibleFor(USER)`), plus the admin views as further
  children via `@Route(value = "...", layout = MainLayout.class)`.
  The drawer hides private entries for anonymous visitors via
  `SecuredUi.link().hideWhenDenied()`; the navbar swaps a Sign in /
  Sign out button on every navigation.
- an `/audit` view restricted by `@RequiresPermission("audit:read")`
  that queries `JCustosServiceResolver.securityAuditService()` and
  renders the ring buffer as a grid
- an `/admin/sessions` view extending the framework's
  `SessionManagementView` over an `InMemorySessionStore`
- an `/admin/roles` view for assigning / revoking roles (admin-only)

Validated against the `demo-vaadin` reference module in this repo. The
skill emits the same shape, parameterised on the target app's package
+ subject type names.

## How to use this skill

1. **Read the user's brief.** Most briefs name two things: "add
   jCustos" + the app's package. Extract the slots in
   "Reading the brief" below. If more than one slot is missing, ask
   **one focused message** with all missing slots — never one
   question at a time.
2. **Echo the slots back in one block**, then proceed. Single allowed
   checkpoint.
3. **Render every template** in `references/` with the slot values
   substituted (see "Rendering templates" below).
4. **Apply the POM patch** — merge the deps + annotationProcessorPaths
   stanzas into the Vaadin module's `pom.xml` (do NOT overwrite the
   whole file).
5. **Register the SPI files** under `src/main/resources/META-INF/services/`.
6. **Verify** with `./mvnw -pl <module> -am compile` and (if Jetty is
   wired) `./mvnw -pl <module> jetty:run`. Open `http://localhost:8080/login`.

Default to fully-automatic execution. The single checkpoint is the
slot echo in step 2.

---

## The integration at a glance

```
src/main/java/<base>/
├── Application.java                      ← @Push, @Theme, AppShellConfigurator
├── security/
│   ├── model/
│   │   ├── <Subject>.java                ← record (id, name, Set<AuthorizationRole>)
│   │   ├── Credentials.java              ← record (username, password)
│   │   ├── UserDirectory.java            ← interface
│   │   ├── InMemoryUserDirectory.java    ← pre-seeded admin + user
│   │   └── UserDirectoryProvider.java    ← static holder
│   ├── roles/
│   │   ├── AuthorizationRole.java        ← enum ADMIN, USER
│   │   ├── VisibleFor.java               ← @JCustosAnnotation(RoleAccessEvaluator.class)
│   │   └── RoleAccessEvaluator.java      ← AccessEvaluator<VisibleFor>
│   ├── permissions/
│   │   └── AppPermission.java            ← enum AUDIT_READ, ADMIN_SESSIONS, ADMIN_ROLES, APP_VIEW
│   ├── services/
│   │   ├── My<...>AuthenticationService.java ← @JCustosAutoService
│   │   ├── My<...>AuthorizationService.java  ← @JCustosAutoService
│   │   └── SessionStoreProvider.java
│   └── bootstrap/
│       └── JCustosBootstrapInitListener.java ← VaadinServiceInitListener
└── views/
    ├── MainLayout.java                   ← AppLayout shell — no @Route. Drawer + dynamic Sign in/out
    ├── PublicHomeView.java               ← @Route("",            layout=MainLayout.class) — no auth, public landing
    ├── DashboardView.java                ← @Route("dashboard",   layout=MainLayout.class) + @VisibleFor(USER)
    ├── MyLoginView.java                  ← @Route("login")        (standalone — login page bypasses layout)
    ├── HomeButton.java                   ← Optional<Button> helper — only when @Route(layout=UI.class)
    └── admin/                            ← admin-only views, all embedded in MainLayout
        ├── AuditView.java                ← @Route("audit",         layout=MainLayout.class) + @RequiresPermission("audit:read")
        ├── SessionsView.java             ← @Route("admin/sessions",layout=MainLayout.class) + @RequiresPermission("admin:sessions")
        └── AdminRolesView.java           ← @Route("admin/roles",   layout=MainLayout.class) + @RequiresPermission("admin:roles")

src/main/resources/META-INF/services/
├── eu.jsentinel.jcustos.authorization.LoginListener
├── eu.jsentinel.jcustos.authorization.api.AccessEvaluator
└── com.vaadin.flow.server.VaadinServiceInitListener
```

**Distribution of registration mechanisms** — match the demo exactly:

| Where | Mechanism | Reason |
|---|---|---|
| `AuthenticationService`, `AuthorizationService` | `@JCustosAutoService` | Generated `META-INF/services` entry — no manual file maintenance |
| `AccessEvaluator` | hand-written `META-INF/services` line | Loaded by `JCustosAnnotationScanner`, but `@JCustosAutoService` only ships for `AuthenticationService` / `AuthorizationService` in V00.73 |
| `LoginListener` | hand-written `META-INF/services` line | Same |
| `VaadinServiceInitListener` (the bootstrap init) | hand-written `META-INF/services` line | Vaadin's own SPI mechanism, outside the `@JCustosAutoService` scope |

Don't try to convert the second group to `@JCustosAutoService` — the
annotation only carries one SPI mapping per use, and the supported
target classes are limited in V00.73. Stay with the hybrid.

### Home-button discipline

Every skill-generated view (`AuditView`, `SessionsView`,
`AdminRolesView`, and any future view) calls
`HomeButton.forStandalone(getClass()).ifPresent(...)` once during
construction and drops the result into the toolbar (or the root
layout for views without a toolbar — see `SessionsView`).

The helper inspects the view's own `@Route(layout = ...)` annotation:

- `layout()` defaults to `UI.class` → standalone route → render a Home
  button pointing at `PublicHomeView` (the universally reachable
  root).
- `layout()` set to anything else (e.g. `MainLayout.class`) →
  embedded in a router layout (the layout's drawer / navbar handles
  navigation) → return empty, no button.

Skill default: the three admin views are wired with
`@Route(value = "...", layout = MainLayout.class)` and therefore
render *inside* `MainLayout` — `HomeButton.forStandalone` returns
empty, the drawer's `SecuredUi.link(...)` entries provide the
navigation back to `/`. If a consumer later detaches one of the
admin views (`@Route("audit")` without a layout), the Home button
re-appears automatically — no template re-edit.

### Public vs. private routes

Routes generated by the skill fall into three buckets — the
visibility rule is "no restriction annotation ⇒ public":

| Bucket | Annotations | Reachable by | Drawer entry |
|---|---|---|---|
| **Public** | `@Route(value="", layout=MainLayout.class)` (no `@VisibleFor` / `@RequiresPermission`) | anyone, signed in or not | plain `RouterLink` → always shown |
| **Authenticated-only** | `@Route(...) + @VisibleFor(USER)` — e.g. `DashboardView` | every logged-in subject | `SecuredUi.link().requiresPermission("app:view").hideWhenDenied()` → hidden for anonymous |
| **Permission-protected** | `@Route(...) + @RequiresPermission("...")` — e.g. `AuditView` | subjects holding the permission | `SecuredUi.link().requiresPermission("...").hideWhenDenied()` → hidden until granted |

The `LoginListener` does the gatekeeping: if a navigation target
carries no `@JCustosAnnotation`-meta-annotated restriction, the
scanner returns empty, the listener marks it unrestricted and
authentication is skipped. That is what makes `PublicHomeView`
reachable without login — there's nothing for the listener to
check.

The **navbar's Sign in / Sign out button** is dynamic — `MainLayout`
implements `BeforeEnterObserver` and rebuilds the button on every
navigation. The button lives inside a `Div` "slot" so only the
button instance is swapped, not the navbar layout. Anonymous
visitors see a primary "Sign in" CTA; logged-in users see a tertiary
"Sign out".

To add a new public area, drop a view at
`@Route(value="...", layout=MainLayout.class)` with no security
annotation and a plain `RouterLink` in the drawer. To add a new
private area, add `@RequiresPermission("x")` (or `@VisibleFor`) and
use `SecuredUi.link().requiresPermission("x").hideWhenDenied()` —
the drawer entry materialises only for subjects that hold the
permission.

---

## Reading the brief — slots to extract

The brief is usually a sentence or two. Extract these slots before
generating anything. Default everything you can; ask only when more
than one slot is genuinely missing.

| Slot | Example | Default if missing |
|---|---|---|
| **Target Vaadin module** | `webapp`, `ui`, root `pom.xml` | Single Vaadin module: that one. Multi-module: ask which one. |
| **Base package** | `com.acme.bookstore` | Look at existing `@Route` classes' package; ask if none. |
| **Subject type name** | `User`, `Account`, `Identity`, `MyUser` | `User` |
| **Subject prefix for service classes** | `My`, `App`, `Bookstore`, `<empty>` | `My` (matches the demo) — yields `MyAuthenticationService`, `MyLoginView` |
| **Admin credentials** | `admin / admin`, `root / changeit` | `admin / admin` |
| **Regular user credentials** | `user / user`, `alice / wonderland` | `user / user` |
| **Bootstrap profile** | `developmentDefaults`, `productionDefaults`, `strictDefaults` | `developmentDefaults` |
| **App title** | "Bookstore Admin" | "<app name from pom.xml> Security" |

**If more than one slot is missing**, send ONE message with all the
clarifying questions (use AskUserQuestion). If only one is missing,
infer it from the surrounding context (existing `@Route` packages,
the module's `<name>` in pom.xml, etc).

---

## Rendering templates

Every file in `references/` ends with `.tmpl`. Open each one, perform
these substitutions (case-sensitive), then write to the target path.

| Token | Replace with |
|---|---|
| `{{BASE_PACKAGE}}` | `com.acme.bookstore` |
| `{{BASE_PATH}}` | `com/acme/bookstore` (BASE_PACKAGE with `.` → `/`) |
| `{{SUBJECT_TYPE}}` | `User`, `Account`, ... |
| `{{SUBJECT_PREFIX}}` | `My`, `App`, ... (used in `{{SUBJECT_PREFIX}}AuthenticationService`) — empty string is valid |
| `{{ADMIN_USERNAME}}` | `admin` |
| `{{ADMIN_PASSWORD}}` | `admin` |
| `{{USER_USERNAME}}` | `user` |
| `{{USER_PASSWORD}}` | `user` |
| `{{BOOTSTRAP_PROFILE}}` | `developmentDefaults` / `productionDefaults` / `strictDefaults` |
| `{{APP_TITLE}}` | `Bookstore Admin` |
| `{{LOGIN_ROUTE}}` | always `login` |
| `{{STEP_UP_ROUTE}}` | always `step-up` |

Template-to-target file mapping (apply after substitution):

| Template | Target |
|---|---|
| `pom-snippet.xml.tmpl` | merge into existing `pom.xml` |
| `Application.java.tmpl` | `src/main/java/{{BASE_PATH}}/Application.java` |
| `Subject.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/{{SUBJECT_TYPE}}.java` |
| `Credentials.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/Credentials.java` |
| `UserDirectory.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/UserDirectory.java` |
| `InMemoryUserDirectory.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/InMemoryUserDirectory.java` |
| `UserDirectoryProvider.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/model/UserDirectoryProvider.java` |
| `AuthorizationRole.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/roles/AuthorizationRole.java` |
| `VisibleFor.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/roles/VisibleFor.java` |
| `RoleAccessEvaluator.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/roles/RoleAccessEvaluator.java` |
| `AppPermission.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/permissions/AppPermission.java` |
| `AuthenticationService.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/{{SUBJECT_PREFIX}}AuthenticationService.java` |
| `AuthorizationService.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/{{SUBJECT_PREFIX}}AuthorizationService.java` |
| `SessionStoreProvider.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/services/SessionStoreProvider.java` |
| `BootstrapExtension.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/BootstrapExtension.java` |
| `BootstrapBuilder.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/BootstrapBuilder.java` |
| `DefaultBootstrapExtension.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/DefaultBootstrapExtension.java` |
| `JCustosBootstrapInitListener.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/bootstrap/JCustosBootstrapInitListener.java` |
| `services-BootstrapExtension.tmpl` | `src/main/resources/META-INF/services/{{BASE_PACKAGE}}.security.bootstrap.BootstrapExtension` |
| `LoginListenerImpl.java.tmpl` | `src/main/java/{{BASE_PATH}}/security/{{SUBJECT_PREFIX}}LoginListener.java` |
| `MyLoginView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/{{SUBJECT_PREFIX}}LoginView.java` |
| `MainLayout.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/MainLayout.java` |
| `PublicHomeView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/PublicHomeView.java` |
| `DashboardView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/DashboardView.java` |
| `HomeButton.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/HomeButton.java` |
| `AuditView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/admin/AuditView.java` |
| `SessionsView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/admin/SessionsView.java` |
| `AdminRolesView.java.tmpl` | `src/main/java/{{BASE_PATH}}/views/admin/AdminRolesView.java` |
| `services-LoginListener.tmpl` | `src/main/resources/META-INF/services/eu.jsentinel.jcustos.authorization.LoginListener` |
| `services-AccessEvaluator.tmpl` | `src/main/resources/META-INF/services/eu.jsentinel.jcustos.authorization.api.AccessEvaluator` |
| `services-VaadinServiceInitListener.tmpl` | `src/main/resources/META-INF/services/com.vaadin.flow.server.VaadinServiceInitListener` |

---

## POM patch — what to merge

Open the target module's `pom.xml`. Confirm the `<parent>` is
`jCustos-parent` (or pull `<version>` from a property — the
templates assume the user is in the security-for-flow reactor or in a
project that depends on it via Maven coordinates).

**Add these dependencies** under `<dependencies>` (idempotent — skip
any already present):

```xml
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-core</artifactId>
    <version>${jcustos.version}</version>
</dependency>
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-autoservice-annotations</artifactId>
    <version>${jcustos.version}</version>
</dependency>
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-vaadin</artifactId>
    <version>${jcustos.version}</version>
</dependency>
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-dx</artifactId>
    <version>${jcustos.version}</version>
</dependency>
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-dx-vaadin</artifactId>
    <version>${jcustos.version}</version>
</dependency>
<dependency>
    <groupId>eu.jsentinel</groupId>
    <artifactId>jCustos-vaadin-starter</artifactId>
    <version>${jcustos.version}</version>
</dependency>
```

Define `<jcustos.version>` in `<properties>` if not inherited. Use
the same version coordinate the parent ships (currently `00.73.00`).

**Add these annotation processor paths** to the
`maven-compiler-plugin` configuration. If the plugin block doesn't
exist, create it; if it does, merge the `<annotationProcessorPaths>`
entries (don't replace existing ones):

```xml
<plugin>
    <artifactId>maven-compiler-plugin</artifactId>
    <configuration>
        <annotationProcessorPaths>
            <path>
                <groupId>eu.jsentinel</groupId>
                <artifactId>jCustos-autoservice-processor</artifactId>
                <version>${jcustos.version}</version>
            </path>
            <path>
                <groupId>eu.jsentinel</groupId>
                <artifactId>jCustos-autoservice-annotations</artifactId>
                <version>${jcustos.version}</version>
            </path>
        </annotationProcessorPaths>
    </configuration>
</plugin>
```

> **Path order matters.** The `*-processor` path MUST come before the
> `*-annotations` path on JDK 21+; reversed order causes silent
> no-emit. (The demo proves it; the JDK isolates each processor JAR
> from the annotation it processes if the annotation JAR comes
> first.)

---

## Bootstrap profile choice

`developmentDefaults` (the skill default) prints a verbose
startup banner via `JCustosRuntime.log()` to stdout, wires an
in-memory audit ring buffer (256 events), and tolerates missing
critical SPIs with WARNing-level diagnostics. The right default while
the integration is being verified.

`productionDefaults` is the same surface minus the in-memory defaults
— missing SPIs surface as WARNings but the app continues. Use for
deployed builds.

`strictDefaults` raises `JCustosBootstrapException` if any critical
SPI is missing. Right for compliance-gated deployments where a
silently-misconfigured security stack is unacceptable.

The three profiles are interchangeable — swap the one-liner in
`JCustosBootstrapInitListener` and recompile.

---

## Verification checklist

After rendering + writing every template:

1. `./mvnw -pl <module> -am compile` — must succeed with zero warnings
   in the security packages.
2. Verify `META-INF/services` has three new entries:
   ```bash
   ls src/main/resources/META-INF/services/
   ```
3. Verify `@JCustosAutoService` produced the `META-INF/services`
   entries for `AuthenticationService` and `AuthorizationService`:
   ```bash
   find target/classes/META-INF/services -type f -exec grep -l '{{SUBJECT_PREFIX}}AuthenticationService' {} +
   find target/classes/META-INF/services -type f -exec grep -l '{{SUBJECT_PREFIX}}AuthorizationService' {} +
   ```
4. Start the dev server (`jetty:run` or whatever the module uses) and
   open `http://localhost:8080/login`.
5. Log in with the admin credentials — should land at `/` with the
   role badges showing `ADMIN, USER`.
6. Confirm `/audit`, `/admin/sessions`, `/admin/roles` are reachable.
7. Log out, log in with the regular user — `/audit`, `/admin/sessions`,
   `/admin/roles` must reroute (per the framework's denied-decision
   mapper).

The bootstrap banner (a multi-line `JCustosRuntime.log()` printout)
appears on the first request handled by Vaadin — that's the signal
the fluent chain actually installed.

---

## Pitfalls

### Annotation processor path order

`*-processor` BEFORE `*-annotations` in `<annotationProcessorPaths>`.
Reversed → silent no-emit, no error, no `META-INF/services` entries,
runtime `NoServiceFoundException`. This is the single most common
cause of "I added the annotation but ServiceLoader can't find my
class".

### `optimizeBundle=false` for dynamic routes

Not required for this skill (we use `@Route` annotations, not
`RouteConfiguration` programmatic registration). But if the consuming
app later adds `vaadin-opencore` or another runtime route registrar,
that toggle becomes mandatory.

### Subject-type leakage between adapters

`{{SUBJECT_TYPE}}` lives in this Vaadin app only. If the same project
later adds the REST adapter (`jCustos-rest`), DO NOT reuse the same
type — REST has its own `JCustosSubject` view of the user. The
`AuthenticationService` is the boundary; everything past
`loadSubject` is adapter-local.

### Audit sink swallowing failures

The `JCustosAuditService` calls in the templates wrap every
`publish(...)` in `try { ... } catch (RuntimeException ignored) {}`.
This is deliberate — a logging-sink failure must never block login,
role admin, or session creation. If the audit feed seems empty in
the `/audit` grid, check the JVM logs first; the sink throw was
caught and discarded.

### `MainLayout` drawer entries

The `MainLayout` template builds its drawer entirely from
`SecuredUi.link(...)` builders — each entry hides itself when the
subject lacks the required permission (`hideWhenDenied()`). No
manual `isCurrentUserAuthorizedFor(...)` guards. A regular user
sees only "Home"; an ADMIN sees "Home" + "Audit log" + "Active
sessions" + "Role administration". If the consuming app needs a
Tabs-based drawer instead, swap `SecuredUi.link(...)` for tabs
with `SecuredUi.menuItem(...)` — the visibility discipline is the
same.

### Pre-seeded passwords visible in source

The skill seeds `admin / admin` and `user / user` as **plain
constants in `InMemoryUserDirectory`** — the constructor hashes them
through `JCustosServiceResolver.passwordHashingService()` before
storing. The strings appear in the source file, which is acceptable
for a demo / first integration but is a hard "DO NOT SHIP" for
production. Real deployments wire the V00.72
`InitialAdminBootstrapService` + `BootstrapWiring` (token flow) — see
`demo-vaadin`'s `SetupView` for the full pattern. The skill leaves a
`TODO` comment in the directory file pointing at that.

### `<jcustos.version>` property

If the consuming project doesn't already define `<jcustos.version>`
(or `${project.version}` for in-reactor builds), the rendered POM
fails. The skill writes `${jcustos.version}` by default — if the
project is the security-for-flow reactor itself, swap to
`${project.version}` after rendering.

---

## What this skill deliberately does NOT cover

- **Token-based first-admin bootstrap** (`BootstrapWiring`,
  `SetupView`, `InitialAdminBootstrapService`,
  `BootstrapTokenStore`). The skill pre-seeds the admin in plaintext
  for fast onboarding. Migrate to the token flow before any
  multi-tenant or multi-user deployment — see
  `demo-vaadin/src/main/java/.../security/bootstrap/BootstrapWiring.java`.
- **Persistence** (`jCustos-persistence-eclipsestore`,
  `StoreBackedJCustosAuditService`, `EclipseStoreSessionStore`).
  The skill uses in-memory stores. Swap the providers in
  `SessionStoreProvider` + the `.audit(...)` sub-builder when wiring
  Eclipse-Store.
- **REST or Standalone adapters.** Separate skills.
- **i18n.** Use the `vaadin-i18n` skill alongside.
- **Mutation tests.** Use the `vaadin-mutation-browserless` skill
  alongside.
- **Custom `JCustosSubject` mapping.** The default —
  `AuthorizationService.rolesFor` / `permissionsFor` returning the
  user's role + permission sets — is enough for most apps. Custom
  mappings live in `JCustosSubjectMapper` and are out of scope.

---

## Compact procedural recipe

```text
1. Resolve slots (1 message, all questions at once if missing).
2. Echo the slot block back, then proceed.
3. Render each .tmpl in references/, perform substitutions, write to target.
4. Merge pom-snippet.xml.tmpl into the module's pom.xml (do NOT overwrite).
5. Create the three META-INF/services files from their .tmpl counterparts.
6. Run ./mvnw -pl <module> -am compile.
7. If green, instruct the user to start dev server and visit /login.
8. Verify admin login + regular-user login; confirm role-restricted views.
```

Done.
