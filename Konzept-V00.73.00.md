# Konzept V00.73.00: Fluent-Bootstrap-Vervollständigung + Stable-API

Version: `00.73.00`
Quellstand: V00.72.00 (feature-complete on `develop`)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.73.00` schließt zwei Lücken, die V00.72 bewusst offengehalten hat:

1. **Sub-Builder-Wiring.** Die fünf in V00.72 als "recorded only" eingeführten Sub-Builder (`.audit`, `.sessions`, `.policies`, `.roles`, `.credentials`) bekommen ihr echtes Wiring in `SecurityServiceResolver`, bestehende Stores und die jeweiligen V00.70/V00.71-Registries. Aufrufer können dann ihren Setup-Code weitgehend in einer einzigen `*Security.bootstrap()`-Kette schreiben.
2. **Gezielte Stable-API-Promotion.** V00.73 promoted nur die Typen, deren Laufzeitverhalten nach dem Wiring wirklich stabil ist. Sub-Builder, deren Semantik noch von offenen V00.75/V00.80-Entscheidungen abhängt, bleiben bewusst `@ExperimentalSecurityApi`.

Begleitend werden zwei kleinere V00.72-Carve-outs nachgezogen:

3. **Wrapper-Index-Writer.** `security-processor` schreibt die in V00.72 nur lesbare `META-INF/security-for-flow/generated-wrappers.idx`. Damit funktioniert die `SecurityDiagnostics`-Wrapper-Erkennung end-to-end.
4. **`SecuredUi.requiresPolicy(...)`.** Der V00.72-Builder warf bei diesem Aufruf `UnsupportedOperationException`. V00.73 verdrahtet ihn gegen `PolicyRegistry`.

Der Kern (`security-core`) bekommt keinen neuen Runtime-Dependency-Eintrag. `security-processor` erhält additive Metadaten-Ausgabe; die proxybuilder-Generierungs-Semantik bleibt unverändert.

V00.73 ändert keine bestehenden Core-SPIs. Wo der aktuelle Quellstand keinen passenden `SecurityServiceResolver`-Setter besitzt, wird der Sub-Builder zunächst über `BootstrapState`, `SecurityRuntime` und adapter-spezifische Verdrahtung wirksam. Ein neuer Core-Setter ist nur zulässig, wenn er als eigene Scope-Entscheidung dokumentiert und getestet wird.

---

## 2. Leitmotiv und Einordnung im Roadmap-Kontext

V00.72 hat die DX-Schicht eingeführt und gezeigt, dass eine fluente Bootstrap-API in vier Adapter-Modulen sauber funktioniert. Die Akzeptanzkriterien hat V00.72 vollständig erfüllt; die in §1 genannten Sub-Builder waren explizit als V00.73-Arbeit ausgewiesen, damit V00.72 nicht durch Wiring-Komplexität blockiert wurde.

V00.73 nutzt das Feedback aus den vier V00.72-Demo-Migrationen (`demo-standalone`, `demo-vaadin`, `demo-vaadin-rest-client`, `demo-rest`), um die richtigen Wrapper für Audit, Sessions, Policies, Rollen und Credentials zu finden. Das ist genau die Iterations-Strategie, die V00.72-§2 anvisiert hat: **erst die richtige API-Form lernen, dann committen**.

V00.73 ist damit eine **Vervollständigungs- und Stabilisierungs-Version**. Sie führt keine neuen Security-Primitiven ein und ersetzt keine bestehenden SPIs — sie verdrahtet, was V00.72 als Versprechen hinterlegt hatte, und macht die DX-Surface zur Long-Term-API.

V00.75 (Security Event Bus) und V00.80 (MFA, OIDC, Hardening) bauen darauf auf.

---

## 3. Scope und Non-Scope

### 3.1 In Scope

- **Sub-Builder-Wiring** für `.audit(...)`, `.sessions(...)`, `.policies(...)`, `.roles(...)`, `.credentials(...)` in der `CommonSecurityBootstrap`-Basis.
- **Adapter-Symmetrie**: REST und Standalone bekommen wo sinnvoll dieselben Sub-Builder; Vaadin-spezifische Erweiterungen (`SessionManagementView`-Aktivierung, `VaadinSessionSubjectStore`-Auto-Wiring) werden konsumiert.
- **`SecuredUi.requiresPolicy(...)`** integriert mit `PolicyRegistry`.
- **`@SecureRoute(policy=...)`** integriert mit `PolicyRegistry` (V00.72 schlug Forbidden vor; V00.73 evaluiert echt).
- **`security-processor`-Wrapper-Index-Writer**: `META-INF/security-for-flow/generated-wrappers.idx` wird beim Compile-Time-Wrapper-Generieren emittiert.
- **Gezielte Stable-API-Promotion**: Entfernen von `@ExperimentalSecurityApi` nur nach Typ-Audit und nur für Typen, deren Semantik nach V00.73 stabil ist.
- **`security-dx-test`-Modul nur dann, wenn während der Implementierung ein konkreter Cross-Module-Reuse-Fall auftritt.** Bis dahin: DX-typisierte Test-Helpers leben in `security-dx/src/test/java/.../testsupport/` und werden über Maven-Test-Jar (`<scope>test</scope>` + `<classifier>tests</classifier>`) für andere V00.72/V00.73-Module zugänglich gemacht. Erst wenn eine Demo oder ein externer Konsument diese Helper braucht, rechtfertigt das ein eigenes Modul.
- **STRICT-Mode-Regeln** für die neuen Sub-Builder (z. B. `STRICT` + `.sessions(s -> s.storeBacked(null))` → `SecurityBootstrapException`).
- **Dokumentations-Update**: 5-Minute-Setup-Dateien zeigen den vollständigen Fluent-Pfad statt der V00.72-Mischform.
- **Acceptance-Kriterium**: `demo-vaadin-rest-client/DemoPolicyInitListener.registerDemoPolicies()` verschwindet — die Policy-Registrierung passiert vollständig im `.policies(...)`-Lambda.

### 3.2 Non-Scope für V00.73.00

- Keine neuen Authentifizierungsverfahren (MFA, WebAuthn, OIDC bleiben V00.80).
- Kein Security Event Bus (V00.75).
- Kein Ersatz für `SecurityServiceResolver` — die Sub-Builder verdrahten dorthin.
- Keine neue Policy-DSL — die V00.70-DSL (`Policy.named(...).allowIf(...).deny(...).build()`) bleibt unverändert.
- Keine neuen Krypto-Provider.
- Keine Änderung der V00.71-Credential-Pipeline und keine Vermischung von alter `PasswordHasher`-Resolver-API mit der neueren `PasswordHashingService`-Pipeline ohne expliziten Adapter.
- Keine Migration externer Hash-Formate.
- Keine Maven-Central-Deploy-Pipeline-Änderungen.

### 3.3 Explizit nicht in V00.73 — bleiben außerhalb der Builder-API

Folgende V00.70/V00.71-Services bekommen in V00.73 **keinen** Sub-Builder. Sie bleiben über `SecurityServiceResolver.setXxx(...)`, `@SecurityAutoService` oder direkte Konstruktion erreichbar:

- `ActionAuthorizationService` — selten verwendet
- `LogoutService` — V00.70-Stable, kein Bedarf für Fluent-Wrapping
- API-Keys (`ApiKeyStore` / `ApiKeyAuthenticationService`)
- Refresh-Tokens (`TokenService` / `RefreshTokenStore`)
- Rate-Limit (`RateLimitPolicy` / `RateLimitStore`)
- Account-Lifecycle (`BootstrapStateService` / `InitialAdminBootstrapService`)
- `AbuseDetectionService`
- `CompromisedPasswordChecker` (HIBP)
- `CredentialMetricsCollector`
- Tenant-Aware (`TenantAwareResolver`, tenant-spezifische Policies)

Das ist die ehrliche Antwort auf "welche Features fehlen nach V00.73 noch im Builder". Spätere Releases können fluent-Wrapper nachziehen, sobald Demo-Bedarf entsteht.

### 3.4 STRICT-Mode-Promotion = dokumentiertes Breaking Change

Drei V00.72-Warnings werden in V00.73 zu STRICT-Exceptions:

- `secure-route/unknown-policy`
- `session-management-view-without-session-store`
- `security-version-without-subject-id-resolver`

Eine V00.72-Anwendung mit `mode(STRICT)` und einer dieser Warnings hat sich bisher zwar diagnostisch gemeldet, aber nicht abgebrochen — ab V00.73 bricht sie ab. Das ist ein semver-relevantes Breaking Change und wird in `RELEASE-NOTES-00.73.00.md` als eigene Sektion ausgewiesen. Konsumenten, die im STRICT-Mode laufen wollen, müssen vor dem V00.73-Update die Diagnose-Output ihrer V00.72-Instanz auf diese drei Codes prüfen.

---

## 4. Architektonische Leitlinien

1. **Additiv über V00.72.** Bestehende Setup-Pfade (direkt auf `SecurityServiceResolver.setXxx(...)` oder `.xxxRegistry()`) bleiben gleichwertig nutzbar. Sub-Builder-Wiring ersetzt sie nicht, sondern bietet einen alternativen Pfad.

2. **Kein neuer Runtime-Dependency-Eintrag im Kern.** `security-core` bleibt dependency-stabil. Sub-Builder-Wiring verwendet bevorzugt bestehende `SecurityServiceResolver`-Setter. Fehlt ein Setter, bleibt die Verdrahtung in `security-dx` / Adapter-DX oder wird als separate Core-SPI-Erweiterung entschieden.

3. **Sub-Builder-Methoden sind explizit typisiert.** Statt der V00.72-Placeholder-Methoden (`.ringBuffer()`, `.timeout(Duration)`, `.register(Object)`, …) bekommen die fünf Sub-Builder konkrete Methoden für jede V00.70/V00.71-Service-Variante.

4. **STRICT-Konsistenz.** Jeder Sub-Builder-Aufruf, der eine kritische Voraussetzung verletzt (z. B. `SessionManagementView` ohne `SessionStore`), führt im `STRICT`-Mode zu `SecurityBootstrapException` mit stabilem Code. Die Code-Namespaces sind in V00.72 bereits etabliert; V00.73 füllt sie aus.

5. **Adapter-Symmetrie wo sinnvoll.** Audit / Sessions / Policies / Roles / Credentials sind common — sie funktionieren in Vaadin, REST und Standalone identisch. Adapter-spezifische Aspekte (`SessionManagementView` ist Vaadin-only, `LoginAttemptPolicy` ist primär Standalone-relevant) bleiben adapter-spezifisch.

6. **Stable-API-Promotion ist ein Versprechen.** Sobald `@ExperimentalSecurityApi` entfernt ist, gilt SemVer: Breaking Changes nur in Major-Bumps. V00.73 prüft jede V00.72-Public-Surface darauf, ob sie nach dem echten Wiring stabil ist. Die Promotion ist kein Prozentziel, sondern eine Typ-für-Typ-Entscheidung.

7. **`security-processor` bleibt fokussiert.** Der Wrapper-Index-Writer ist additive Metadaten-Ausgabe. Die `proxybuilder`-basierte Generierung bleibt byte-für-byte identisch zu V00.72.

8. **Migration ist optional, nicht zwingend.** V00.72-Konsumenten, die direkt auf `SecurityServiceResolver` setzen, müssen nichts ändern. V00.73 bietet einen besseren Pfad — Adoption bleibt Sache des Konsumenten.

### 4.1 Adapter-Symmetrie — was tut welcher Sub-Builder pro Adapter?

| Sub-Builder | Vaadin | REST | Standalone |
|---|:---:|:---:|:---:|
| `.audit(...)` | ✓ | ✓ | ✓ |
| `.sessions(...)` | ✓ | ✓ (sofern HTTP-Session-Konzept verwendet wird) | ⚠ no-op (keine Session-Semantik in CLI) |
| `.policies(...)` | ✓ | ✓ | ✓ |
| `.roles(...)` | ✓ | ✓ | ✓ |
| `.credentials(...)` | ✓ | ✓ | ✓ |

`.sessions(...)` in `StandaloneSecurityBootstrap` ist kein Fehler — die Methode bleibt aufrufbar, aber `install()` warnt mit Code `standalone/sessions-not-applicable` (Severity.INFO; STRICT macht keine Exception, das wäre überreagiert). Adapter-spezifische Schritte (Vaadin: `SessionManagementView`-Activation, REST: `RestSecurityVersionFilter`) bleiben weiter auf dem jeweiligen Adapter-Bootstrap.

---

## 5. Modulstrategie

V00.73 erweitert sechs bestehende Module und fügt **kein neues Pflichtmodul** hinzu. Ein optionales `security-dx-test`-Modul kann später nachgezogen werden, wenn Demo-/Konsumenten-Tests den Bedarf konkret zeigen — bis dahin liefert `security-dx` seine Test-Helpers über das Maven-Test-Jar (`<classifier>tests</classifier>`).

| Modul | V00.72-Status | V00.73-Änderung |
|---|---|---|
| `security-dx` | DX-Core | Sub-Builder-Surface stark erweitert (echte Methoden statt Platzhalter), `BootstrapState` in Sub-Aggregate aufgeteilt (`AuditState`, `SessionState`, `PolicyState`, `RoleState`, `CredentialState`), damit sie kein Gott-Objekt wird |
| `security-dx-vaadin` | Vaadin-Bootstrap | `SessionManagementView`-Flag aktiviert echte View-Registrierung; `VaadinSessionSubjectStore`-Auto-Wiring |
| `security-dx-rest` | REST-Bootstrap | Sub-Builder konsumieren Audit / Session / Policy für REST-Pfad |
| `security-dx-standalone` | Standalone-Bootstrap | Sub-Builder konsumieren Audit / Session / Policy für Standalone-Pfad |
| `security-vaadin-starter` | Starter | `SecuredUi.requiresPolicy(...)` echt; `@SecureRoute(policy=...)` über PolicyRegistry evaluiert |
| `security-processor` | Wrapper-Generierung | Wrapper-Index-Writer ergänzt |

`security-core`, `security-vaadin`, `security-rest`, `security-standalone` bleiben unverändert. Ein eigenes `security-dx-test`-Modul wird **nicht** aufgemacht — Test-Helpers liegen unter `security-dx/src/test/java/.../testsupport/` und werden bei Bedarf über das Maven-Test-Jar (`<classifier>tests</classifier>`) wiederverwendet. Erst wenn ein konkreter Cross-Modul-Reuse-Fall entsteht, wird das Modul nachgezogen.

### 5.1 Abhängigkeitsregeln (unverändert)

Die V00.72-§5.2 Regeln gelten unverändert weiter. `security-dx-test` (falls eingeführt) folgt dem Muster von `security-test`: hängt nur an `security-dx` (+ `security-test` für Core-Fakes) und wird von Konsumenten als `<scope>test</scope>` gezogen.

### 5.2 Forbidden

- `security-dx` → adapter-spezifische Typen
- `security-dx` → `security-dx-test`
- Sub-Builder-Wiring führt zu `security-core`-Imports — kein Problem (DX hängt schon an Core)
- Sub-Builder-Wiring führt zu `security-vaadin`-spezifischen Imports — nur in `security-dx-vaadin`

---

## 6. Baustein 1: Audit Sub-Builder

### 6.1 Problem (V00.72-Status)

`AuditBootstrap.ringBuffer()` ist Recorded-only. Konsumenten verdrahten `SecurityAuditService`-Impls direkt über `SecurityServiceResolver.setSecurityAuditService(...)` oder via `META-INF/services`.

Der aktuelle Core-Stand unterscheidet zwischen `SecurityAuditService`, `AuditSink`, `AuditEventStore`, `StoreBackedSecurityAuditService`, `LoggingAuditSink`, `RingBufferAuditSink` und `CompositeAuditService`. V00.73 verwendet diese vorhandenen Typen; ein generischer `AuditStore` wird nicht neu eingeführt.

### 6.2 Ziel

```java
.audit(a -> a
    .storeBacked(auditEventStore)      // StoreBackedSecurityAuditService
    .logging()                          // LoggingAuditSink anschließen
    .ringBuffer(1024)                   // In-Memory RingBuffer-Sink
    .credentialEvents(true)             // CredentialAuditPublisher nutzt den konfigurierten Audit-Service
)
```

`install()` bildet aus den gewählten Bausteinen genau einen `SecurityAuditService`:

- `.securityAuditService(...)` setzt einen fertigen Service direkt.
- `.storeBacked(...)` erzeugt einen `StoreBackedSecurityAuditService`.
- `.logging()` und `.ringBuffer(...)` werden als Sinks in einen `CompositeAuditService` aufgenommen.
- Werden mehrere Ziele konfiguriert, entsteht ein Composite; nichts wird still überschrieben.

Der resultierende Service wird über `SecurityServiceResolver.setSecurityAuditService(...)` registriert. `CredentialAuditPublisher` nutzt anschließend denselben Resolver-Pfad; V00.73 führt dafür keinen zweiten Audit-Kanal ein.

### 6.3 API-Skizze

```java
public interface AuditBootstrap {
  AuditBootstrap securityAuditService(SecurityAuditService service);
  AuditBootstrap storeBacked(AuditEventStore store);
  AuditBootstrap logging();
  AuditBootstrap ringBuffer(int capacity);
  AuditBootstrap credentialEvents(boolean enabled);
}
```

### 6.4 STRICT-Regeln

- `audit/missing-service` — `audit(...)` aufgerufen ohne mindestens eine Auswahl-Methode → STRICT wirft.
- `audit/store-backed-without-store` — `.storeBacked(null)` → STRICT wirft.
- `audit/invalid-ring-buffer-capacity` — `.ringBuffer(0)` oder kleiner → STRICT wirft; PRODUCTION warnt.

---

## 7. Baustein 2: Sessions Sub-Builder

### 7.1 Problem

`SessionBootstrap.timeout(Duration)` ist Recorded-only. `SessionPolicy` und `SecurityVersionStore` haben bestehende Resolver-Setter; `SessionStore` hat im aktuellen Core-Stand keinen globalen `SecurityServiceResolver`-Setter. V00.73 muss diesen Unterschied explizit behandeln.

### 7.2 Ziel

```java
.sessions(s -> s
    .storeBacked(sessionStore)
    .securityVersion(securityVersionStore)
    .timeout(Duration.ofMinutes(30))
    .absoluteLifetime(Duration.ofHours(8))
)
```

### 7.3 API-Skizze

```java
public interface SessionBootstrap {
  SessionBootstrap storeBacked(SessionStore store);
  SessionBootstrap securityVersion(SecurityVersionStore store);
  SessionBootstrap subjectIdResolver(SubjectIdResolver<?> resolver);
  SessionBootstrap timeout(Duration idleTimeout);
  SessionBootstrap absoluteLifetime(Duration absoluteTimeout);
  SessionBootstrap policy(SessionPolicy<?> policy);
}
```

Wiring-Regeln:

- `.policy(...)` wird über `SecurityServiceResolver.setSessionPolicy(...)` registriert.
- `.timeout(...)` / `.absoluteLifetime(...)` erzeugen eine `TimeoutSessionPolicy`, sofern keine explizite `.policy(...)` gesetzt wurde.
- `.securityVersion(...)` wird über `SecurityServiceResolver.setSecurityVersionStore(...)` registriert.
- `.subjectIdResolver(...)` wird über `SecurityServiceResolver.setSubjectIdResolver(...)` registriert. Die Methode landet im `SessionBootstrap`, weil der `SubjectIdResolver` in V00.70/V00.71 ausschließlich für `SecurityVersion`-Drift-Detection benötigt wird — also ein Session-Konzept. Wenn V00.75 weitere Verwendungen einführt, kann eine zweite Aufruf-Position ergänzt werden.
- `.storeBacked(...)` bleibt im `BootstrapState` und im `SecurityRuntime` verfügbar und wird von Adapter-DX-Modulen konsumiert. Vaadin nutzt ihn für `SessionManagementView`. Ein globaler `setSessionStore(...)` wird in V00.73 nicht stillschweigend eingeführt.

### 7.4 Vaadin-Erweiterung

Wenn `VaadinSecurityBootstrap.sessionManagementView()` gesetzt war, prüft V00.73 jetzt zur `install()`-Zeit, ob `.sessions(s -> s.storeBacked(...))` konfiguriert wurde. Falls nicht → `session-management-view-without-session-store`-Warning (STRICT: Exception).

Die Aktivierung der View ist kein bloßer Boolean mehr. Das Vaadin-DX-Modul muss eine konkrete Route-/Provider-Strategie definieren:

- bevorzugt: dokumentierte Adapter-Route, die den konfigurierten `SessionStore` injiziert,
- alternativ: Factory-/Supplier-Hook im Vaadin-Bootstrap,
- nicht zulässig: Registrierung einer View, deren Konstruktorabhängigkeiten zur Laufzeit fehlen.

### 7.5 STRICT-Regeln

- `sessions/missing-store` — `.timeout(...)` aufgerufen ohne `.storeBacked(...)` oder `.policy(...)` → STRICT wirft.
- `sessions/security-version-without-subject-id-resolver` — `securityVersion(...)` ohne `SubjectIdResolver` registriert → Warning; STRICT wirft.
- `sessions/invalid-timeout` — `timeout` oder `absoluteLifetime` ist `null`, negativ oder `Duration.ZERO` → STRICT wirft; PRODUCTION warnt.

---

## 8. Baustein 3: Policies Sub-Builder

### 8.1 Problem

`PolicyBootstrap.register(Object)` ist untypisiert und Recorded-only. Demos rufen `SecurityServiceResolver.policyRegistry().register(...)` direkt.

### 8.2 Ziel

```java
.policies(p -> p
    .register(Policy.named("doc.owner-or-admin")
        .allowIf(SubjectPredicates.hasRole("ADMIN"))
        .orIf(ResourcePredicates.ownerMatchesSubject("doc", "owner"))
        .deny("not owner or admin")
        .build())
    .resourceResolver(new DemoDocumentResolver())
    .registry(externalPolicyRegistry)   // optional: externe Registry injizieren
)
```

Im `demo-vaadin-rest-client` ersetzt das die heutige `registerDemoPolicies()`-Methode komplett.

### 8.3 API-Skizze

```java
public interface PolicyBootstrap {
  PolicyBootstrap register(Policy policy);
  PolicyBootstrap resourceResolver(ResourceResolver<?> resolver);
  PolicyBootstrap registry(PolicyRegistry external);            // ersetzt die Default-Registry
  PolicyBootstrap resourceRegistry(ResourceResolverRegistry external);
}
```

### 8.4 SecuredUi-/`@SecureRoute`-Integration

Sobald `.policies(...)` echt verdrahtet, kann V00.73:

- `SecuredUi.button(...).requiresPolicy("doc.delete").build()` echt evaluieren (V00.72: UOE).
- `@SecureRoute(policy = "doc.view")` echt gegen `PolicyRegistry` evaluieren (V00.72: deny-by-default).

Konsumenten, die das schon in V00.72 nutzen wollten, bekommen ohne Code-Änderung das erwartete Verhalten.

**Empty-Subject-Semantik.** Wenn der `AccessContext` kein `SecuritySubject` enthält:

- Bei nicht-leerem Policy-Wert: `AuthorizationDecision.Unauthenticated("policy requires subject: <name>")`. Nicht `Forbidden` — der Subject-Layer ist die zuerst zu klärende Frage.
- Konsistent mit der V00.72-Logik von `SecureRouteEvaluator` für nicht-leere `roles[]` / `permissions[]`.
- `SecuredUi.requiresPolicy(...)` evaluiert über `SecuredVisibility.currentSecurityView()`; ist die View leer (kein Login), zeigt sich das Verhalten gemäß gewähltem `hideWhenDenied()` / `disableWhenDenied()`.

**Deterministische Cross-Validation.** Da `.policies(...)` nach `install()` alle registrierten Policy-Namen kennt, prüft V00.73 zur Bootstrap-Zeit, ob Routes mit `@SecureRoute(policy="x")` einen unbekannten Namen referenzieren. Die Prüfung wird genau dann deterministisch, wenn der Konsument einen `SecureRouteDiscovery`-Hook bereitstellt — eine schmale neue SPI in `security-vaadin-starter`, die alle `@SecureRoute`-annotierten Klassen aufzählt. Sie hat eine Default-Implementierung, die Vaadins `RouteConfiguration.getAvailableRoutes()` benutzt; Konsumenten ohne diesen Hook (z. B. Tests, Lazy-Loading) bleiben beim V00.72-Verhalten (Prüfung erst zur Route-Visit-Zeit). Findet der Hook einen Mismatch → `secure-route/unknown-policy` als deterministischer STRICT-Fehler vor dem ersten Route-Visit; ohne Hook bleibt das ein Runtime-Warning.

### 8.5 STRICT-Regeln

- `secure-route/unknown-policy` (war V00.72 Warning) → STRICT-Exception.
- `policies/empty-registry` — `policies(...)` ohne tatsächlichen `register(...)`-Aufruf → INFO-Warning.

---

## 9. Baustein 4: Roles Sub-Builder

### 9.1 Problem

`RoleBootstrap.hierarchy(RoleHierarchy)` ist Recorded-only. Im aktuellen Core-Stand existiert ein Resolver-Setter für `RoleHierarchy`, aber keine globale Resolver-API für `RolePermissionMapping`. `RolePermissionResolver` ist eine Utility-Klasse, kein SPI.

### 9.2 Ziel

```java
.roles(r -> r
    .hierarchy(RoleHierarchy.builder()
        .role("ADMIN").includes("USER")
        .role("USER").includes("GUEST")
        .build())
)
```

### 9.3 API-Skizze

```java
public interface RoleBootstrap {
  RoleBootstrap hierarchy(RoleHierarchy hierarchy);
}
```

Wiring: `SecurityServiceResolver.setRoleHierarchy(...)`.

`RolePermissionMapping` bleibt für V00.73 bewusst außerhalb der Stable-Surface, solange kein eigener Resolver-Hook existiert. Wenn Rollen-zu-Permissions über den Bootstrap unterstützt werden soll, ist das ein eigener kleiner Core-SPI-Schnitt:

```java
// nur falls explizit in Scope genommen
SecurityServiceResolver.setRolePermissionMapping(RolePermissionMapping mapping)
SecurityServiceResolver.findRolePermissionMapping()
```

Ohne diese Core-Erweiterung darf das Konzept keine `.mapping(...)`-Methode als produktionsreif versprechen.

### 9.4 STRICT-Regeln

- `roles/missing-hierarchy` — `.roles(...)` ohne `.hierarchy(...)` → INFO-Warning.
- `roles/hierarchy-cycle` — wenn `RoleHierarchy.builder().build()` einen Zyklus enthielte (RoleHierarchy validiert selbst) → bereits via V00.70-Logik; V00.73 leitet die Exception als `SecurityBootstrapException` durch.

---

## 10. Baustein 5: Credentials Sub-Builder

### 10.1 Problem

`CredentialBootstrap.pbkdf2Defaults()` ist Recorded-only. Der Quellstand enthält zwei Credential-Welten:

- die ältere Resolver-API `SecurityServiceResolver.setPasswordHashingService(PasswordHasher)`,
- die V00.71-Credential-Pipeline mit `PasswordHashingService`, `CredentialStore`, `PasswordChangeService`, `PasswordResetService`, `PepperService`.

V00.73 darf diese beiden Ebenen nicht unklar vermischen. Die Sub-Builder-Surface unterscheidet daher explizit zwischen dem legacy-kompatiblen `PasswordHasher`-Resolverpfad und der V00.71-Credential-Pipeline.

### 10.2 Ziel

```java
.credentials(c -> c
    .passwordHasher(new Pbkdf2PasswordHasher())    // legacy Resolver-Pfad
    .hashing(PasswordHashingServices.defaults())   // V00.71 Credential-Pipeline
    .pepper(pepperService)
    .credentialStore(credentialStore)
    .passwordChange(passwordChangeService)
    .passwordReset(passwordResetService)
)
```

### 10.3 API-Skizze

```java
public interface CredentialBootstrap {
  CredentialBootstrap passwordHasher(PasswordHasher hasher);
  CredentialBootstrap hashing(PasswordHashingService service);
  CredentialBootstrap pbkdf2Defaults();           // setzt PasswordHasher und V00.71 defaults, sofern moeglich
  CredentialBootstrap modern();                   // = .hashing(BouncyCastleHashingServices.modern())
                                                  //   wirft, wenn security-crypto-bc fehlt
  CredentialBootstrap pepper(PepperService service);
  CredentialBootstrap credentialStore(CredentialStore store);
  CredentialBootstrap passwordChange(PasswordChangeService service);
  CredentialBootstrap passwordReset(PasswordResetService service);
}
```

Wiring-Regeln:

- `.passwordHasher(...)` wird über `SecurityServiceResolver.setPasswordHashingService(...)` registriert.
- `.hashing(...)`, `.credentialStore(...)`, `.passwordChange(...)`, `.passwordReset(...)` werden im `BootstrapState` / `SecurityRuntime` als V00.71-Credential-Services verfügbar gemacht. Sie werden nicht über den alten `PasswordHasher`-Setter gequetscht.
- `.pbkdf2Defaults()` ist eine Convenience-Methode. **Sie setzt beide Defaults gleichzeitig**: `Pbkdf2PasswordHasher` über den Legacy-Resolver-Setter UND `PasswordHashingServices.defaults(...)` in den DX-State. `SecurityRuntime.services()` listet beide separat — Legacy unter `PasswordHasher.class`, Pipeline unter `PasswordHashingService.class` — damit ein Konsument im Audit sieht, dass nichts implizit ist. Konsumenten, die nur einen Pfad wollen, nutzen `.passwordHasher(...)` ODER `.hashing(...)` direkt statt `.pbkdf2Defaults()`.
- `.modern()` darf nur die V00.71-Pipeline konfigurieren, sofern `security-crypto-bc` vorhanden ist. Sie darf keinen stillen Fallback auf PBKDF2 durchführen.

### 10.4 STRICT-Regeln

- `credentials/missing-hashing` — `.passwordChange(...)` oder `.passwordReset(...)` ohne `.hashing(...)` → STRICT wirft (die Services brauchen ein gehashtes Backend).
- `credentials/legacy-hasher-and-pipeline-diverge` — `.passwordHasher(...)` und `.hashing(...)` sind beide gesetzt, aber nicht als bewusst getrennte Pfade dokumentiert → PRODUCTION warnt; STRICT wirft nur bei widersprüchlicher Default-Konfiguration.
- `credentials/modern-without-bc` — `.modern()` aufgerufen, aber `security-crypto-bc` nicht auf dem Classpath → STRICT wirft mit konkretem Maven-Snippet als Fix.

---

## 11. Baustein 6: Wrapper-Index-Writer (`security-processor`)

### 11.1 Problem

V00.72 hat den `WrapperIndexReader` in `security-dx` geliefert; der entsprechende Writer in `security-processor` wurde explizit nach V00.73 verschoben (Konzept-V00.72 §10.2). `SecurityProcessorReport.wrappers()` ist daher heute in Demos leer.

### 11.2 Ziel

`SecuredAnnotationProcessor` schreibt nach erfolgreicher Wrapper-Generierung eine Index-Zeile pro `@Secured`-Klasse:

```text
META-INF/security-for-flow/generated-wrappers.idx
```

Format wie V00.72 definiert:

```text
sourceFqn:generatedFqn:processor:proxyBuilderVer:method1,method2,...
```

### 11.3 Implementierungsdetails

- Append-Modus pro Compilation-Round.
- Marker-Comment-Line am Anfang (analog zu `security-autoservice-processor`).
- Idempotent über inkrementelle Builds.
- Dedup auf (sourceFqn, generatedFqn).
- Wenn das Generieren eines Wrappers fehlschlägt, wird **kein** Index-Eintrag geschrieben (verhindert `secured-without-wrapper`-Warnings für tatsächlich nicht generierte Wrapper).

### 11.4 V00.72-Reader bleibt unverändert

`WrapperIndexReader.read(ClassLoader)` parst das gleiche Format. Demos sehen ab V00.73 echte Wrapper-Einträge in `SecurityDiagnostics.inspect().processorReport()`.

### 11.5 STRICT-Regeln

Unverändert zu V00.72: `secured-without-wrapper` → STRICT-Exception. Mit V00.73-Writer fallen die meisten dieser Warnings weg, weil Wrapper jetzt zuverlässig indexiert sind.

---

## 12. Baustein 7: Stable-API-Promotion

### 12.1 Problem

Alle V00.72-Public-Typen tragen `@ExperimentalSecurityApi`. Konsumenten zögern, die API als Long-Term-Setup zu adoptieren.

### 12.2 Ziel

Jeder Typ wird zur V00.73-Release-Zeit einzeln bewertet:

- **Promote**: `@ExperimentalSecurityApi` entfernt; Typ ist Stable, gilt SemVer.
- **Behalten**: Typ bleibt experimentell, mit Begründung im JavaDoc warum.

### 12.3 Promote-Kandidaten (nur nach erfolgreichem Wiring-Audit)

- `SecurityBootstrap`-Facaden (`VaadinSecurity`, `RestSecurity`, `StandaloneSecurity`)
- `CommonSecurityBootstrap<B>` + die drei Adapter-Sub-Interfaces, sofern ihre Methoden nach V00.73 keine recorded-only Semantik mehr haben
- `SecurityRuntime`, `SecurityBootstrapMode`, `SecurityBootstrapException`, `Severity`, `RegisteredSecurityService`, `SecurityBootstrapWarning`
- `SecurityDiagnostics` + `SecurityServiceReport`, `DiscoveredService`, `MissingRecommendedService`, `DuplicateService`, `ServiceWarning`
- `DiagnosticContributor` SPI + `DiagnosticReportBuilder`
- `@SecurityAutoService` (war schon stable durch SOURCE-Retention; reine Form-Promotion)
- `SecuredUi`, `@SecureRoute`, `VaadinSecurityStarter`, sofern Policy-Integration und Fehlerverhalten vollständig getestet sind
- Adapter-DiagnosticContributors (Vaadin/REST/Standalone)

### 12.4 Behalten-Kandidaten (mit Begründung)

- `SecurityProcessorReport` + `GeneratedSecurityWrapper` + `ProcessorWarning` — bleiben experimentell, weil das Wrapper-Index-Format mit V00.75 (Event-Bus-Wrapper) erweitert wird.
- `BootstrapState` + `AbstractSecurityBootstrap` im `internal`-Paket — bleiben experimentell und sind als "internal" dokumentiert.
- `CredentialBootstrap` bleibt experimentell, falls V00.73 die Trennung zwischen `PasswordHasher` und `PasswordHashingService` nicht vollständig stabilisieren kann.
- `RoleBootstrap` bleibt experimentell, falls nur `RoleHierarchy` wired und `RolePermissionMapping` bewusst ausgelassen wird.

### 12.5 Stability-Vertrag

Konsumenten der Stable-API bekommen:
- **Keine Breaking-Changes** in V00.73.x-Bugfix-Releases.
- **Deprecation-Cycle** mindestens eine Minor-Version vor Removal.
- **JavaDoc** dokumentiert `@since 00.72.00` und `@apiNote` wo nötig.

---

## 13. Validierung und Fehlermeldungen

V00.73 ergänzt diese stabilen Warning-Codes (zusätzlich zu V00.72):

| Code | Auslöser | STRICT |
|---|---|:---:|
| `audit/missing-service` | `.audit(...)` ohne Auswahl-Methode | ✓ |
| `audit/store-backed-without-store` | `.storeBacked(null)` | ✓ |
| `sessions/missing-store` | `.timeout(...)` ohne `.storeBacked(...)` | ✓ |
| `sessions/invalid-timeout` | `timeout` / `absoluteLifetime` ist `null`, negativ oder `Duration.ZERO` | ✓ |
| `sessions/session-management-view-without-session-store` | `.sessionManagementView()` + keine Session-Konfiguration | ✓ (war V00.72-Warning) |
| `secure-route/unknown-policy` | `@SecureRoute(policy="x")` und PolicyRegistry kennt "x" nicht (deterministisch zur Bootstrap-Zeit, sofern Route-Discovery möglich) | ✓ (war V00.72-Warning) |
| `policies/empty-registry` | `.policies(p -> {})` ohne `register(...)`-Aufruf — niedrige Priorität, gerne ganz droppen falls Implementierung Lärm produziert | INFO (optional) |
| `standalone/sessions-not-applicable` | `.sessions(...)` an `StandaloneSecurityBootstrap` aufgerufen (CLI hat keine Session-Semantik) | INFO |
| `roles/missing-hierarchy` | `.roles(...)` ohne `.hierarchy(...)` | INFO |
| `roles/hierarchy-cycle` | RoleHierarchy enthält Zyklus | ✓ |
| `credentials/missing-hashing` | `.passwordChange/.passwordReset(...)` ohne `.hashing(...)` | ✓ |
| `credentials/legacy-hasher-and-pipeline-diverge` | Legacy-Hasher und V00.71-Pipeline widersprechen sich | abhängig vom Modus |
| `credentials/modern-without-bc` | `.modern()` und `security-crypto-bc` fehlt | ✓ |

---

## 14. Phasenplan und Migration

### Phase 1 — Wrapper-Index-Writer (klein, isoliert)
- `security-processor` ergänzen
- Demo-Smoke-Test: `demo-standalone` druckt `MemberDirectorySecured` im `SecurityRuntime.log()`

### Phase 2 — Audit + Sessions + Credentials + Roles Sub-Builder
- Audit vollständig gegen vorhandene Core-Typen (`AuditEventStore`, `AuditSink`, `CompositeAuditService`) verdrahten
- Sessions inkl. `SessionManagementView`-Aktivierung und `VaadinSessionSubjectStore`-Auto-Wiring (`security-dx-vaadin`)
- Credentials mit klar getrennter Legacy-Hasher- und V00.71-Pipeline-Semantik umsetzen
- Roles zunächst nur `RoleHierarchy` produktionsreif machen; Mapping nur bei expliziter Core-SPI-Erweiterung
- Tests + STRICT-Regeln pro Sub-Builder

### Phase 3 — Policies Sub-Builder + SecuredUi.requiresPolicy
- Größter Sub-Builder
- `SecuredUi.requiresPolicy(...)` echt
- `@SecureRoute(policy=...)` echt
- `demo-vaadin-rest-client/DemoPolicyInitListener.registerDemoPolicies()` wird zur Lambda im `.policies(...)`-Aufruf

### Phase 4 — Stable-API-Promotion
- `@ExperimentalSecurityApi` nur aus erfolgreich auditierten Promote-Kandidaten entfernen
- Behalten-Kandidaten dokumentieren
- `RELEASE-NOTES-00.73.00.md` finalisieren
- `CLAUDE.md` aktualisieren

### Phase 5 — Demo-Migrationen (optional, je Demo separat)
- Jede der vier Demos zeigt nach V00.73 den vollständigen Fluent-Pfad
- Manuelle V00.71-`SecurityServiceResolver`-Aufrufe wo möglich durch Sub-Builder ersetzt

---

## 15. Akzeptanzkriterien

- Alle fünf Sub-Builder haben konkrete typisierte Methoden statt Platzhaltern; bewusst ausgelassene Methoden sind dokumentiert und bleiben experimentell.
- `install()` wired jeden Sub-Builder-Aufruf entweder in den entsprechenden `SecurityServiceResolver`-Setter / Registry-Aufruf oder in eine dokumentierte Adapter-/Runtime-Struktur, wenn kein Core-Setter existiert.
- STRICT-Mode raised für jede der documented Validierungs-Codes.
- `security-processor` schreibt `generated-wrappers.idx`; `SecurityDiagnostics.inspect()` listet die Wrapper.
- `SecuredUi.requiresPolicy(...)` und `@SecureRoute(policy=...)` evaluieren echt gegen `PolicyRegistry`.
- `demo-vaadin-rest-client/DemoPolicyInitListener` ist eine reine Fluent-Bootstrap-Datei ohne direkte `SecurityServiceResolver.policyRegistry()`-Aufrufe.
- Jeder V00.72-Public-DX-Typ hat eine Promote-/Keep-Entscheidung mit Begründung. Es gibt kein Mindestprozent; Stabilität geht vor Quote.
- Alle bestehenden Tests (`security-core`, `security-vaadin`, `security-rest`, `security-standalone`, `security-processor`, V00.72-DX-Module) bleiben grün.
- Mutation-Coverage der V00.71-Module sinkt durch V00.73 nicht.
- Voller Reactor (23+ Module): `./mvnw clean install` ist grün.

---

## 16. Risiken und Gegenmassnahmen

| Risiko | Gegenmassnahme |
|---|---|
| Sub-Builder-Wiring überschreibt eine vorher direkt registrierte SPI | `BootstrapState` merkt sich, ob ein Wert aus `.audit/.sessions/...` kommt; `install()` warnt, wenn der Resolver schon einen anderen Wert hatte (`duplicate-service-overridden` mit `Severity.INFO`) |
| Stable-Promotion zu früh | Pro Typ einzeln entscheiden; bei Unsicherheit experimentell lassen mit klarer JavaDoc-Begründung |
| Credential-API vermischt `PasswordHasher` und `PasswordHashingService` | Zwei Pfade explizit modellieren: legacy Resolver-Setter fuer `PasswordHasher`, V00.71-Pipeline als Runtime-/Adapter-Service |
| RoleBootstrap verspricht Mapping ohne Resolver-Hook | V00.73 stabilisiert nur `RoleHierarchy`; Mapping nur mit expliziter Core-SPI-Erweiterung |
| SessionStore kann nicht global über `SecurityServiceResolver` gesetzt werden | `SessionStore` bleibt in `BootstrapState` / `SecurityRuntime` und wird adapter-spezifisch konsumiert; kein versteckter Core-Setter |
| Vaadin `SessionManagementView` wird ohne Konstruktorabhängigkeiten registriert | Route-/Factory-Strategie vor Implementierung festlegen; STRICT blockiert fehlenden `SessionStore` |
| Wrapper-Index-Writer bricht den existierenden `security-processor` | Schreiben passiert in einem separaten Round-Handler nach erfolgreicher Wrapper-Generierung; Failure beim Index-Write ist `Diagnostic.Kind.WARNING`, nicht ERROR |
| Policy-DSL-Wrapper in `.policies(...)` zieht Policy-Module-Imports in `security-dx` | Nur konkrete `Policy`-Typen werden referenziert (keine Builder-Wrapper); `Policy.named(...)` bleibt der Konstruktor und liegt in `security-core/policy/api` |
| STRICT-Regel-Verschärfung bricht V00.72-Konsumenten | Jede neue STRICT-Regel wird explizit dokumentiert; V00.72-Demos werden im Phase-6-Schritt geprüft |
| Demo-Tests brauchen DX-Test-Helfer, die in `security-test` nicht hingehören | Helpers landen in `security-dx/src/test/.../testsupport/` und werden über Maven-Test-Jar (`<classifier>tests</classifier>`) bereitgestellt; eigenes `security-dx-test`-Modul nur bei echtem Cross-Modul-Reuse-Bedarf |
| `BootstrapState` wird zum Gott-Objekt | In V00.73 in Sub-Aggregate aufgeteilt (`AuditState`, `SessionState`, …); Methoden auf `BootstrapState` delegieren in die Sub-Aggregate |
| Adapter-spezifische No-ops verwirren Aufrufer | Adapter-Symmetrie-Tabelle in §4.1 dokumentiert genau, was wo passiert; INFO-Warning `standalone/sessions-not-applicable` macht das Verhalten sichtbar |
| `SecuredUi.requiresPolicy` läuft asynchron / outside-of-session | PolicyRegistry-Lookup ist synchron und thread-safe; existierende V00.70-Garantie |

---

## 17. Beziehung zu V00.70 / V00.71 / V00.72 / V00.75 / V00.80

- **V00.70** liefert PolicyRegistry, ResourceResolverRegistry, RoleHierarchy. V00.73 wrappt sie über Sub-Builder; V00.70 selbst bleibt unverändert.
- **V00.71** liefert Credential-Services. V00.73 wrappt sie über `.credentials(...)`; V00.71 bleibt unverändert.
- **V00.72** liefert die DX-Surface. V00.73 vervollständigt sie und macht sie stable.
- **V00.75** (Security Event Bus) wird einen sechsten Sub-Builder `.eventBus(...)` einführen — V00.73 hält die Sub-Builder-Topologie offen dafür.
- **V00.80** (MFA, OIDC) wird über die etablierte Profile-Mechanik integrieren (`MfaSecurity.bootstrap()` / `OidcSecurity.bootstrap()`). Die V00.73-Stable-API ist die Anker-Surface dafür.

---

## 18. Empfohlener erster Implementierungsschnitt

1. **Phase 1** (Wrapper-Index-Writer) komplett. Klein, isoliert, kein Risiko für die DX-Surface.
2. **Phase 2a**: `audit` Sub-Builder. Übersichtlich, vorhandene Core-Typen, kein Adapter-spezifisches Verhalten. Vollständig durchziehen: API + Wiring + STRICT + Tests + ein Demo-Lambda.
3. **Phase 2b**: `sessions` (inkl. `SessionManagementView`-Aktivierung + `VaadinSessionSubjectStore`-Auto-Wiring). Hier wird die wichtige Adapter-Frage `SessionStore` ohne Resolver-Setter sauber gelöst.
4. **Phase 2c**: `credentials`, weil hier die V00.71-Pipeline-vs-Legacy-Trennung explizit modelliert wird.
5. **Phase 2d**: `roles` (nur `RoleHierarchy`), weil bewusst klein und nach `credentials` einfach abzugrenzen.
6. **Phase 3**: `policies` zuletzt, weil `SecuredUi.requiresPolicy(...)` und `@SecureRoute(policy=...)` direkt auf eine korrekte Registry-Verdrahtung angewiesen sind.
7. **Phase 4**: Demo-Migrationen + Stable-API-Promotion + RELEASE-NOTES + PIT.

Diese Reihenfolge ist die kanonische — sie ist deckungsgleich mit §14 und der Milestone-Tabelle im Implementierungsplan §5.

---

## 19. Ergebnisbild

Nach V00.73 ist ein Konsumenten-Setup-File ungefähr so kompakt:

```java
@SecurityAutoService(AuthenticationService.class)
public class MyAuthn implements AuthenticationService<Credentials, MyUser> { /* ... */ }

@SecurityAutoService(AuthorizationService.class)
public class MyAuthz implements AuthorizationService<MyUser> { /* ... */ }

public class SecurityInit implements VaadinServiceInitListener {
  @Override public void serviceInit(ServiceInitEvent event) {
    VaadinSecurity.bootstrap()
        .use(VaadinSecurityStarter.productionDefaults())
        .authentication(ServiceLoader.load(AuthenticationService.class).findFirst().orElseThrow())
        .authorization(ServiceLoader.load(AuthorizationService.class).findFirst().orElseThrow())
        .loginRoute("login").stepUpRoute("step-up")
        .sessions(s -> s.storeBacked(sessionStore).timeout(Duration.ofMinutes(30)))
        .policies(p -> p
            .register(Policy.named("doc.owner-or-admin").allowIf(...).deny("...").build())
            .resourceResolver(new DocumentResolver()))
        .roles(r -> r.hierarchy(RoleHierarchy.builder().role("ADMIN").includes("USER").build()))
        .credentials(c -> c.pbkdf2Defaults().credentialStore(credentialStore))
        .audit(a -> a.storeBacked(auditEventStore).logging())
        .install();
  }
}
```

Das ist **das vollständige Security-Setup für eine Vaadin-App** entlang der V00.73-Stable-Surface. Kein Direct-Resolver-Aufruf im Anwendungscode, kein Mix aus V00.71- und V00.72-Style an den Stellen, die V00.73 produktionsreif verdrahtet. Typen, deren Core-Hooks noch nicht stabil genug sind, bleiben bewusst experimentell statt ein falsches Stabilitätsversprechen zu geben.

Das ist das eigentliche Versprechen aus V00.72 §17 — V00.73 löst es ein.
