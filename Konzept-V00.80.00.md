# Konzept V00.80.00: High-Security, Identity-Integration und Betrieb

> Zielbild: `v00.80.00` hebt das Framework von produktionsfähigen
> Security-Bausteinen auf einen High-Security- und Betriebsfokus.
> Schwerpunkt sind stärkere Authentifizierung, Identity Provider
> Integration, manipulationsresistenteres Audit, Monitoring und
> Incident-faehige Integrationen auf Basis des Security Event Bus aus
> `v00.75.00`.

## Leitmotiv

`v00.70.00` macht Policies, Persistenz und aktive Sessions
produktionsfaehig. `v00.75.00` ergaenzt den Security Event Bus mit
signierten Envelopes, Replay-Schutz, Sequencing pro Tenant und Producer,
Producer Policy, persistenten Stores und REST/SSE Bridge. `v00.80.00`
baut darauf auf und adressiert Systeme mit hoeherem Schutzbedarf: starke
Authentifizierung, externe Identitaeten, Forensik, Betriebsintegration
und klare Hardening-Modi.

`FEATURES.md` beschreibt OAuth2/OIDC/SAML/LDAP/Kerberos und
Cluster-Mode für `00.60.00` bewusst als nicht im Scope. `v00.80.00`
nimmt diese Negativliste nicht komplett zurück, sondern wählt daraus
gezielt High-Security- und Betriebsbausteine: OIDC/OAuth2 Bridge,
Monitoring, EventBus-Integrationen, Web-Hardening und auditierbare
Integrationen.

Auch in dieser Version bleibt das Framework pluggable. High-Security
Features werden als optionale Module und SPIs ergänzt, nicht als
unvermeidbare Komplexität für einfache Anwendungen.

## Kernziele

### 1. MFA und Step-Up Authentication

Das Framework erhält ein SPI für Mehrfaktor-Authentifizierung und
Step-Up-Entscheidungen.

Ziele:

- `MfaService`
- `StepUpPolicy`
- `StepUpChallenge`
- `StepUpDecision`
- Integration in Policy DSL über `StepUpRequired`
- Security Events fuer MFA-Erfolg, MFA-Fehler und Step-Up-Anforderung
- Audit-faehige EventBus-Integration fuer kritische MFA-Entscheidungen

Beispiel:

```java
Policy.named("admin.user-delete")
    .when(Action.is("user:delete"))
    .require(SubjectPredicates.hasPermission("admin:users:delete"))
    .requireStepUp("mfa", Duration.ofMinutes(5))
    .deny("User deletion requires recent MFA");
```

Der erste Scope kann TOTP und Recovery Codes vorsehen. WebAuthn/Passkeys
können als separates Modul folgen oder direkt als experimenteller
Adapter starten.

Relevante EventBus-Events:

```text
MfaChallengeCreatedEvent
MfaChallengeSucceededEvent
MfaChallengeFailedEvent
StepUpRequiredEvent
StepUpSucceededEvent
StepUpFailedEvent
RecoveryCodeUsedEvent
```

### 2. WebAuthn / Passkeys

Passkeys sind für High-Security und moderne UX ein wichtiger
Ausbaupfad. Das Framework sollte eine Integrationsschicht bereitstellen,
ohne eine konkrete UI oder Datenbank zu erzwingen.

Geplante Bausteine:

```text
WebAuthnCredentialStore
WebAuthnChallengeStore
PasskeyRegistrationFlow
PasskeyAuthenticationFlow
```

Wichtige Anforderungen:

- Credentials nie als Klartext-Secret behandeln.
- Challenge-Lifetime strikt begrenzen.
- Device-/Credential-Metadaten als Security Events publizieren.
- Recovery- und Deaktivierungsprozesse definieren.

### 3. OIDC/OAuth2 Bridge

Das Framework soll externe Identity Provider anbinden können, ohne
selbst zu einem vollständigen OIDC-Stack zu werden.

Der 00.60.00-Katalog grenzt OAuth2/OIDC/SAML/LDAP/Kerberos bewusst aus
dem Kern aus. `v00.80.00` bleibt bei dieser Linie: Die Bridge übersetzt
externe Identität in interne Subjects, Rollen, Permissions und Tenants,
ersetzt aber keine etablierten Identity-Provider-Clients.

Ziel:

- Externe Claims werden in interne `JSentinelSubject`, Rollen,
  Permissions und Tenant-Kontext übersetzt.
- Die interne Autorisierung bleibt Framework-eigen.
- Token- und Session-Verarbeitung bleiben klar getrennt.

Mögliche SPIs:

```text
ExternalIdentityResolver
ClaimsToSubjectMapper
ClaimsToRolesMapper
ClaimsToTenantMapper
IdentityProviderSessionLink
```

Relevante EventBus-Events:

```text
ExternalIdentityLinkedEvent
ExternalIdentityLoginSucceededEvent
ExternalIdentityLoginFailedEvent
ExternalClaimsMappedEvent
ExternalIdentitySessionLinkedEvent
ExternalIdentitySessionRevokedEvent
```

Nicht-Ziel:

- Kein vollständiger Ersatz für etablierte OIDC-Clients.
- Kein harter Zwang zu Keycloak, Entra ID, Auth0 oder einem bestimmten
  Provider.

### 4. Device- und Remember-Me-Management

Auf Basis der in `v00.70.00` vorbereiteten Store-Interfaces wird
Device- und Remember-Me-Management produktionsreif ausgebaut.

Ziele:

- Vertrauenswürdige Geräte anzeigen und widerrufen.
- Remember-Me-Tokens rotieren.
- Tokens nur gehasht oder als Fingerprint speichern.
- Geräte tenant-aware und subject-aware verwalten.
- Verdächtige Geräte gezielt invalidieren.
- Step-Up erzwingen, wenn ein neues oder riskantes Gerät verwendet wird.
- Device- und Token-Statusaenderungen ueber den Security Event Bus an
  aktive Adapter verteilen.

Geplante Services:

```text
DeviceRegistry
RememberMeService
RememberMeTokenHasher
DeviceRiskEvaluator
```

Relevante EventBus-Events:

```text
DeviceTrustedEvent
DeviceRevokedEvent
RememberMeTokenIssuedEvent
RememberMeTokenUsedEvent
RememberMeTokenRevokedEvent
RefreshTokenRotatedEvent
RefreshTokenReuseDetectedEvent
```

### 5. Risk-Based Authentication

Login-Entscheidungen sollen Risikosignale berücksichtigen können.

Mögliche Signale:

- neue IP-Adresse
- unbekanntes Gerät
- ungewöhnliche Uhrzeit
- auffällige Fehlversuche
- Tenant-Wechsel
- neue Region
- alte oder riskante Session

Entscheidungen:

```text
Allow
Deny
Delay
StepUpRequired
Lockout
```

Der Fokus liegt auf klarer Nachvollziehbarkeit. Jede Risk-Entscheidung
muss auditierbar und erklärbar sein.

Risk-Based Authentication nutzt den Security Event Bus sowohl als Quelle
als auch als Senke. Der Risk-Service konsumiert Login-, Device-,
Session-, Token- und Rate-Limit-Events und publiziert nachvollziehbare
Risk-Entscheidungen.

Konsumierte Events:

```text
LoginFailedEvent
LoginSucceededEvent
DeviceTrustedEvent
DeviceRevokedEvent
RateLimitExceededEvent
SuspiciousLoginDetectedEvent
SessionJSentinelVersionOutdatedEvent
```

Publizierte Events:

```text
RiskScoreChangedEvent
RiskDecisionMadeEvent
StepUpRequiredEvent
AccountTemporarilyLockedEvent
```

### 6. Password Hardening

Das Passwort-Subsystem wird weiter gehärtet.

Ziele:

- Argon2id als zusätzlicher `PasswordHasher`.
- Pepper-Support über separates Secret.
- Hash-Policy-Versionierung.
- automatische Rehash-Migration.
- Passwort-Blocklisten.
- Security Events fuer Policy-Verletzungen ohne Secret Leakage.

Wichtig:

Der Core darf kein Secret Management erzwingen. Pepper-Bereitstellung
erfolgt über ein SPI, z. B. `PasswordPepperProvider`.

### 7. Tamper-Evident Audit

Audit wird für forensische und Compliance-Szenarien erweitert.

Ziele:

- Hash-Chaining von Audit-Events.
- Signierte Audit-Batches.
- append-only Store-Modell.
- verifizierbare Exporte.
- Audit-Integrity-Checks.

Mögliche Typen:

```text
AuditChainStore
AuditIntegrityVerifier
SignedAuditBatch
AuditExportService
```

Dieses Feature ergänzt persistentes Audit aus `v00.70.00`, ersetzt es
aber nicht.

Der Security Event Bus aus `v00.75.00` liefert Integritaet,
Authentizitaet und Replay-Schutz fuer transportierte Events. Das ersetzt
nicht die Audit-Hash-Chain. Die Aufgaben bleiben getrennt:

```text
EventBus-Signatur: Authentizitaet und Integritaet des Events beim Transport.
Audit-Hash-Chain: manipulationsresistente historische Ablage.
```

V00.80.00 sollte einen `AuditIntegrityListener` ergaenzen, der
audit-relevante Security Events konsumiert und daraus hash-verkettete
Audit-Eintraege oder signierte Audit-Batches erzeugt.

### 8. Security Event Integrations

Der Security Event Bus wird in `v00.75.00` eingefuehrt. `v00.80.00`
nutzt diese Infrastruktur fuer produktive Betriebs-, Monitoring-,
Alerting- und Integrationsszenarien.

Ziel:

- Security Events an Monitoring, SIEM, Alerting, Webhooks oder
  Incident-Prozesse senden.
- Audit bleibt historischer Nachweis.
- Der Event Bus ermoeglicht operative Reaktion.
- Signierte Envelopes aus `v00.75.00` bleiben die gemeinsame
  Integrationsbasis.

Relevante Integrationen:

```text
LoggingEventPublisher
WebhookEventPublisher
OpenTelemetryEventPublisher
SiemEventExporter
JSentinelAlertPublisher
EventStreamPublisher
```

EventBus-Fehler werden selbst beobachtbar:

```text
JSentinelEventEnvelopeRejectedEvent
JSentinelEventReplayDetectedEvent
JSentinelEventSignatureInvalidEvent
JSentinelEventSequenceViolationEvent
JSentinelEventListenerFailedEvent
JSentinelEventDeadLetteredEvent
```

### 9. Betrieb und Monitoring

Das Framework soll klare Betriebsmetriken und Health-Signale liefern.

`FEATURES.md` listet bereits Test-, Mutation-Coverage- und
Versionsdaten. `v00.80.00` ergänzt dazu Laufzeitmetriken und
Health-Signale, damit produktive Systeme nicht nur getestet, sondern
auch betrieben und überwacht werden können.

Metriken:

- Login-Erfolge und Fehler
- Lockout-Zähler
- Denied Decisions
- MFA-Erfolg/Fehler
- aktive Sessions
- widerrufene Sessions
- Audit-Store-Lag
- Event-Bus-Fehler
- publizierte Security Events
- abgelehnte Envelopes
- Replay-Erkennungen
- Sequenzverletzungen
- ungueltige Signaturen
- Dead-Letter-Eintraege
- Listener-Fehler
- aktive SSE-Verbindungen
- SSE-Reconnects

Konkrete Metriknamen:

```text
security.eventbus.published.total
security.eventbus.rejected.total
security.eventbus.replay.detected.total
security.eventbus.sequence.violation.total
security.eventbus.signature.invalid.total
security.eventbus.deadletter.total
security.eventbus.listener.failure.total
security.eventbus.sse.connections.active
security.eventbus.sse.reconnects.total
```

SPIs:

```text
JSentinelMetricsPublisher
JSentinelHealthIndicator
JSentinelDiagnostics
```

Ziel ist kein großer Monitoring-Stack, sondern saubere Exportpunkte.

### 10. Fail-Closed Strict Mode

High-Security-Installationen brauchen sichere Defaults bei
Fehlkonfiguration.

Strict Mode Verhalten:

- fehlendes SPI führt zu Deny statt Allow
- unbekannte Permission führt zu Deny
- unbekannte Policy führt zu Deny
- Evaluator-Fehler führt zu Deny
- Audit-Fehler kann je nach Konfiguration blockieren oder alarmieren
- unklassifizierte Route kann blockiert werden
- ungueltige Event-Signatur fuehrt zu Reject
- unbekannter Signing Key fuehrt zu Reject
- erkannter Replay fuehrt zu Reject und kritischem Security Event
- Sequenzverletzung fuehrt zu Reject oder Dead Letter
- nicht erlaubter Producer fuehrt zu Reject
- fehlende `TenantId` fuehrt zu Reject
- fehlender kritischer Listener kann Fail-Closed ausloesen

Wichtig:

Strict Mode braucht sehr gute Fehlermeldungen. Betreiber müssen schnell
erkennen können, welche Konfiguration fehlt.

### 11. Supply-Chain und Release Hardening

Für ein Security-Framework ist die Lieferkette Teil des Produkts.

Ziele:

- SBOM als Release-Artefakt.
- Dependency-Allowlist.
- CVE-Gates.
- signierte Artefakte.
- reproduzierbare Builds prüfen.
- Provenance/SLSA-Vorbereitung.
- Release-Checklist für Security-relevante Änderungen.

### 12. CSRF- und Web-Adapter-Hardening

Die Feature-Ideen nach `v00.60.00` nennen CSRF-Schutz für
`jSentinel-vaadin` und `jSentinel-rest`. Dieser Punkt passt in den
High-Security-Scope, weil er adapter- und deploymentabhängig ist und
saubere Defaults braucht.

Mögliche Strategien:

```text
OriginHeaderCheck
DoubleSubmitCookie
CsrfTokenStore
CsrfProtectionPolicy
```

Ziele:

- CSRF-Schutz als optionales SPI für REST- und Vaadin-nahe Flows.
- sichere Defaults für state-changing Requests.
- klare Opt-outs für reine Bearer-Token-APIs.
- Audit-/Monitoring-Signal bei CSRF-Denials.

### 13. Privacy, Retention, Backup und Restore

Die Ideenliste nennt GDPR/Recht auf Vergessenwerden, Soft Delete,
Retention Policies sowie Backup-/Restore-Endpunkte. Diese Punkte
gehören in den Betriebs- und Compliance-Scope von `v00.80.00`.

Geplante Bausteine:

```text
UserAnonymizationService
RetentionPolicy
SoftDeletePolicy
JSentinelBackupService
JSentinelRestoreService
```

Ziele:

- PII kann anonymisiert werden, während Audit-Nachweise erhalten
  bleiben.
- Benutzer und sicherheitsrelevante Records können soft-deleted werden.
- Retention Policies definieren Aufbewahrungsdauer und Löschverhalten.
- Backup/Restore ist administrativ geschützt und auditierbar.

### 14. Weitere Integrationsmodule

Nicht alle Ideen sollten in `v00.80.00` Kernumfang werden. Einige
bleiben bewusst optionale Erweiterungen.

Kandidaten:

```text
security-quarkus
security-persistence-jdbc
security-persistence-redis
security-persistence-eventstream
```

Der Quarkus-Adapter ist fachlich sinnvoll, sollte aber erst entstehen,
wenn Policy API, Persistence API und Identity Bridge stabil genug sind,
damit der Adapter nicht gegen bewegliche Zielscheiben implementiert
wird.

`security-javafx` bleibt weiterhin kein eigenes Kernziel. Der bestehende
Standalone-Adapter deckt Desktop-/CLI-Szenarien funktional ab; ein
JavaFX-spezifisches Modul wäre erst bei realem UI-Lifecycle-Bedarf
sinnvoll.

## Empfohlene Modulstruktur

```text
security-core
security-vaadin
security-rest
security-standalone

security-persistence-eclipsestore

security-events
security-events-rest
security-events-testkit
security-events-persistence-eclipsestore

security-mfa-api
security-mfa-totp
security-webauthn
security-identity-oidc
security-monitoring
security-events-opentelemetry
security-events-webhook
security-events-siem
security-audit-integrity
security-privacy
security-web-hardening
```

Die Modulgrenzen sollten pragmatisch bleiben. APIs, die nur Interfaces
und Records enthalten, können im Core bleiben, solange sie keine
optionalen externen Abhängigkeiten einführen.

## Akzeptanzkriterien

- MFA/Step-Up ist über Policy Decisions integrierbar.
- OIDC/OAuth2 Bridge übersetzt externe Identität in interne Subjects.
- Remember-Me- und Device-Management nutzt keine Klartext-Tokens.
- Risk-Based Authentication ist auditierbar.
- Argon2id ist als PasswordHasher verfügbar.
- Tamper-Evident Audit kann Event-Ketten verifizieren.
- Der Security Event Bus aus `v00.75.00` wird fuer Monitoring, Risk,
  MFA, Device Management, Identity und Audit-Integrity genutzt.
- OpenTelemetry-, Webhook- und SIEM-Exporter verarbeiten signierte
  Security Event Envelopes.
- EventBus-Fehler, Replay-Erkennungen, Signaturfehler,
  Sequenzverletzungen und Dead Letters sind als Metriken sichtbar.
- Kritische EventBus-Verifikationsfehler erzeugen Alerts.
- Monitoring-Exportpunkte liefern nutzbare Betriebsdaten.
- Strict Mode ist dokumentiert und testbar.
- Supply-Chain-Prüfungen sind Teil der Release-Dokumentation.
- CSRF-Schutz ist für relevante Adapter als Policy/Filter-Grundlage
  vorhanden.
- Privacy-/Retention-Konzepte sind über SPIs abbildbar.

## Nicht-Ziele

- Kein vollständiges IAM-System.
- Keine Benutzerverwaltung für alle IdPs.
- Kein SIEM als Bestandteil des Frameworks.
- Kein Zwang zu WebAuthn für alle Anwendungen.
- Keine automatische Migration beliebiger Legacy-Identitäten.
- Keine harte Cloud-Provider-Bindung.
- Kein Quarkus-Adapter als Kernziel, solange Policy/Persistence/Identity
  APIs nicht stabil sind.
- Kein eigenes `security-javafx`, solange `jSentinel-standalone` die
  benötigten Desktop-Flows ausreichend abdeckt.

## Ergebnisbild

Nach `v00.80.00` ist das Framework für Anwendungen mit höherem
Schutzbedarf deutlich besser geeignet. Externe Identitäten können
angebunden werden, kritische Aktionen können Step-Up verlangen,
Audit-Daten können stärker abgesichert werden, und Betriebs-/Monitoring-
Systeme erhalten klare Integrationspunkte auf Basis des in `v00.75.00`
eingefuehrten Security Event Bus. Zusaetzlich sind Web-Hardening und
Privacy-/Retention-Anforderungen als optionale SPIs vorbereitet.

`v00.80.00` ist damit der Schritt von produktionsfähiger Security zu
High-Security Readiness.
