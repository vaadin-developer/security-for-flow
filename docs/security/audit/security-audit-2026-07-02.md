# Sicherheitsaudit jSentinel — 2026-07-02

## Zusammenfassung

Dieses Audit umfasst ausschließlich die projekt-neutralen Library-Module des jSentinel-Frameworks (`jSentinel-*`); die `demo-*`-Module wurden nur stichprobenartig zur Reachability-Prüfung herangezogen. Die Untersuchung erfolgte als Source-Review entlang von 12 Finder-Dimensionen (u. a. `jwt-jose`, `oauth2-core`, `oidc-identity`, `dpop`, `session-mgmt`, `authz-decision`, `credential-pipeline`, `rest-adapter`, `propagation`, `persistence-serialization`, `token-secret`, `crosscutting-rng-injection-leak`). Jeder Kandidat wurde anschließend adversarial verifiziert: widerlegte Befunde wurden entfernt, Schweregrade wurden gegen die real erreichbaren Codepfade korrigiert. Verbleiben 28 bestätigte bzw. kontextabhängige Findings.

Kern-Ergebnis: Es gibt **keine Critical/High-Findings**. Die vier Medium-Findings sind durchweg Secure-by-Default-Schwächen bzw. unvollständige Remediations auf ausgelieferten Pfaden (Session-Fixation, Mid-Session-Revocation, Audit-PII-Leak, JWKS-DoS). Der Großteil der Low/Info-Findings sind Härtungs- und Dokumentations-Konsistenzlücken auf experimentellen Opt-in-Oberflächen ohne bislang ausgelieferten verwundbaren Consumer.

| Severity | Anzahl |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 4 |
| Low | 15 |
| Info | 9 |
| **Gesamt** | **28** |

## Übersichtstabelle

| ID | Severity | Titel | Modul | CWE |
|---|---|---|---|---|
| JS-SEC-001 | Medium | Unknown-`kid` erzwingt JWKS-Refresh pro Request (fehlende Refresh-Drossel) | jSentinel-jwt | CWE-770 |
| JS-SEC-002 | Medium | Version-Drift-Reroute löscht Snapshot, aber nicht das Cached Subject | jSentinel-vaadin | CWE-613 |
| JS-SEC-003 | Medium | `LoginView` rotiert Session-ID nicht per Default (Session Fixation) | jSentinel-vaadin | CWE-384 |
| JS-SEC-004 | Medium | Session-Audit-`subjectId` weiterhin aus `subject.toString()` (PII-Leak) | jSentinel-core / jSentinel-vaadin | CWE-532 |
| JS-SEC-005 | Low | Versprochenes `claims/audience-empty`-INFO nie implementiert; `aud` bleibt optional | jSentinel-jwt | CWE-345 |
| JS-SEC-006 | Low | Introspection-Cache meldet `active=true` bis TTL über `exp` hinaus | jSentinel-oauth2 | CWE-613 |
| JS-SEC-007 | Low | `DefaultIdTokenValidator`: `expectedIssuer` tot, kein OIDC-Backstop für Single-Audience | jSentinel-identity-oidc | CWE-287 |
| JS-SEC-008 | Low | `InMemoryJtiStore` Soonest-Expiry-Eviction unter All-Fresh-Flood (DPoP-Replay) | jSentinel-core | CWE-294 |
| JS-SEC-009 | Low | Anti-Enumeration-Dummy-KDF nutzt Preferred- statt Stored-Algorithmus (Timing-Kanal) | jSentinel-core | CWE-208 |
| JS-SEC-010 | Low | `RequiresPermissionEvaluator` fail-open bei leerem `@RequiresPermission({})` | jSentinel-core | CWE-863 |
| JS-SEC-011 | Low | `RoleBasedAccessEvaluator` behandelt leere Rollenmenge als public (grants anonymous) | jSentinel-core | CWE-863 |
| JS-SEC-012 | Low | `StoreBackedLoginAttemptPolicy` deckt Spraying/Distributed-Stuffing nicht ab | jSentinel-core | CWE-307 |
| JS-SEC-013 | Low | `StepUpRequired.method()` unescaped in `WWW-Authenticate` (CRLF) | jSentinel-rest | CWE-113 |
| JS-SEC-014 | Low | `ClientCredentialsStrategy` Cache-Key ohne Scope (Cross-Scope-Kollision) | jSentinel-propagation-oidc | CWE-269 |
| JS-SEC-015 | Low | `InMemoryTokenExchangeCache` unbounded, nur Lazy-TTL-Eviction | jSentinel-propagation-oidc | CWE-770 |
| JS-SEC-016 | Low | `PERSISTENT_FILE`-Bootstrap-Token: keine Owner-only-ACL auf Non-POSIX | jSentinel-core | CWE-256 |
| JS-SEC-017 | Low | Eclipse-Store-Storage-Tree mit umask-Default (world-readable) angelegt | jSentinel-persistence-eclipsestore | CWE-276 |
| JS-SEC-018 | Low | `HttpJwksClient` ohne HTTPS-Guard auf dem Direkt-SPI-Pfad; falsche JavaDoc-Zusage | jSentinel-jwt | CWE-319 |
| JS-SEC-019 | Low | CRLF-Log-Injection über Decode-Fehlermeldung auf dem `events:publish`-Pfad | jSentinel-events-rest | CWE-117 |
| JS-SEC-020 | Info | EdDSA-Pfad ohne `crit`-Header-Rejection (RFC 7515 §4.1.11) | jSentinel-jwt | CWE-345 |
| JS-SEC-021 | Info | `DefaultLogoutTokenValidator`: store-loser Konstruktor deaktiviert Replay-Schutz | jSentinel-identity-oidc | CWE-294 |
| JS-SEC-022 | Info | `htu`-Normalisierung mit `URI.getPath` (Full-Decode) über-normalisiert | jSentinel-dpop | CWE-172 |
| JS-SEC-023 | Info | DPoP-`ath`-Check opt-in pro Call-Site ohne Fail-Closed-Default | jSentinel-dpop | CWE-345 |
| JS-SEC-024 | Info | Allow-by-Omission-Autorisierung (unannotierte Routes/Handler sind public) | jSentinel-vaadin | CWE-862 |
| JS-SEC-025 | Info | Credentialed-Origin-Lint übersieht `"null"`-Origin | jSentinel-dx-rest | CWE-942 |
| JS-SEC-026 | Info | `RestSecurity.bootstrap()` `decisionMapper`/`errorBodies` recorded-not-wired | jSentinel-dx-rest | CWE-1188 |
| JS-SEC-027 | Info | Drift-Snapshot-Capture ist Best-Effort-No-op auf dem Raw-`LoginView`-Pfad | jSentinel-vaadin | CWE-636 |
| JS-SEC-028 | Info | OIDC-Logout-Basisklasse delegiert lokalen Session-Teardown an Hook | jSentinel-identity-oidc-vaadin | CWE-613 |

## Findings

### JS-SEC-001 — Unknown-`kid` erzwingt JWKS-Refresh pro Request (fehlende Refresh-Drossel) (Medium)

**Modul/Datei:** `jSentinel-jwt` — `jSentinel-jwt/src/main/java/com/svenruppert/jsentinel/jwt/impl/HttpJwksClient.java:99-123, 194-203`

**CWE:** CWE-770: Allocation of Resources Without Limits or Throttling

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — im Gegenteil verspricht die Doku das Gegenteil (Konzept-V00.76.00 §16 fordert Negative-Cache-on-unknown-kid und „max 3 Refresh-Versuche pro Minute"; RELEASE-NOTES-00.76.00 behauptet „a JWKS client that cannot be turned into a DoS against the IDP").

**Beschreibung:** Der Negative-Cache öffnet sich nur bei Endpoint-**Failure**. Bei erfolgreichem Fetch setzt `apply()` `negativeUntil = Instant.EPOCH` (Zeile 198), also keinerlei Cooldown. Präsentiert ein Token einen `kid`, der in einem gesunden, frisch gecachten JWKS fehlt, greift weder der Fresh-plus-Contains-Kurzschluss (Zeile 113) noch das Negative-Window (Zeile 118, EPOCH liegt in der Vergangenheit), sodass `refreshOnce()` (Zeile 121) einen vollen synchronen ausgehenden HTTPS-GET auslöst. Die `kid`-Auflösung erfolgt in `validate()` Schritt 4 **vor** jeder Signaturprüfung (`NimbusJwtValidator.validate` Zeile 144), ist also für einen komplett unauthentifizierten Aufrufer erreichbar.

**Angriffsszenario:** Ein Angreifer sendet N Requests mit Header `{"alg":"RS256","kid":"rand-<i>"}` und Dummy-Payload/Signatur an einen jSentinel-geschützten Endpoint (kein gültiges Token nötig). Schritte 1–3 von `validate()` passieren (3 Segmente, RS256 allow-gelistet). Jeder distinkte `kid` erzwingt einen ausgehenden HTTPS-GET zum IdP-JWKS-Endpoint, der bis zu 10 s (`HTTP_TIMEOUT`) einen Worker-Thread blockiert. Sustained Distinct-`kid`-Traffic hält einen kontinuierlichen Refetch-Loop gegen den IdP (Amplification) und parkt den Handler-Thread-Pool (Self-DoS) — ohne Auth, ohne Rate-Limit.

**Bewertung (Medium):** Single-Flight (`refreshOnce()` Zeilen 131-143) kollabiert konkurrierende Bursts auf einen In-Flight-Fetch, IdP-Amplification ist damit ~1:1; ein langsamer/failing IdP läuft ins Timeout (10 s) und öffnet dann das 30-s-Negative-Window, was den Worst Case selbst begrenzt; die JWT-Stack-Typen sind `@ExperimentalJSentinelApi`. Nicht auf Low herabgestuft, weil vollständig unauthentifiziert, trivial auslösbar und im direkten Widerspruch zur ausdrücklichen Release-Notes-DoS-Zusage.

**Remediation / Härtung:** Die beiden im Konzept spezifizierten Drosseln implementieren. (1) Im SUCCESS-Zweig von `apply()` (Zeile 197-198): fehlt ein zuvor gesuchter `kid` weiterhin, ein kurzes Negative-Window (10–30 s) öffnen statt `negativeUntil = Instant.EPOCH`, sodass ein wirklich unbekannter `kid` aus dem aktuellen Snapshot als `UnknownKid` aufgelöst wird, statt erneut zu fetchen (Konzept Zeile 642). (2) Globales Refresh-Rate-Cap ergänzen (rollierender Zähler, „max 3 Refresh/min", Konzept Zeile 641). Beides hinter dem bestehenden Lock, ohne Kosten auf dem Hot-Path. Test ergänzen, der belegt, dass ein wiederholter/nie bekannter `kid` innerhalb des Cooldowns höchstens einen Refresh auslöst. Optional den unauthentifizierten Inbound-Pfad (`OidcInboundTokenValidator`) hinter den Rate-Limit-Service des Frameworks stellen.

**Vorgeschlagener Issue-Titel:** `HttpJwksClient: Negative-Cache und Refresh-Rate-Cap gegen unknown-kid-Refresh-Flood (Konzept §16) implementieren`

---

### JS-SEC-002 — Version-Drift-Reroute löscht Snapshot, aber nicht das Cached Subject (Medium)

**Modul/Datei:** `jSentinel-vaadin` — `jSentinel-vaadin/src/main/java/com/svenruppert/jsentinel/session/vaadin/JSentinelVersionEnforcerListener.java:77-100`

**CWE:** CWE-613: Insufficient Session Expiration

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — Skill/Demo werben ausdrücklich mit sofortiger Mid-Session-Revocation („revoking a role mid-session forces the affected user back to the login view", „an admin who revokes anything wants that user out, full stop").

**Beschreibung:** Der Drift-Stack existiert, um bei Mid-Session-Rollen-/Permission-Änderung einen Re-Check zu erzwingen. Bei Drift tut `beforeEnter` (Zeilen 94-99) genau zwei Dinge: `VaadinJSentinelVersionContext.clear(...)` und Reroute zur LoginView. Es entfernt weder das Cached Subject aus dem `SubjectStore` noch invalidiert es die Session. Da der Snapshot der **einzige** Drift-Trigger ist (Zeilen 81-83 kehren früh zurück, wenn kein Snapshot vorliegt), deaktiviert das Löschen alle weiteren Drift-Checks der Session — während das veraltete Subject mit der widerrufenen Rolle autoritativ bleibt und über `VaadinAccessContextFactory` weiterhin für die Autorisierung herangezogen wird.

**Angriffsszenario:** User U ist eingeloggt (Cached-Subject-Modell). Ein Admin widerruft Us ADMIN-Rolle und bumpt den Version-Store. U navigiert zu `/admin`: Enforcer erkennt Drift, löscht den Snapshot, reroutet zur LoginView — U bleibt aber authentifiziert und wird nie ausgeloggt. U re-navigiert zu `/admin`: der Snapshot ist weg, der Enforcer no-op't, der `AuthorizationListener` autorisiert gegen das gecachte (veraltete) Subject, das weiterhin ADMIN hält, und gewährt Zugriff. Die Revocation wird nie durchgesetzt.

**Bewertung (Medium):** Von High auf Medium korrigiert, weil es Privilege-**Retention** ist, begrenzt durch die Session-Lifetime (CWE-613), keine neue Eskalation — der User behält ein bereits gehaltenes Privileg bis zum freiwilligen Logout/Timeout; zudem existiert eine Out-of-Band-Remediation (`AdminSessionsView`/`LogoutService` kann die Zielsession force-terminieren). Nicht wegkonditionierbar für die betroffene Population: das Drift-Feature existiert nur für das Cached-Subject-Modell, jede App, die es aktiviert, ist exponiert.

**Remediation / Härtung:** Bei `EnforcementOutcome.SessionStale` die authentifizierte Session tatsächlich beenden statt nur den Snapshot zu löschen: aktuelles Subject entfernen (`SubjectStores.subjectStore().removeCurrentSubject(...)` bzw. `VaadinLogoutService`) und die Vaadin-Session re-initialisieren/invalidieren, **dann** zur LoginView reroute-n. Alternativ den Snapshot bei Drift **nicht** löschen, sodass jede Folge-Navigation mit dem noch-veralteten Cached Subject weiter abgewiesen wird, bis ein echter Re-Login ein frisches Subject und einen frischen Snapshot bindet. Muss die Library adapter-dünn bleiben, einen verpflichtenden Logout-Hook exponieren, den das Reroute-Target aufruft, und die Referenz-LoginView das Subject on-attach clearen lassen. Zusätzlich die irreführenden Demo-/Skill-Aussagen korrigieren. Regressionstest: zweite Navigation nach dem Drift-Reroute muss weiterhin Deny liefern.

**Vorgeschlagener Issue-Titel:** `JSentinelVersionEnforcerListener: bei SessionStale Subject entfernen und Session invalidieren statt nur Snapshot zu clearen`

---

### JS-SEC-003 — `LoginView` rotiert Session-ID nicht per Default (Session Fixation) (Medium)

**Modul/Datei:** `jSentinel-vaadin` — `jSentinel-vaadin/src/main/java/com/svenruppert/jsentinel/authorization/LoginView.java:274-314`

**CWE:** CWE-384: Session Fixation

**Status:** confirmed, Confidence high, kein dokumentierter Design-Carve-out — der Rotations-**Mechanismus** (`rotateSessionAfterLogin`, B3) ist dokumentiert, die Sicherheits-Exposition des Defaults ist es nirgends.

**Beschreibung:** `LoginView` ist die kanonische Login-Komponente. `notifyOnLogin()` rotiert die HTTP-Session-ID (`VaadinService.reinitializeSession`) nur, wenn `SessionPolicy.onLogin` `SessionDecision.Invalidate` zurückgibt (Zeilen 274-289). Der Resolver-Default ist `NoopSessionPolicy`, dessen `onLogin` das Interface-Default (`SessionPolicy.onLogin`, Zeilen 58-60) erbt und `Continue` liefert — also keine Rotation. Der DX-Bootstrap baut die rotierende `TimeoutSessionPolicy` nur, wenn die App Session-Timeouts/Policy explizit konfiguriert (`AbstractJSentinelBootstrap.applySessionConfiguration` kehrt bei `if (!state.sessionsConfigured()) return;` früh zurück). Das Standard-Integrationsrezept ergibt somit **keine** Session-ID-Rotation beim Login; eine Pre-Auth-Session-ID überlebt den Login. Bemerkenswert: auch das `jsentinel-vaadin-hardening`-Skill aktiviert keine Rotation.

**Angriffsszenario:** Der Angreifer setzt/erzwingt eine Session-ID im Browser des Opfers (z. B. Cookie-Injection von einer Sibling-Subdomain unter gemeinsamer Parent-Domain, MITM ohne HSTS, oder Container-`jsessionid`-URL-Rewriting). Das Opfer authentifiziert sich über `LoginView`; mit dem Default `NoopSessionPolicy` wird die ID nicht rotiert. Die dem Angreifer bekannte Session-ID ist nun an die authentifizierte `VaadinSession`/das Subject gebunden — Account-Takeover.

**Bewertung (Medium):** Nicht High, weil der Angreifer zuerst eine Session-ID fixieren muss (deployment-abhängige Vorbedingung); nicht Low, weil es der kanonische Login-Pfad eines Security-Frameworks ist und selbst der Hardening-Layer ihn offen lässt — ein Secure-by-Default-Fehler für CWE-384.

**Remediation / Härtung:** Session-ID-Rotation auf dem Framework-Login-Pfad secure-by-default machen. `VaadinService.reinitializeSession(request)` erhält alle `VaadinSession`-Attribute (das eben gebundene Subject überlebt — vom B3-Integrationstest bereits abgesichert), Rotation ist also gefahrlos unbedingt durchführbar. Bevorzugt: in `LoginView.validate()`/`notifyOnLogin()` die Session-ID nach Subject-Bindung **unabhängig** von der `SessionPolicy`-Entscheidung rotieren (Rotation ist eine Login-Boundary-Angelegenheit, orthogonal zur Timeout-Policy); `SessionPolicy.onLogin` weiterhin Audit-Emission/zusätzliche `Invalidate`-Semantik steuern lassen. Alternativ Resolver-Default von `NoopSessionPolicy` auf eine Secure-Default-Policy mit `Invalidate("RotationAfterLogin")` ändern. Mindestens `rotateSessionAfterLogin=true` in den PRODUCTION/STRICT-Profilen und in den `jsentinel-vaadin`/`jsentinel-vaadin-hardening`-Skill-Templates setzen und einen Session-Fixation-Hinweis ins Vaadin-Integrationsrezept aufnehmen. Bestehendes Best-Effort-Exception-Swallowing und das Old-Session-ID-Audit-Event beibehalten.

**Vorgeschlagener Issue-Titel:** `LoginView: Session-ID beim Login secure-by-default rotieren (Session-Fixation, CWE-384)`

---

### JS-SEC-004 — Session-Audit-`subjectId` weiterhin aus `subject.toString()` (PII-Leak) (Medium)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/session/TimeoutSessionPolicy.java:202-204`; zusätzlich `jSentinel-vaadin` — `SessionLifetimeListener.java:185-192` (219-227)

**CWE:** CWE-532: Insertion of Sensitive Information into Log File

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — unvollständige Remediation der bereits anerkannten Leak-Klasse R14/R019 (nur `LoginView.subjectIdOf` wurde in V00.76.10 gehärtet).

**Beschreibung:** `LoginView.subjectIdOf` (Zeilen 333-348) wurde ausdrücklich gehärtet, nie `subject.toString()` als Audit-`subjectId` zu publizieren, weil `toString()` eines App-User-Objekts häufig E-Mail/Hash/interne IDs serialisiert. Zwei Pfade tun genau das weiterhin: `TimeoutSessionPolicy.subjectIdOf` (Zeilen 202-204) liefert `context.subject().toString()` und stempelt es in `SessionCreated`/`SessionExpired`/`SessionInvalidated`. `SessionLifetimeListener.subjectIdOf` (jSentinel-vaadin, Zeilen 185-192, per SPI in jeder Vaadin-App registriert) tut dasselbe und speist `SessionExpired` via `audit()`. Beide umgehen den registrierten `SubjectIdResolver`, den `LoginView` bereits nutzt. Auffällig: derselbe Login-Flow nutzt für das Rotation-Audit den gehärteten Pfad, für das angrenzende `SessionCreated` (via `policy.onLogin`) den leaky Core-Pfad — R14 hat nur die halbe Login-Kette geschlossen.

**Angriffsszenario:** Ein Operator oder eine SIEM-Pipeline mit Zugriff auf den Security-Audit-Stream (niedrigere Trust-Boundary als der Credential-Store) liest `SessionCreated`/`SessionExpired`-Records und rekonstruiert PII (E-Mail, interne ID, Hash-Fragmente) aus dem `User.toString()` der Anwendung — ermöglicht Korrelation/Enumeration von Subjects aus Audit-Logs.

**Bewertung (Medium):** Entspricht dem projekteigenen Rating der identischen CWE-532-`toString`-Leaks (R14 = Medium). R019 war High, betraf aber Identität in Access-Control-Entscheidungen (breiterer Blast-Radius), was für diese reinen Audit-Emissionen nicht gilt. Praktische Auswirkung app-abhängig (ein sauberes `User.toString()` leakt nichts), landet im Audit-Kanal statt in einem öffentlichen Log — aber die R14/R019-Vertragslage lautet ausdrücklich, sich nie auf ein sauberes `toString()` zu verlassen.

**Remediation / Härtung:** Beide `subjectIdOf` über den registrierten `SubjectIdResolver` routen, exakt wie `LoginView.subjectIdOf`: `JSentinelServiceResolver.findSubjectIdResolver().map(r -> r.resolve(subject).value())`; nie `subject.toString()`. Nuance: `SessionMetadata`s Compact-Constructor lehnt eine leere `subjectId` ab (`IllegalArgumentException`) — in `SessionLifetimeListener` bei fehlendem/leerem Resolver auf einen Non-PII-Placeholder (`ClassName@identityHashCode`) zurückfallen, nicht auf Leerstring. Für `TimeoutSessionPolicy` ist der Leerstring-Fallback zulässig (Audit-Records akzeptieren leere `subjectId`, wie bei `LoginView`). Auch das gekoppelte `SessionCreated` aus `policy.onLogin` muss den Resolver nutzen, damit der Login-Pfad konsistent ist. Regressionstest: keine Audit-`subjectId` darf je gleich `subject.toString()` sein — über `onLogin`/`beforeNavigation`/`onLogout` sowie den `SessionLifetimeListener`-Timeout-Pfad.

**Vorgeschlagener Issue-Titel:** `Session-Audit: subjectId in TimeoutSessionPolicy und SessionLifetimeListener über SubjectIdResolver statt subject.toString() (CWE-532, R14-Nachzug)`

---

### JS-SEC-005 — Versprochenes `claims/audience-empty`-INFO nie implementiert; `aud` bleibt optional (Low)

**Modul/Datei:** `jSentinel-jwt` — `jSentinel-jwt/src/main/java/com/svenruppert/jsentinel/jwt/impl/NimbusJwtValidator.java:248-255`; Bootstrap-Seite `AbstractJSentinelBootstrap.applyJwtConfiguration:404`

**CWE:** CWE-345: Insufficient Verification of Data Authenticity

**Status:** needs-context, Confidence high, dokumentierte Design-Limitation — empty-`aud`=accept-any ist explizit dokumentiert (ClaimExpectations-JavaDoc, Konzept-V00.76 §334-336/§567), STRICT-Enforcement ist per Absicht auf den `.oidc(...)`-Pfad beschränkt (Konzept-V00.78 §3.4).

**Beschreibung:** Audience wird nur geprüft, wenn `expectations.acceptedAudiences()` non-empty ist; eine leere Menge akzeptiert stillschweigend jedes `aud` (Zeilen 248-255). Der DX-Bootstrap reicht `jwt.audiences()` durch (Zeile 404) und emittiert **kein** Warning, wenn diese leer ist — auch nicht in STRICT/PRODUCTION — obwohl die `ClaimExpectations`-JavaDoc ein „bootstrap INFO" ausdrücklich verspricht. Dieses INFO existiert nicht (grep bestätigt: `claims/audience-empty` kommt nur in Konzept-Docs vor, in keiner `.java`). Ein Deployer, der `.audiences(...)` nicht setzt, erhält einen ungeprüft audience-blinden Validator.

**Angriffsszenario:** Ein IdP stellt Access-Tokens an mehrere Relying Parties aus (`aud=rp-b`, `aud=rp-a`). Ein Angreifer besorgt sich ein legitimes, für Service B ausgestelltes Token und replay't es gegen das ohne `.audiences(...)` gebootstrappte Service A. `validate()` passiert Issuer-, Signatur-, `exp`- und `typ`-Checks und vergleicht — bei leerem `acceptedAudiences` — nie das `aud`, sodass das B-scoped Token den Angreifer bei A authentifiziert (Confused-Deputy/Token-Reuse).

**Bewertung (Low):** Verhalten entspricht RFC 7519 §4.1.3 (aud-Validierung ist bedingt) und dem Default gängiger JWT-Libraries (Nimbus `DefaultJWTClaimsVerifier`, Spring `JwtDecoders`). Der OIDC-Identity-Flow erzwingt Audience separat (`IdTokenExpectations.expectedAudience` ist non-Optional). Der einzige echte Defekt ist das nie implementierte, rein advisorische INFO — es würde selbst bei Existenz den JWT-Bearer-Pfad in STRICT nicht gaten und den Angriff nicht verhindern. Exploit erfordert Deployer-Fehlkonfiguration in einer spezifischen Multi-RP-Shared-IdP-Topologie — Hardening/Observability-Lücke, keine unbedingte Library-Schwäche.

**Remediation / Härtung:** Das `claims/audience-empty`-INFO in `AbstractJSentinelBootstrap.applyJwtConfiguration` implementieren, wenn `jwt.audiences()` leer ist (Code an JavaDoc/Konzept §567 angleichen — reine Observability). Im JWT-Integrationsguide dokumentieren, dass ein ohne `.audience(...)` konfigurierter Validator audience-blind ist und nicht ohne externe `aud`-Validierung hinter einen Multi-RP-Shared-IdP gehört. Eine Promotion zu STRICT/PRODUCTION-ERROR auf dem `.jwt()`-Pfad würde der dokumentierten Absicht (Konzept-V00.78 §3.4) widersprechen und wäre eine bewusste Design-Änderung, kein Bugfix.

**Vorgeschlagener Issue-Titel:** `Bootstrap: claims/audience-empty-INFO für leere jwt.audiences() implementieren (JavaDoc/Konzept §567 einlösen)`

---

### JS-SEC-006 — Introspection-Cache meldet `active=true` bis TTL über `exp` hinaus (Low)

**Modul/Datei:** `jSentinel-oauth2` — `jSentinel-oauth2/src/main/java/com/svenruppert/jsentinel/oauth2/HttpIntrospectionClient.java:109-159`

**CWE:** CWE-613: Insufficient Session Expiration

**Status:** confirmed, Confidence high, dokumentierte Design-Limitation (analoges Revocation-within-TTL-Tradeoff in Klassen-JavaDoc Zeilen 64-69 und RELEASE-NOTES-00.77.00).

**Beschreibung:** `introspect()` cached jedes erfolgreiche RFC-7662-Ergebnis unter `sha256(token)` mit fester Expiry `now + ttlMillis` (Default 60 s) und liefert bei Cache-Hit die gespeicherte Decision ohne erneute Prüfung des token-eigenen `exp`. `parse()` extrahiert `exp` bereits nach `IntrospectionResult.expiresAt`, nutzt diesen Wert aber nie zur Begrenzung der Cache-Entry-Lifetime (Zeile 135: `now + ttlMillis`; Hit-Pfad Zeile 118). Für opake Access-Tokens hat der Resource-Server keine Möglichkeit, `exp` selbst zu prüfen, und muss auf das `active`-Flag vertrauen — der Cache meldet ein bereits abgelaufenes Token bis zu einer vollen TTL nach dessen echtem `exp` als aktiv.

**Angriffsszenario:** Ein Angreifer erbeutet ein kurzlebiges opakes Bearer-Token (z. B. 10 s Lifetime via Log-/Referer-Leak). Der RS introspектiert es einmal bei T0 (noch gültig) und cached `active=true` für 60 s. Der Angreifer replay't das Token bei T0+30 s; es ist längst über `exp`, der RS akzeptiert es aber aufgrund des gecachten `active=true`.

**Bewertung (Low):** Von Medium herabgestuft: Staleness-Bound ist exakt `ttlMillis`, die identische, per Design akzeptierte Größe wie beim dokumentierten Revocation-Tradeoff; das gecachte `IntrospectionResult` trägt `expiresAt()` weiterhin, ein RFC-7662-§2.2-konformer Consumer (`active() && expiresAt().map(e -> e.isAfter(now)))`) ist immun; der Angriff erfordert eine widersprüchliche Config (~10 s Token + 60 s TTL, `TTL=0` deaktiviert den Cache); kein Produktions-Consumer im Repo. Bounded (<= TTL) Verlängerung des Replay-Fensters eines bereits einmal gültigen Tokens — Defense-in-Depth-Zeitgrenze, kein Auth-Bypass.

**Remediation / Härtung:** Positive Cache-Entry beim Speichern auf das bekannte `exp` deckeln: `long expiry = parsed.expiresAt().map(Instant::toEpochMilli).map(e -> Math.min(now + ttlMillis, e)).orElse(now + ttlMillis)`. Optional bei Cache-Hit `parsed.expiresAt()` gegen `now` prüfen und einen abgelaufenen Entry als Miss behandeln. Zusätzlich dokumentieren, dass Consumer bei vorhandenem `expiresAt()` dieses honorieren müssen (nicht nur `active()`), und dass Deployments mit sehr kurzen opaken Token-Lifetimes `ttlMillis` senken (oder `0` zum Deaktivieren) sollten.

**Vorgeschlagener Issue-Titel:** `HttpIntrospectionClient: positive Cache-Entry auf min(now+ttl, token-exp) deckeln (CWE-613, Defense-in-Depth)`

---

### JS-SEC-007 — `DefaultIdTokenValidator`: `expectedIssuer` tot, kein OIDC-Backstop für Single-Audience (Low)

**Modul/Datei:** `jSentinel-identity-oidc` — `jSentinel-identity-oidc/src/main/java/com/svenruppert/jsentinel/identity/oidc/DefaultIdTokenValidator.java:97-125`

**CWE:** CWE-287: Improper Authentication (OIDC audience/issuer confusion)

**Status:** needs-context, Confidence high, Delegation ist dokumentiert („Composition contract", RELEASE-NOTES-00.78.00), aber die tote `expectedIssuer`-Field und der fehlende Single-Audience-Backstop sind es nicht.

**Beschreibung:** `IdTokenExpectations` deklariert `expectedIssuer` und `expectedAudience` als mandatorische Non-Null-Felder. `validate(...)` referenziert `expectations.expectedIssuer()` jedoch nie (grep: 0 Uses im Modul) und nutzt `expectations.expectedAudience()` nur im `azp`-Zweig `if (audiences.size() > 1 || azp.isPresent())` (Zeilen 121-124). Für das übliche Single-Audience-No-`azp`-ID-Token gibt es keinen OIDC-Layer-Check, dass `aud` die `client_id` enthält, und keinen, dass `iss` dem erwarteten Issuer entspricht. Beides ist vollständig an einen **separat** konstruierten `JwtValidator` delegiert, dessen `ClaimExpectations` der Integrator unabhängig verdrahten muss; nichts cross-checkt, dass dessen Config zu den per Call übergebenen `IdTokenExpectations` passt. Ein mandatorischer, sicherheitskritischer Parameter (`expectedIssuer`) ist somit stumm tot.

**Angriffsszenario:** Ein Integrator übergibt korrekte `IdTokenExpectations.of(issuer, clientId, nonce)`, konstruiert den `NimbusJwtValidator` aber mit leerem `acceptedAudiences` (oder `Optional.empty()` Issuer) — ein naheliegender Fehler, da die OIDC-Layer-Expectations autoritativ wirken. Gegen einen Shared IdP besorgt sich ein Angreifer ein legitim signiertes ID-Token für eine andere `client_id` (`aud = victimClientB`) und replay't es zu diesem RP. Signatur verifiziert, `exp` gültig, `azp` abwesend (Single-`aud`), sodass weder JWT- noch OIDC-Layer ablehnt — der Angreifer wird als fremdes Subject am falschen RP eingeloggt.

**Bewertung (Low):** Von Medium herabgestuft: Delegation ist documented-by-design und alle Tests verdrahten korrekt; kein Shipped-/Produktions-Pfad ruft `validate` auf (keine RP-Authorization-Code-Callback-/Login-Flow, nur Bausteine + `StubIdentityProvider`). Der Angriff erfordert eine dokumentiert-abgeratene Fehlkonfiguration (`empty acceptedAudiences`, bereits per Bootstrap-INFO surfacet) **und** einen Shared/Multi-Tenant-IdP — Compound-Precondition, kein As-Shipped-Exploit. Echter Rest-Defekt: die nachweislich tote `expectedIssuer`-Field (Over-Promising-API-Contract) und der fehlende Single-`aud`-Backstop.

**Remediation / Härtung:** OIDC-Layer-Backstop in `validate` nach Erhalt des `ValidatedJwt` ergänzen, sodass die mandatorischen Felder unabhängig von der `ClaimExpectations` des komponierten Validators erzwungen werden: `jwt.issuer()` present und gleich `expectations.expectedIssuer()` (sonst `IssuerMismatch`), `jwt.audience()` present und enthält `expectations.expectedAudience()` auf Single- und Multi-`aud`-Pfad (sonst `AudienceMismatch`); bestehenden `azp`-Check als zusätzliche Constraint belassen. Regressionstests: Single-Entry `aud=[otherClient]` ohne `azp` → reject; `iss=other` → reject. Doku angleichen (`expectedIssuer`/`expectedAudience` entweder erzwingen oder JavaDoc auf JWT-Layer-Enforcement umformulieren) und das Release-Note-Parenthetical „(the .oidc(...) bootstrap wires this)" korrigieren, da `applyOidcConfiguration` `aud`/`iss` nicht aus der OIDC-Config ableitet.

**Vorgeschlagener Issue-Titel:** `DefaultIdTokenValidator: OIDC-Layer-Backstop für iss/aud ergänzen und tote expectedIssuer-Field einlösen (CWE-287)`

---

### JS-SEC-008 — `InMemoryJtiStore` Soonest-Expiry-Eviction unter All-Fresh-Flood (DPoP-Replay) (Low)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/replay/impl/InMemoryJtiStore.java:64-91` (DPoP-jti-Replay-Cache des `NimbusDpopProofValidator`)

**CWE:** CWE-294: Authentication Bypass by Capture-replay

**Status:** confirmed, Confidence medium, keine dokumentierte Limitation — RELEASE-NOTES-00.79.10 (R-EXIT-1) und JavaDoc **überzeichnen**, dass die Soonest-Expiry-Policy Flood-Evict-Replay „closes".

**Beschreibung:** Der Single-Use-jti-Store hinter DPoP-Replay-Schutz (RFC 9449 §11.1) ruft bei `maxEntries` in `record()` `evictOne(now)` auf: bereits abgelaufene Entries werden gepurgt, bei weiterhin voller Map wird der Entry mit dem **frühesten** `expiresAt` evict't. Doc-Kommentar und R-EXIT-1 behaupten, diese Policy fixe den Flood-Evict-Replay-Angriff der alten LRU-Policy. Tatsächlich ist der Soonest-Expiry-Entry der älteste noch **lebende** jti, noch in seinem Acceptance-Window; ihn zu evict-en öffnet das Replay-Fenster für exakt diesen jti wieder. Die Eviction failt nie closed und schützt lebende Entries nie — sie wählt nur das Opfer.

**Angriffsszenario:** Der Angreifer captured einen gültigen DPoP-Proof P_v des Opfers (`jti=J_v`, `iat=T_v`). Sofort (`T_v < now <= T_v+60`) flutet er den RS mit selbstsignierten, einzeln gültigen DPoP-Proofs bis `seen.size() == maxEntries` erreicht ist (je späteres `expiresAt` als J_v). Beim nächsten `record` purgt `evictOne` nichts (alle frisch) und evict't den Min-`expiresAt`-Entry = J_v. Danach replay't er das byte-identische P_v: Freshness passt noch (`iat` innerhalb `maxAge`), J_v ist nicht mehr im Store, `record()` erfolgreich — voller Replay des Sender-Constrained-Requests.

**Bewertung (Low):** Von High herabgestuft: der Min-`expiresAt`-Entry hat per Konstruktion das **kleinste** Restfenster (Freshness akzeptiert nur bis `expiresAt − maxFutureSkew`≈5 s, Entries mit < 5 s Store-Life sind bereits un-replaybar); der Angriff erfordert, dass der Victim-jti gleichzeitig globales Minimum ist, noch im ~55-s-Sub-Window liegt und der Angreifer einen vollständigen `maxEntries`-Flood einzeln EC-signierter, valider Proofs (~1800 req/s bei Default 100k) im schrumpfenden Fenster durchbringt — selbst DoS-Größenordnung; `@ExperimentalJSentinelApi`, single-JVM-only, Produktion soll einen Shared-atomic-Store nutzen. Nicht widerlegt, weil Mechanismus und Fehl-Dokumentation real sind (vom projekteigenen Test `overflowEvictsSoonestToExpire` belegt).

**Remediation / Härtung:** Primär Doku-Ehrlichkeit: R-EXIT-1 und `InMemoryJtiStore`/`JtiStore`-JavaDoc korrigieren — Soonest-Expiry **mitigiert** Flood-Evict-Replay (Purge-Expired-First + Shortest-Remaining-Window-Opfer), schließt einen sustained All-Fresh-Flood auf single-JVM aber nicht. Produktions-DPoP-RS weiter auf einen Shared-atomic-SET-NX+TTL-Store (Redis/JDBC) verweisen (die echte Remediation, bereits empfohlen). **Nicht** das naive Fail-Closed-Reject-on-Full adoptieren — es macht aus dem schmalen Replay-Fenster einen trivialen Full-DoS. Falls doch der In-Memory-Default gehärtet wird: (a) `maxEntries` deutlich über jedes plausible In-Window-Proof-Volumen dimensionieren und/oder (b) einen neuen jti nur ablehnen, wenn das Soonest-to-Expire-Opfer noch in seinem Freshness-Window ist (`expiresAt − now > maxFutureSkew`). Constructor-Lower-Bound von `1` weg verschärfen.

**Vorgeschlagener Issue-Titel:** `InMemoryJtiStore: R-EXIT-1/JavaDoc-Overclaim korrigieren (Soonest-Expiry mitigiert, schließt Flood-Evict-Replay nicht) + Eviction-Guard`

---

### JS-SEC-009 — Anti-Enumeration-Dummy-KDF nutzt Preferred- statt Stored-Algorithmus (Timing-Kanal) (Low)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/credential/password/dummy/DefaultDummyVerificationService.java:55-100`

**CWE:** CWE-208: Observable Timing Discrepancy (mit CWE-203 Observable Discrepancy / User-Enumeration)

**Status:** confirmed, Confidence medium, keine dokumentierte Limitation — Doku behauptet das Gegenteil (RELEASE-NOTES-00.71.00, `DefaultPasswordHashingService`-JavaDoc, `algorithm-compromise.md` §5 „observational equivalence"); `gaps.md` listet den Mixed-Algorithm-Caveat nicht.

**Beschreibung:** Die Verifikations-Pipeline soll „User existiert nicht", „malformed Envelope" und „falsches Passwort" auf ein Timing-Profil kollabieren (JavaDoc zitiert CWE-203/CWE-208), indem auf jedem Failure-Pfad ein Dummy-KDF läuft. `DefaultDummyVerificationService` cached aber **ein** Envelope, das zur Konstruktionszeit aus dem **Preferred**-Provider gebaut wird (`resolveAnyProvider()` liefert Preferred zuerst, Zeilen 66-72, 88-100), und verifiziert jeden Kandidaten gegen dieses eine Envelope (Zeile 85). Der Real-Pfad läuft dagegen gegen Provider/Parameter aus dem **User**-Envelope (`DefaultPasswordHashingService.verifyUnderLease` Zeilen 208-241). Im Modern-Profile ist Preferred Argon2id@64 MiB, Legacy-Hashes sind PBKDF2 — die für lazy Migration ausdrücklich vorgesehene Koexistenz. Ergebnis: Unknown-User → langsamer Argon2id-Dummy; existierender-aber-noch-legacy-User mit falschem Passwort → schnelles PBKDF2-Verify. Beide sind timing-unterscheidbar.

**Angriffsszenario:** Eine Org migriert von PBKDF2 zum Argon2id-Modern-Profile, User werden lazy on-login rehasht. Der Angreifer sendet Wrong-Password-Attempts für Kandidaten-Usernames und misst Latenz (über mehrere Requests gemittelt). Schnelle Antworten ⇒ Username existiert und ist noch auf Legacy-PBKDF2; langsame ⇒ nicht existent oder bereits migriert. Der Angreifer hat nun eine High-Value-Liste existierender, unmigrierter Accounts (schwächster KDF).

**Bewertung (Low):** Von Medium herabgestuft: die behauptete Magnitude ist falsch — `Pbkdf2Defaults` erzwingt MIN 210k / DEFAULT 600k Iterationen; PBKDF2-HMAC-SHA256 dabei ~50–350 ms, dieselbe Größenordnung wie (oft langsamer als) Argon2id 64 MiB/t=3 (~50–90 ms). Der Kanal ist verrauscht, statistisch, evtl. vorzeichen-invertiert und im Netzwerk-Jitter leicht verloren; er leakt nur existierende-UND-unmigrierte Accounts, ist migrationsfenster-beschränkt und wird durch `KdfExecutionLimiter`, `LoginAttemptPolicy`, `AbuseDetectionService` gedämpft. Inhärenter Tradeoff jeder lazy Multi-KDF-Migration — Hardening/Doku-Gap.

**Remediation / Härtung:** Bevorzugt: einen einheitlichen Cost-Floor auf jedem Verify-Outcome erzwingen — nach einem Stored-Algorithm-Verify, dessen `ResourceEstimate` unter der Preferred-Cost liegt, einen kompensierenden `dummyService.runDummyKdf` laufen lassen (für `NotMatched` **und** `Matched` vor Rückgabe), sodass Real- und Dummy-Pfad unabhängig vom Stored-Algorithmus konvergieren. Mindestens: die „timing stays uniform"/„observational equivalence"-Aussagen in RELEASE-NOTES-00.71.00, JavaDoc und `algorithm-compromise.md` abschwächen (Equalization ist exakt nur, wenn alle Hashes auf Preferred sind), den Caveat in `gaps.md` aufnehmen und beim Modern-Profile über einem Legacy-PBKDF2-Bestand eine Forced-Rehash-Migration statt lazy Rehash-on-Login empfehlen.

**Vorgeschlagener Issue-Titel:** `Dummy-Verification: Cost-Floor gegen Mixed-Algorithm-Timing-Enumeration + Doku-Caveat (CWE-208/CWE-203)`

---

### JS-SEC-010 — `RequiresPermissionEvaluator` fail-open bei leerem `@RequiresPermission({})` (Low)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/authorization/api/permissions/RequiresPermissionEvaluator.java:33-50`

**CWE:** CWE-863: Incorrect Authorization

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — inkonsistent zu den fail-closed Geschwistern und dem Enforcer.

**Beschreibung:** Der Evaluator hat keinen Guard für ein leeres Permission-Array. Bei leerer Required-Menge ist `PermissionMatcher.containsAll(held, {})` ein `required.stream().allMatch(...)` über einen leeren Stream — vakuös `true` —, sodass der Evaluator `AuthorizationDecision.granted()` an **jedes** authentifizierte Subject liefert, unabhängig von dessen Permissions (Zeilen 39-45; `PermissionMatcher.java:59-65`). Das ist das exakte Gegenteil der Geschwister: `RequiresAllPermissionsEvaluator` (46-49) und `RequiresAnyPermissionEvaluator` (46-49) liefern bei `value().length == 0` ausdrücklich `forbidden`; `JSentinelEnforcer.requireAllPermissions` (144-147) wirft `IllegalArgumentException`. Nur diese eine Annotation wandelt eine leere Constraint in einen Grant — und es ist die **stabile** Oberfläche, während die geschützten Geschwister experimentell sind.

**Angriffsszenario:** Ein Entwickler refactort einen Handler/View von `@RequiresPermission({"doc:delete"})` zu `@RequiresPermission({})` (bei Merge entfernt, oder programmatisch/per Template mit leerer Liste emittiert). Die Ressource sieht weiter geschützt aus, lässt aber jeden eingeloggten User zu. Ein Low-Privilege-User navigiert zum Endpoint/zur Route und führt eine privilegierte Operation aus. Kein Warning geloggt; Audit verzeichnet `AccessGranted`.

**Bewertung (Low):** Von Medium herabgestuft: Trigger ist ein Entwickler-Authoring-Fehler (kein attacker-controlled Input); repo-weiter grep nach `@RequiresPermission({})`/`()` = 0 Treffer; der Subject-Check bleibt, Impact ist Downgrade von „spezifische Permission" auf „any authenticated user", kein anonymer Bypass. Latenter Footgun auf der Mainstream-Annotation.

**Remediation / Härtung:** Denselben Empty-Value-Guard wie die Geschwister ergänzen, oben in `evaluate()` nach dem Subject-Check: `if (annotation.value().length == 0) return AuthorizationDecision.forbidden("@RequiresPermission requires at least one permission");`. Test-Fixture mit `@RequiresPermission({})` ⇒ Forbidden ergänzen (derzeit ungetestet). Langfristig die Fail-Closed-Empty-Constraint-Regel zentralisieren, sodass alle Permission-/Role-Evaluatoren eine Decision teilen.

**Vorgeschlagener Issue-Titel:** `RequiresPermissionEvaluator: fail-closed bei leerem @RequiresPermission({}) analog zu Geschwistern (CWE-863)`

---

### JS-SEC-011 — `RoleBasedAccessEvaluator` behandelt leere Rollenmenge als public (grants anonymous) (Low)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/authorization/api/roles/RoleBasedAccessEvaluator.java:44-73`

**CWE:** CWE-863: Incorrect Authorization

**Status:** confirmed, Confidence high, teils dokumentiert (entspricht der „no-annotation ⇒ public"-Regel), aber der Empty-Annotation-Fall ist in JavaDoc/RELEASE-NOTES **nicht** dokumentiert und inkonsistent zu den neueren fail-closed Evaluatoren.

**Beschreibung:** Die stabile, produktions-empfohlene Role-Evaluator-Basis liefert `AccessDecision.granted()`, sobald `requiredRoles(annotation)` leer ist — und zwar in Zeilen 48-50, **vor** dem Subject-Präsenz-Check (52-57). Eine leere Required-Rollenmenge gewährt somit Zugriff für **jeden**, inklusive unauthentifizierter Besucher (der `SubjectStore` wird nie konsultiert). Stärker als JS-SEC-010, weil (a) Stable API und empfohlener Produktions-Evaluator und (b) es anonyme User zulässt. Die neueren Evaluatoren lehnen das ausdrücklich ab: `SecureRouteEvaluator` (jSentinel-vaadin-starter, 46-53) dokumentiert „R035: fail closed"; `RequiresRoleEvaluator` failt closed bei empty. Die Basis wurde nie angeglichen.

**Angriffsszenario:** Ein Entwickler annotiert eine sensible Vaadin-Route mit leerer Rollenliste, `@VisibleFor({})` (kompiliert), oder `requiredRoles(...)` liefert für einen Annotations-Zweig/dynamisches Mapping eine leere Menge. Die Route rendert für anonyme Browser: der `AuthorizationListener` gewährt Navigation, weil der Evaluator `Granted` zurückgab, bevor überhaupt geprüft wurde, ob jemand eingeloggt ist.

**Bewertung (Low):** Von Medium herabgestuft: kein Default-Config-Exploit — der Empty-Zweig erfordert eine Empty-Constraint-Annotation (Fehlkonfiguration), eine korrekt konfigurierte Route übergibt stets Non-Empty-Rollen. Real und undokumentiert, per Copy-Paste-Skill-Template propagiert, auf einem stabilen Evaluator — Footgun-Härtung.

**Remediation / Härtung:** Die Empty-Constraint-Semantik explizit machen. Entweder (a) falls „empty = public" wirklich intendiert ist, in der Klassen-JavaDoc **und** im `RoleAccessEvaluator.java.tmpl`-Skill-Template dokumentieren, damit `@VisibleFor({})` nicht mit Schutz verwechselt wird; oder (bevorzugt für eine Security-Library) (b) fail-closed analog `SecureRouteEvaluator` (R035)/`RequiresRoleEvaluator` — zuerst ein authentifiziertes Subject verlangen und eine leere Required-Menge als „any authenticated subject" (nie „anyone") oder als Deny behandeln. Test für Empty-Roles + anonymes Subject ergänzen und Skill-Template + Demo-Evaluatoren im Gleichschritt aktualisieren.

**Vorgeschlagener Issue-Titel:** `RoleBasedAccessEvaluator: Empty-Roles-Semantik explizit machen (fail-closed statt anonymous grant) + Template angleichen (CWE-863)`

---

### JS-SEC-012 — `StoreBackedLoginAttemptPolicy` deckt Spraying/Distributed-Stuffing nicht ab (Low)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/bruteforce/StoreBackedLoginAttemptPolicy.java:90-130`

**CWE:** CWE-307: Improper Restriction of Excessive Authentication Attempts

**Status:** needs-context, Confidence high, keine dokumentierte Limitation auf der Store-Backed-Policy — der Layering-Vertrag (Anti-Automation via `AbuseDetectionService`) ist in der ASVS-Map dokumentiert, die fehlende Parität zur In-Memory-Policy nicht.

**Beschreibung:** `key()` (123-126) baut einen einzigen Composite-`LoginAttemptKey(tenant, username, ip)`; `beforeAttempt`/`recordFailure`/`reset` zählen nur gegen dieses Tupel. Ein Lockout triggert daher nur, wenn **derselbe** Username von **derselben** IP `failureThreshold`-mal fehlschlägt. Distributed Credential Stuffing (viele IPs, ein Account) und Password Spraying (viele Usernames, ein Host) halten jeden Zähler unter der Schwelle. Das widerspricht dem eigenen Key-Modell: die `LoginAttemptKey`-JavaDoc (22-35) bewirbt beide Dimensionen als **unabhängig** getrackt, aber diese Policy konsultiert nie einen Username-only- oder IP-only-Zähler. `InMemoryLoginAttemptPolicy` ist besser (Username-only-Zähler, 99-109), hat aber ebenfalls keinen IP-only-Zähler.

**Angriffsszenario:** Der Angreifer nimmt die Top-1000-Usernames und ein Common-Password und probiert es von einem Host gegen `username_1..1000`; jeder `(username_j, ip)`-Zähler erreicht 1, nie die Schwelle, kein Lockout, kein `BruteForceLimitReached`-Audit. Oder: aus einem 500-IP-Proxy-Pool 500 Passwörter gegen ein Opfer; jeder `(victim, ip_i)`-Zähler erreicht 1.

**Bewertung (Low):** Von Medium herabgestuft: `StoreBackedLoginAttemptPolicy` ist `@ExperimentalJSentinelApi` und in **keinem** Produktions-/Demo-Consumer verdrahtet (Default-Resolver = noop, Demos nutzen `InMemoryLoginAttemptPolicy`). Per-Account-Lockout stoppt Spraying/Distributed-Low-and-Slow per Definition nicht (OWASP-Standard). Das Framework liefert die korrekte Anti-Automation-Kontrolle (`AbuseDetectionService`, CLIENT_ADDRESS/TENANT/GLOBAL-VOLUME-Dimensionen), und die ASVS-L2-Map (`asvs-v2-mapping.md:50`) weist CWE-307 §2.2.1 ausdrücklich dieser zu, nicht der `LoginAttemptPolicy`. Echter Rest: Parity-Regression (fehlender Username-only-Zähler), undokumentiert.

**Remediation / Härtung:** Primär Doku/Parität, kein Exploit-Fix: (1) auf `StoreBackedLoginAttemptPolicy` dokumentieren, dass sie nur per-`(username,ip)`-Flat-Lockout bietet — kein Account-weites/per-Source-Throttling — und dass ein Umstieg (In-Memory → Store-Backed) für Clustering mit einem verdrahteten `AbuseDetectionService` (CLIENT_ADDRESS-Volume) für Spraying/Distributed-Stuffing gepaart werden muss. (2) Optional Parität herstellen: zusätzlicher `store.failureCount`-Lookup gegen einen Username-only-Key (Sentinel-IP), damit IP-Hopping gegen einen Account weiterhin auslöst. (3) Nicht als CWE-307-Anti-Automation-Kontrolle behandeln — die ASVS-Map ordnet das korrekt dem `AbuseDetectionService` zu; Consumer-Guides sollten dessen Verdrahtung empfehlen.

**Vorgeschlagener Issue-Titel:** `StoreBackedLoginAttemptPolicy: fehlenden Username-only-Zähler + Doku zum AbuseDetectionService-Layering ergänzen (CWE-307)`

---

### JS-SEC-013 — `StepUpRequired.method()` unescaped in `WWW-Authenticate` (CRLF) (Low)

**Modul/Datei:** `jSentinel-rest` — `jSentinel-rest/src/main/java/com/svenruppert/jsentinel/rest/HttpStatusDecisionMapper.java:64-74`

**CWE:** CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers (HTTP Response Splitting)

**Status:** needs-context, Confidence high, keine dokumentierte Limitation.

**Beschreibung:** Bei einer `StepUpRequired`-Decision schreibt der Mapper den Header als `STEP_UP_SCHEME + " method=\"" + stepUp.method() + "\""` ohne Neutralisierung von Anführungszeichen oder CR/LF (Zeilen 69-71). Das Record `AuthorizationDecision.StepUpRequired` (jSentinel-core `AuthorizationDecision.java:104-110`) validiert `method` nur auf non-blank, akzeptiert also `"`, `\r`, `\n`. Liefert eine app-eigene `AuthorizationEvaluator`-Implementierung den Step-Up-Mechanismus aus request-kontrolliertem Input (z. B. `auth-level`-Query-Param oder zurückgespiegeltes `acr`-Claim), fließt der Token verbatim in den Header. Die Library darf Header-Value-Sicherheit nicht an die app-bereitgestellte `RestResponse`-Implementierung delegieren.

**Angriffsszenario:** Eine App schreibt einen Custom-Step-Up-Evaluator, der `StepUpRequired(reason, requestedMethodFromQueryParam)` liefert. Der Angreifer ruft `?stepup=MFA%22%0d%0aSet-Cookie:%20sid=attacker`. Der Evaluator liefert ein `method` mit Quote+CRLF; `HttpStatusDecisionMapper` konkateniert es in `WWW-Authenticate`; eine nicht-validierende `RestResponse`/Servlet schreibt einen Split-Response-Header — Response-Splitting/Client-Confusion.

**Bewertung (Low):** Die frameworkeigenen Step-Up-Produzenten sind enum-constrained (`StepUpMethod` MFA/REAUTH → `name()`); `RestResponse.header()` hat einen No-op-Default ohne Library-Impl; gängige Servlet-/HTTP-Container lehnen CR/LF in Header-Werten ab. Exploit erfordert sowohl einen Custom-Evaluator, der Request-Input in `method` pipet, als auch eine nicht-validierende App-`RestResponse` — beides nicht im Shipped-/Demo-Code. Legitime Defense-in-Depth-Lücke für eine Security-Library.

**Remediation / Härtung:** Einmal an der Trust-Boundary fixen: im Compact-Constructor von `AuthorizationDecision.StepUpRequired` (105-110) nach dem Non-Blank-Check jedes `method` mit Zeichen außerhalb des RFC-7235-Token-Sets (insbesondere `"`, `\`, CR, LF, Control-Chars) mit `IllegalArgumentException` ablehnen. Dieser eine Guard schützt jeden Adapter (REST-Header, Vaadin/Standalone-Reason-Strings) unabhängig vom Autor des Evaluators. Sekundär könnte `HttpStatusDecisionMapper.apply` `method` als korrekt backslash-escaptes RFC-7235-Quoted-String emittieren — der Constructor-Guard ist der Primär-Fix.

**Vorgeschlagener Issue-Titel:** `AuthorizationDecision.StepUpRequired: method gegen RFC-7235-Token-Set validieren (CRLF/Quote-Reject, CWE-113)`

---

### JS-SEC-014 — `ClientCredentialsStrategy` Cache-Key ohne Scope (Cross-Scope-Kollision) (Low)

**Modul/Datei:** `jSentinel-propagation-oidc` — `jSentinel-propagation-oidc/src/main/java/com/svenruppert/jsentinel/propagation/oidc/strategy/ClientCredentialsStrategy.java:95-131`

**CWE:** CWE-269: Improper Privilege Management

**Status:** needs-context, Confidence high, keine dokumentierte Limitation — dormant, über Shipped-Propagation-Pfade nicht erreichbar.

**Beschreibung:** `resolve()` cached das gemintete Access-Token unter `clientId + "|" + call.declaredAudience()` (Zeile 96), der Token-Request (`formBody`, 141-150) enthält aber den angeforderten OAuth-`scope` aus `call.hints().get("scope")` (147-148). Da `scope` Teil des Request-Body, aber **nicht** des Cache-Keys ist, kollidieren zwei Calls zur selben Audience mit unterschiedlichen Scopes. Der erste Call fixiert den Scope des gecachten Tokens für alle späteren bis zur Expiry. Ein späterer Call mit engerem Scope (`read`) erhält das für breiteren Scope (`read write`) gemintete Token — die Least-Privilege-/Downscoping-Absicht wird unterlaufen; die Richtung ist call-order-abhängig, also nicht-deterministisch.

**Angriffsszenario:** Ein Service nutzt einen Confidential Client für verschiedene Scopes: der Bulk-Import-Pfad fordert `scope=documents.write`, der Preview-Pfad `scope=documents.read`. Unter Last wärmt der Write-Pfad den Cache; der Read-Pfad liest das gecachte `documents.write`-Token und forwardet es downstream. Ein Bug oder ein kompromittierter Low-Privilege-Codepfad, der nur `read` halten sollte, präsentiert dem RS ein `write`-Token.

**Bewertung (Low):** Von Medium herabgestuft: über die intendierte Annotation-getriebene Propagation (`PropagatingProxy`/`PropagateTokenProcessor`) ist `hints` **immer** `Map.of()`, `@PropagateToken` hat kein `scope`-Attribut — kein Shipped-Pfad triggert die Kollision. Selbst bei manueller Hint-Nutzung ist es Degradation einer selbst-auferlegten Least-Privilege-Convenience, keine Cross-Boundary-Eskalation: eine Instanz hält **eine** Client-Identity, jeder Pfad, der `resolve()` erreicht, könnte `scope=documents.write` direkt anfordern. Modul `@ExperimentalJSentinelApi`.

**Remediation / Härtung:** Effektiven `scope` (und jeden anderen body-formenden Hint) in den Cache-Key aufnehmen: `clientId + "|" + declaredAudience + "|" + scope`, analog zu `TokenExchangeStrategy.cacheKey()`. Test: zweimal resolve-n mit gleichem `clientId`+`audience`, unterschiedlichem `scope`-Hint ⇒ zwei distinkte Token-Endpoint-Calls/Cache-Entries. Da derzeit dormant: falls per-Operation-Scope ein unterstütztes Feature sein soll, End-to-End verdrahten (`@PropagateToken(scope=...)` → `OutboundCall.hints`) und den Cache-Key-Fix zusammen landen; andernfalls das opportunistische `scope`-Lesen (Zeile 147) entfernen, bis das Feature real ist.

**Vorgeschlagener Issue-Titel:** `ClientCredentialsStrategy: scope in Cache-Key aufnehmen (Cross-Scope-Kollision, CWE-269)`

---

### JS-SEC-015 — `InMemoryTokenExchangeCache` unbounded, nur Lazy-TTL-Eviction (Low)

**Modul/Datei:** `jSentinel-propagation-oidc` — `jSentinel-propagation-oidc/src/main/java/com/svenruppert/jsentinel/propagation/oidc/cache/InMemoryTokenExchangeCache.java:34-67`

**CWE:** CWE-770: Allocation of Resources Without Limits or Throttling

**Status:** confirmed, Confidence high, keine dokumentierte Limitation (im Gegensatz zum R07-Dead-Letter-Store, der explizit „unbounded-by-design" ist).

**Beschreibung:** Der Cache ist eine schlichte `ConcurrentHashMap` ohne Max-Size und ohne Background-/TTL-Sweep. `put()` inserted unbedingt (60-62); abgelaufene Entries werden nur entfernt, wenn **derselbe** Key erneut via `get()` angefragt wird (52-54). Für `TokenExchangeStrategy` ist der Key `sha256(subjectToken)|audience` — ein Entry pro distinktem Inbound-User-Token. In einem stark frequentierten REST-Service erzeugt jeder distinkte End-User (und jede Token-Rotation) einen permanenten Entry, der nie zurückgewonnen wird, solange nicht exakt dieser User nach Expiry erneut aufruft. Die Map wächst unbounded und hält live/expired Access-Tokens dauerhaft im Heap — Availability-Risiko und vergrößerte Secret-at-Rest-Exposition für Heap-Dumps.

**Angriffsszenario:** Ein High-Churn-Client rotiert sein Inbound-Bearer-Token bei jedem Request (jede Rotation = neuer `sha256`-Key) gegen einen `@PropagateToken(strategy="exchange")`-Endpoint. Jeder Request fügt einen nie-evict-ten Entry hinzu; sustained Traffic treibt die Map Richtung OOM. Auch ohne Böswilligkeit leakt eine große Userbase plus Rotation langsam Speicher und hält tausende exchanged Tokens resident.

**Bewertung (Low):** Von Medium herabgestuft: `cache.put()` (Zeile 133) läuft nur nach erfolgreichem (2xx) Token-Exchange gegen den IdP — ein 4xx/5xx wirft vor jedem Insert, ein malformed rotiertes Token failt den Exchange und erzeugt keinen Entry. Jeder Entry kostet also ein bereits validiertes Inbound-Token, ein echt gültiges vom IdP austauschbares Subject-Token und einen echten HTTP-Round-Trip zum IdP (natürlicher Bottleneck; der IdP rate-limitet vor dem OOM). Modul `@ExperimentalJSentinelApi`, `TokenExchangeCache.NONE` und ein 5-arg-Constructor für Custom-Bounded-Impls verfügbar; R023 keyed bereits auf einen SHA-256-Digest.

**Remediation / Härtung:** Default-Cache bounded machen: `maximumSize` mit LRU/Access-Order-Eviction (Access-Order-`LinkedHashMap` hinter Lock oder Caffeine `maximumSize + expireAfterWrite`) und/oder periodischen Sweep, der Entries mit abgelaufenem `expiresAt` unabhängig vom Re-Access entfernt. Evict-ten `CachedEntry.accessToken` prompt überschreiben/clearen, um Heap-Dump-Exposition zu verkleinern. Gewählten Bound dokumentieren und den Convenience-Constructor auf die bounded Variante defaulten; `TokenExchangeCache.NONE` und den 5-arg-Constructor beibehalten.

**Vorgeschlagener Issue-Titel:** `InMemoryTokenExchangeCache: Size-Bound + TTL-Sweep + Secret-Clearing gegen unbounded Wachstum (CWE-770)`

---

### JS-SEC-016 — `PERSISTENT_FILE`-Bootstrap-Token: keine Owner-only-ACL auf Non-POSIX (Low)

**Modul/Datei:** `jSentinel-core` — `jSentinel-core/src/main/java/com/svenruppert/jsentinel/bootstrap/FileBootstrapTokenStore.java:84-106`

**CWE:** CWE-256: Plaintext Storage of a Credential

**Status:** confirmed, Confidence high, teils dokumentierte Limitation — das 0600-Verhalten ist als POSIX-only dokumentiert (bootstrap.md, RELEASE-NOTES-00.74.20), die Non-POSIX-Lücke selbst ist aber real und exploitierbar.

**Beschreibung:** `FileBootstrapTokenStore` backt `BootstrapMode.PERSISTENT_FILE`. Das Bootstrap-Token ist das einzige im Framework im Klartext persistierte Credential (alle anderen Secrets sind SHA-256-Hashes) und autorisiert die Erstellung des ersten Admin-Accounts. `save()` wendet `OWNER_READ|OWNER_WRITE` (0600) atomar nur an, wenn das FS die `posix`-View meldet; auf jedem anderen FS (Windows/NTFS, exFAT, manche Netz-Mounts) ist das `attrs`-Array leer (92-94), sodass Token-Datei und das per `Files.createDirectories(parent)` (88) angelegte Parent-Directory Default-/Parent-ACLs ohne Restriktions-Versuch und ohne Warning erben. Zusätzlich liest `load()` (56-82) das Token unabhängig von den tatsächlichen On-Disk-Permissions.

**Angriffsszenario:** Ein Operator betreibt eine jSentinel-App auf Windows mit der Token-Datei unter einem breit lesbaren App-/Config-Directory (oder einem POSIX-Host, wo ein früherer Prozess die Datei 0644 hinterließ). Ein lokaler Low-Privilege-User liest `token=…`, submittet es vor dem legitimen Operator an den First-Admin-Creation-Endpoint und wird Initial-Admin — Full-Authority-Takeover.

**Bewertung (Low):** Non-Default-Modus (Default `TRANSIENT_CONSOLE`, Token nie auf Disk) + Non-POSIX-FS + breit lesbares Directory (Operator-Fehler) + lokaler Angreifer + uninitialisiertes System innerhalb 24 h. Token ist ~100 Bit Entropie, 24 h gültig, Constant-Time-Compare, nie geloggt, one-time (nach First-Admin invalidiert). Auf POSIX korrekt 0600 ohne umask-Window. Nicht auf Info herabgestuft, weil bei erfüllten Bedingungen First-Admin-Takeover eintritt und auf Non-POSIX **null** Restriktions-Versuch/Warning erfolgt.

**Remediation / Härtung:** Höchster Wert in `save()`: auf Non-POSIX-FS **nicht** stumm auf unrestricted Default-ACLs zurückfallen. Entweder (a) Owner-only-Restriktion via `AclFileAttributeView` nach `CREATE_NEW` (nur Process-Owner + SYSTEM/Administrators, deny others) oder (b) fail-fast/klares WARNING, dass Owner-only nicht erzwungen werden konnte und `PERSISTENT_FILE` auf dieser Plattform keine Confidentiality garantiert. Dokumentieren, dass `PERSISTENT_FILE` ein Owner-only-Directory adressieren muss, und `TRANSIENT_CONSOLE` empfehlen. Der `load()`-seitige Permission-Check ist Low-Value (erkennt kein vorheriges Kopieren) und zugunsten des `save()`-ACL/Warnings verzichtbar.

**Vorgeschlagener Issue-Titel:** `FileBootstrapTokenStore: Owner-only-ACL oder Fail-Fast-Warning auf Non-POSIX-Filesystemen (CWE-256)`

---

### JS-SEC-017 — Eclipse-Store-Storage-Tree mit umask-Default (world-readable) angelegt (Low)

**Modul/Datei:** `jSentinel-persistence-eclipsestore` — `jSentinel-persistence-eclipsestore/src/main/java/com/svenruppert/jsentinel/persistence/eclipsestore/JSentinelStorageFactory.java:95-144`

**CWE:** CWE-276: Incorrect Default Permissions

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — Encryption-at-Rest ist explizit als Consumer-Concern ausgeklammert (Konzept/Plan V00.74.20), Directory-**Permissions** werden nirgends adressiert.

**Beschreibung:** `openAt()`/`ensureParentIsWritableDirectory()` und `EclipseStoreJSentinelStorage.initStorageManager()` starten das Embedded-Storage via `EmbeddedStorage.start(dir)` ohne die Permissions des angelegten Directory-Trees einzuschränken. Die Pre-Flight-Validierung prüft nur, dass ein existierendes Parent ein Directory und writable ist (132-144) — nie, dass der Tree nicht group/other-readable ist. Der Framework-Store hält `SessionRecord` (keyed auf `SessionId`, dem Server-seitigen Session-Handle), Rollen-Assignments, Login-Attempt-Records und Token-Hashes. Auf einem Default-umask-(022)-POSIX-Host sind die Store-Dateien world-readable. `FileBootstrapTokenStore` zeigt, dass der Codebase Owner-only-Permissions bereits anfordern kann.

**Angriffsszenario:** Eine jSentinel-App läuft mit Default-umask, ihr Storage-Directory unter einem geteilten Ort (`/var/lib`, Multi-Tenant-Host). Ein lokaler User ohne App-Privilegien liest die Store-Dateien und enumeriert aktive `SessionId`-Werte und Rollen-Assignments; nutzt das Deployment die gespeicherte `SessionId` direkt als Session-Bearer, replay't er sie zur Session-Hijack, andernfalls harvestet er Rollen-/Login-Attempt-Daten zur Reconnaissance.

**Bewertung (Low):** Token-Replay ist ausgeschlossen (Refresh/API-Key als Hashes gespeichert). Session-Hijack ist **conditional** — nur wenn ein Consumer den rohen Session-Bearer als `SessionId.value` speichert (in den Referenz-Skills liegt der Bearer in einem separaten `TokenStore`, das Session-Handle ist der Key). Erfordert einen lokalen unprivilegierten User mit Read-/Traverse-Zugriff auf den Storage-Pfad (Shared/Multi-Tenant). Unbedingt übrig unter Default-umask: Info-Disclosure von Security-**Metadaten** (Rollen, SubjectIds, Login-Attempts, Session-Metadaten) an einen co-lokalen User — Defense-in-Depth-Härtung. Typen `@ExperimentalJSentinelApi`, aber Skills liefern es als Produktions-Pfad.

**Remediation / Härtung:** Den angelegten Storage-Tree als Defense-in-Depth härten. Beim Anlegen des Framework-Directory dieses mit Owner-only-Permissions vor-erzeugen (`Files.createDirectories(dir, PosixFilePermissions.asFileAttribute("rwx------"/0700))` auf POSIX, `AclFileAttributeView` owner-only sonst) **vor** `EmbeddedStorage.start` — das exakte `OWNER_*`-Muster aus `FileBootstrapTokenStore.save` wiederverwenden. Startup-Check ergänzen, der einen WARN loggt (via `HasLogger`), wenn der Tree group/other-accessible ist. Benötigte Directory-Permissions neben der bestehenden Encryption-at-Rest-Notiz dokumentieren.

**Vorgeschlagener Issue-Titel:** `JSentinelStorageFactory: Storage-Tree mit Owner-only-Permissions anlegen + WARN bei group/other-readable (CWE-276)`

---

### JS-SEC-018 — `HttpJwksClient` ohne HTTPS-Guard auf dem Direkt-SPI-Pfad; falsche JavaDoc-Zusage (Low)

**Modul/Datei:** `jSentinel-jwt` — `jSentinel-jwt/src/main/java/com/svenruppert/jsentinel/jwt/impl/HttpJwksClient.java:58-97`; `NimbusJwtValidatorFactory:54`; `JwtValidatorSpec`-JavaDoc

**CWE:** CWE-319: Cleartext Transmission of Sensitive Information

**Status:** confirmed, Confidence high, teils dokumentiert — die Non-Enforcement ist in der `HttpJwksClient`-JavaDoc als Absicht dokumentiert, aber die `JwtValidatorSpec`-JavaDoc verspricht fälschlich Impl-Level-Enforcement.

**Beschreibung:** `HttpJwksClient` holt das JWKS-Dokument (die gesamte Public-Key-Trust-Root) von der übergebenen URI ohne Scheme-Validierung — die eigene JavaDoc sagt „HTTPS is not enforced here — that is a bootstrap-time STRICT rule". Der einzige Guard liegt im DX-Layer (`AbstractJSentinelBootstrap.validate` ~377-394, ERROR in PRODUCTION/STRICT). Ein Consumer, der über die SPI-Factory `NimbusJwtValidatorFactory.create(spec)` statt über den DX-Bootstrap verdrahtet, erhält **keinen** Guard: `create()` macht `new HttpJwksClient(spec.jwksUri())` ohne Check (Zeile 54). Bei `http://`-`jwks_uri` wird die Trust-Root im Klartext geladen, wo ein On-Path-Angreifer eigene JWKS substituieren und Tokens fälschen kann. Zum Widerspruch: `HttpUserInfoClient` (84) und `OAuth2FormPost.requireHttps` (84-96) erzwingen HTTPS im Client selbst.

**Angriffsszenario:** Eine App integriert JWT-Validierung direkt über die `JwtValidatorFactory`-SPI und konfiguriert `jwks_uri = http://idp.internal/jwks.json`. Kein Warning/Error. Ein Angreifer im Netzpfad (oder mit DNS/ARP-Kontrolle) liefert ein JWKS mit seinem eigenen Public-Key unter dem erwarteten `kid`. Er mintet ein JWT mit dem passenden Private-Key; `NimbusJwtValidator` löst den `kid` aus dem vergifteten JWKS auf, die Signaturprüfung passt — Full-Auth-Bypass/Token-Forgery.

**Bewertung (Low):** Der gesegnete Pfad ist der DX-`.jwt(...)`-Sub-Builder, der das in PRODUCTION/STRICT als ERROR blockt (R11-Fix). Kein Produktions-Consumer/Demo/Skill nutzt den Direkt-Factory-Pfad. `impl`-Package, alle vier Typen `@ExperimentalJSentinelApi`. Exploit erfordert zusätzlich `http://`-Wahl des Operators plus On-Path/DNS-Angreifer. Defense-in-Depth + Doku-Konsistenz-Lücke, kein Loch in einer empfohlenen Config.

**Remediation / Härtung:** Einen Client-Boundary-HTTPS-Guard analog `OAuth2FormPost.requireHttps` (gleicher `-Djsentinel.dev`-Loopback-Carve-out, INFO-Parität zum Bootstrap) in den `HttpJwksClient`-Constructor oder in `NimbusJwtValidatorFactory.create(spec)` einziehen, sodass der Direkt-SPI-Pfad `HttpUserInfoClient`/`OAuth2FormPost` matcht. Unabhängig die widersprüchliche `JwtValidatorSpec`-JavaDoc (`https enforced by impl`) korrigieren — entweder wahr machen (via Guard) oder auf die Bootstrap-Zeit-Regel umformulieren.

**Vorgeschlagener Issue-Titel:** `HttpJwksClient: Client-Boundary-HTTPS-Guard auf dem Direkt-SPI-Pfad + JwtValidatorSpec-JavaDoc korrigieren (CWE-319)`

---

### JS-SEC-019 — CRLF-Log-Injection über Decode-Fehlermeldung auf dem `events:publish`-Pfad (Low)

**Modul/Datei:** `jSentinel-events-rest` — `jSentinel-events-rest/src/main/java/com/svenruppert/jsentinel/events/rest/EventPublishService.java:76-84`

**CWE:** CWE-117: Improper Output Neutralization for Logs

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — im Gegenteil weicht dieser Pfad vom projekteigenen Sanitization-Standard ab (Konzept-V00.76 §381 „Klassename + sanitized message" für das Geschwister-Event `JwksRefreshFailedEvent`).

**Beschreibung:** Bei malformed Publish-Body loggt `EventPublishService` den Codec-Fehler-String auf WARN: `logger().warn("events-rest/publish-malformed: {}", error)` (Zeile 80). `error` wird in `EnvelopeWireCodec.decode` (128-129) als `t.getClass().getSimpleName() + ": " + t.getMessage()` gebaut, und die zugrundeliegenden `WireJson`-Parse-Exceptions betten Fragmente des angreifer-gelieferten JSON in `getMessage()` ein. Der Request-Body-Inhalt fließt somit ohne CR/LF-Neutralisierung in die Log-Zeile — Log-Forging. Erreichbar nur nach Authentifizierung und `events:publish`-Permission-Check.

**Angriffsszenario:** Ein Halter von `events:publish` POSTet an `/api/events` ein JSON-Envelope, dessen Feldwert einen eingebetteten Newline plus eine fabrizierte Log-Zeile enthält. Der Wire-Codec failt, seine Exception-Message echot das Fragment; `EventPublishService` loggt es verbatim auf WARN. Die angreifer-verfasste Zeile landet im Operational-Log — ein Low-Trust-Publisher kann Event-Pipeline-Audit-Records fälschen oder verbergen.

**Bewertung (Low):** Erreichbar nur nach Auth + der privilegierten `events:publish`-Permission (semi-trusted Publisher, nicht anonym); Impact auf Operational-Text-Logs beschränkt (Log-Forging), bounded Länge, Effekt vom Log-Encoder des Deployments abhängig. Dennoch echte CWE-117-Escalation-of-Effect, da `events:publish` sonst keine Log-Write-Fähigkeit gewährt.

**Remediation / Härtung:** CR/LF und weitere Control-Chars aus dem zusammengesetzten Error strippen, bevor er einen Logger erreicht — am besten einmal an der Codec-Quelle (`EnvelopeWireCodec.decode` `mapError`, 128-129), sodass jeder Consumer profitiert: String bauen und `[\r\n\t\p{Cntrl}]` durch Placeholder ersetzen, oder nur `t.getClass().getSimpleName()` plus fixen Reason-Code loggen (entsprechend dem projekteigenen Muster für `JwksRefreshFailedEvent`, Konzept §381). Keine rohen Parser-/Timestamp-Fragmente in die WARN-Zeile. Den generischen 400-Body (`EventPublishBodies.MALFORMED_ENVELOPE`) unverändert lassen.

**Vorgeschlagener Issue-Titel:** `EnvelopeWireCodec/EventPublishService: Decode-Fehlermeldung vor dem Loggen von CR/LF/Control-Chars säubern (CWE-117)`

---

### JS-SEC-020 — EdDSA-Pfad ohne `crit`-Header-Rejection (RFC 7515 §4.1.11) (Info)

**Modul/Datei:** `jSentinel-jwt` — `jSentinel-jwt/src/main/java/com/svenruppert/jsentinel/jwt/impl/NimbusJwtValidator.java:314-326`

**CWE:** CWE-345: Insufficient Verification of Data Authenticity

**Status:** confirmed, Confidence high, keine dokumentierte Limitation.

**Beschreibung:** RSA/EC-Tokens werden via Nimbus `jwt.verify(verifier)` (Zeile 178) verifiziert, wobei die `CriticalHeaderParamsDeferral` des Verifiers jedes Token mit unbekanntem `crit`-Header-Param ablehnt (RFC 7515 §4.1.11). EdDSA-Tokens umgehen Nimbus komplett und werden mit einer rohen JDK-`Signature` in `verifyEd25519()` (314-326) verifiziert, die den `crit`- (oder `b64`-) Header nie inspiziert. Ein EdDSA-Token, das eine Critical-Header-Extension deklariert, die der Validator nicht versteht, wird daher stumm akzeptiert, während dasselbe Token mit RS256/ES256 abgelehnt würde — inkonsistente, spec-non-konforme Verifikations-Posture.

**Angriffsszenario:** Ein legitimer/Upstream-Issuer emittiert EdDSA-Tokens mit einer `crit`-gelisteten Extension, die Processing ändern soll. jSentinel ignoriert die `crit`-Direktive für EdDSA stumm (honoriert den Rejection-Contract aber für RSA/EC), sodass ein Token, das RFC 7515 abzulehnen verlangt, akzeptiert wird. Keine Forgery (der Angreifer kann keine gültige EdDSA-Signatur erzeugen), aber Verletzung der Mandatory-`crit`-Rejection-Regel und familien-abhängiges Verhalten.

**Bewertung (Info):** Von Low herabgestuft auf Exploitierbarkeits-Gründen, nicht auf Korrektheits-Gründen: keine Forgery möglich, keine Privilege-Eskalation; entscheidend führt jSentinel auf **keinem** Pfad `crit`-aware Processing durch (extrahiert nur Standard-Claims), sodass das Ignorieren einer `crit`-Direktive kein divergentes Handling erzeugt — der einzige beobachtbare Unterschied ist Accept-vs-Reject eines bereits vom trusted Issuer signierten Tokens. Modul `@ExperimentalJSentinelApi`. Echter Spec-Compliance-/Cross-Family-Consistency-Defekt.

**Remediation / Härtung:** Symmetrie über alle drei Familien herstellen. Da jSentinel keine `crit`-Extensions versteht, ist der einfachste RFC-7515-§4.1.11-konforme Fix: nach `SignedJWT.parse` (Zeile 164) ablehnen, wenn `getCriticalParams()` non-empty ist und ein Eintrag außerhalb einer explizit verstandenen Menge liegt — idealerweise zentralisiert, sodass RSA/EC- und EdDSA-Zweig einen `crit`-Check teilen und nicht wieder driften. Ein einziger Guard vor dem `alg == EdDSA`-Dispatch schließt die Lücke und future-proof-t weitere Non-Nimbus-Verifier-Zweige.

**Vorgeschlagener Issue-Titel:** `NimbusJwtValidator: crit-Header-Rejection für alle alg-Familien vereinheitlichen (EdDSA-Pfad, RFC 7515 §4.1.11)`

---

### JS-SEC-021 — `DefaultLogoutTokenValidator`: store-loser Konstruktor deaktiviert Replay-Schutz (Info)

**Modul/Datei:** `jSentinel-identity-oidc` — `jSentinel-identity-oidc/src/main/java/com/svenruppert/jsentinel/identity/oidc/DefaultLogoutTokenValidator.java:125-140`

**CWE:** CWE-294: Authentication Bypass by Capture-replay

**Status:** needs-context, Confidence high, teils dokumentiert (JtiStore als „optional" in JavaDoc), aber die Sicherheitskonsequenz des Weglassens nicht.

**Beschreibung:** Der Validator lehnt ein Logout-Token ohne `jti` korrekt ab (127-130, Rationale: infinitely replayable), führt den eigentlichen Single-Use-Replay-Check aber nur aus, wenn ein `JtiStore` übergeben wurde (`if (jtiStore.isPresent())`, Zeile 133). Der No-Store-Constructor `DefaultLogoutTokenValidator(JwtValidator)` (83-85) lässt `jtiStore` leer, sodass ein voll gültiges Logout-Token unbegrenzt replay-bar ist. Zusätzlich wird bei fehlendem `iat` das Retention-Window als `Instant.EPOCH.plus(10min)` berechnet (134), ein bereits abgelaufener Zeitpunkt.

**Angriffsszenario:** Ein RP verdrahtet `DefaultLogoutTokenValidator` ohne `JtiStore`. Ein Angreifer, der ein gültiges Back-Channel-`logout_token` für ein Opfer abfängt, POSTet es wiederholt an den Back-Channel-Endpoint; jeder POST re-runt `SessionRegistry.terminate` für `sid`/`sub` des Opfers — Low-Cost-Forced-Logout-DoS.

**Bewertung (Info):** Von Low herabgestuft: **jede** Konstruktion im Repo (5-minute-setup-oidc.md:79, Hardening-Skill-Template, `LogoutHardeningTest`) nutzt die Store-liefernde Form; der store-lose Constructor hat 0 Caller. `logout_token`s werden OP→RP server-to-server über TLS POSTet (nie via Browser), Replay erfordert MITM dieses Kanals oder Server-Log-Zugriff. Impact self-limiting: ein sid-scoped Replay no-op't nach dem ersten Hit; Re-Logins minten frische `sid` mit frischem Logout-Token. Der `iat→Instant.EPOCH`-Sub-Fall ist near-dead (`requireIat=true` in der empfohlenen Verdrahtung).

**Remediation / Härtung:** Als Defense-in-Depth behandeln. Bevorzugt: den 1-arg-Constructor `DefaultLogoutTokenValidator(JwtValidator)` streichen (0 Caller) und einen `JtiStore` verpflichtend machen, oder auf `new InMemoryJtiStore()` defaulten, sodass ein fehlender Store nie ein stummer No-op ist. Falls die Convenience-Überladung bleibt, einen One-Time-Startup-WARN loggen („back-channel logout replay protection is DISABLED — no JtiStore supplied") und die JavaDoc um die Sicherheitskonsequenz ergänzen. Sekundär Zeile 134 härten, sodass ein fehlendes `iat` das Retention-Window auf `now + JTI_RETENTION` clampt (oder das Token ablehnt) statt `Instant.EPOCH + 10min`.

**Vorgeschlagener Issue-Titel:** `DefaultLogoutTokenValidator: JtiStore verpflichtend machen oder store-losen Constructor mit Startup-WARN versehen (CWE-294)`

---

### JS-SEC-022 — `htu`-Normalisierung mit `URI.getPath` (Full-Decode) über-normalisiert (Info)

**Modul/Datei:** `jSentinel-dpop` — `jSentinel-dpop/src/main/java/com/svenruppert/jsentinel/dpop/DpopHttpUri.java:33-48`

**CWE:** CWE-172: Encoding Error

**Status:** needs-context, Confidence high, teils dokumentiert (Host-Canonicalisation-Edge-Cases als bekannter Nit in RELEASE-NOTES-00.79.10, der Path-Decode-Collapse aber nicht).

**Beschreibung:** `normalize()` baut den `htu`-Binding-Wert aus `uri.getPath()`, das den **percent-decoded** Path liefert (Zeile 40). Dadurch normalisieren distinkte Request-URIs auf denselben `htu`: `/a%2Fb` == `/a/b`. `htu` ist das Per-Endpoint-Binding, das (zusammen mit dem Per-Target-Key im `DpopKeyStore`) verhindern soll, dass ein an einem Pfad gecapturter Proof an einem anderen replay't wird. Das Decoden weitet die Äquivalenzklasse der URIs, an die ein Proof bindet. RFC 9449 `htu`-Vergleich sollte über die normalisierte Request-URI ohne Decoding von Path-Segmenten in andere strukturelle Bedeutung erfolgen.

**Angriffsszenario:** Wo eine Anwendung Ressourcen über encoded Path-Segmente unterscheidet (Gateway, das `/files/%2E%2E/admin` anders behandelt als `/files/../admin`, oder auf encoded Slash routet), bindet ein legitim für eine Form ausgestellter DPoP-Proof nach Normalisierung gleich an die andere — ein gecapturter Proof kann innerhalb seines Freshness-/jti-Windows am Geschwister-Endpoint präsentiert werden.

**Bewertung (Info):** Symmetrische Nutzung (Generator wie Validator rufen dieselbe `normalize()`), also kein Interop-Bruch, nur Äquivalenzklassen-Weitung. Zwei der drei gemeldeten Beispiele (`/%61dmin==/admin`, `%2e%2e==..`) sind RFC-3986-**korrekte** Unreserved-Octet-Normalisierungen; nur `%2F→/` ist echtes Over-Decode. Kein In-Repo-Consumer routet auf encoded-Slash-Distinctions — alle autorisieren auf `getRequestURI().getPath()`, sodass `htu`-Granularität = Enforcement-Granularität. Primärer Replay-Schutz (jti Single-Use) intakt; Modul `@ExperimentalJSentinelApi`. Spec-Fidelity-Nit, nicht exploitierbar in-repo.

**Remediation / Härtung:** Low-Priority-Härtung für Spec-Fidelity. In `normalize()` von `uri.getPath()` auf `uri.getRawPath()` wechseln und nur RFC-3986-§6.2.2-Syntax-basierte Normalisierung anwenden (Hex-Digits uppercase, nur Unreserved-Octets decoden, Dot-Segments entfernen) statt Full-Percent-Decode, sodass Reserved-Octets wie `%2F` nie mit einem Literal-Separator verwechselt werden. Symmetrisch über `DpopProofGenerator` und `NimbusDpopProofValidator`. Zwei der Beispiele (`/%61dmin`, `%2e%2e`) sollen collapsed bleiben. Optional Null-Host-Authorities ablehnen/normalisieren.

**Vorgeschlagener Issue-Titel:** `DpopHttpUri.normalize: getRawPath + RFC-3986-§6.2.2-Normalisierung statt Full-Decode (htu-Over-Normalisierung, CWE-172)`

---

### JS-SEC-023 — DPoP-`ath`-Check opt-in pro Call-Site ohne Fail-Closed-Default (Info)

**Modul/Datei:** `jSentinel-dpop` — `jSentinel-dpop/src/main/java/com/svenruppert/jsentinel/dpop/NimbusDpopProofValidator.java:148-154`

**CWE:** CWE-345: Insufficient Verification of Data Authenticity

**Status:** needs-context, Confidence high, dokumentierte Design-Limitation (Zwei-Profil-API: `of(...)` = Binding-only, `boundTo(...)` = RS mit `ath`).

**Beschreibung:** RFC 9449 §7.1/§4.3 Step 12 verlangt: begleitet ein DPoP-Proof ein Access-Token an einer Protected Resource, MUSS der Proof ein `ath = base64url(SHA-256(access_token))` tragen und dieses MUSS verifiziert werden. Hier läuft der `ath`-Check nur in `if (request.accessToken().isPresent())`. Das Access-Token kommt im `Authorization: DPoP <token>`-Header separat vom `DPoP:`-Proof-Header, sodass ein Integrator den Request leicht via `DpopValidationRequest.of(...)` (kein Token) statt `.boundTo(...)` baut. Dann wird ein Proof mit korrektem Key/htm/htu/iat/jti, aber **ohne** Bindung ans präsentierte Token akzeptiert, und der Validator signalisiert nicht, dass der RFC-Mandatory-`ath`-Check übersprungen wurde.

**Angriffsszenario:** Ein RS-Integrator nutzt `DpopValidationRequest.of(proof, method, uri)` für Protected-Resource-Calls. Ein Angreifer mit einem DPoP-gebundenen Access-Token plus einem separat gecapturten gültigen Proof desselben Client-Keys (Token-Endpoint-Proof, oder Proof für eine andere Ressource im Freshness-Window) paart beide; da `ath` nie geprüft wird, wird das Proof-Token-Pairing akzeptiert.

**Bewertung (Info):** Von Low herabgestuft: die Zwei-Profil-API ist bereits die RFC-9449-korrekte Trennung (Token-Endpoint-Proof hat legitim kein `ath`), Caller wählt den No-`ath`-Pfad explizit. Kein Produktions-Consumer (Modul `@ExperimentalJSentinelApi`, nur Tests rufen `validate`). Die konkreten Pairing-Beispiele werden von always-on-Checks besiegt: htm/htu (126-133) rejecten Token-Endpoint- und Different-Resource-Proofs vor dem `ath`-Gate, Single-Use-jti (156-167) blockt Replay. Der Primär-Sender-Constraint (`cnf.jkt`-Thumbprint) ist intakt.

**Remediation / Härtung:** Zwei-Profil-API beibehalten (`of` = Token-Request/Binding-only, `boundTo` = RS mit `ath`), aber Defense-in-Depth ergänzen: in `validate()` fail-closed (reject), wenn der Proof ein `ath`-Claim trägt und `request.accessToken()` leer ist. Die `DpopValidationRequest.of(...)`-JavaDoc verschärfen, dass sie an einer Protected Resource nie verwendet werden darf, und einen dedizierten RS-Entry-Point erwägen, der das Access-Token verlangt.

**Vorgeschlagener Issue-Titel:** `NimbusDpopProofValidator: fail-closed, wenn Proof ein ath trägt aber kein Token übergeben wird + of()-JavaDoc schärfen (CWE-345)`

---

### JS-SEC-024 — Allow-by-Omission-Autorisierung (unannotierte Routes/Handler sind public) (Info)

**Modul/Datei:** `jSentinel-vaadin` — `jSentinel-vaadin/src/main/java/com/svenruppert/jsentinel/authorization/impl/AuthorizationListener.java:92-123`; zusätzlich `RestAuthorizationFilter.java:142-146`

**CWE:** CWE-862: Missing Authorization

**Status:** confirmed, Confidence high, dokumentierte Design-Limitation (Demo `PublicView` deklariert es ausdrücklich; annotation-getriebene Architektur).

**Beschreibung:** Autorisierung wird nur erzwungen, wenn der Annotation-Scanner eine Restriction-Annotation findet: `AuthorizationListener.beforeEnter` läuft in `scanner.scan(navigationTarget).ifPresent(...)` (Zeile 96, kein Else/Deny-Zweig), der REST-Filter (`authorizeAndHandle` 142-146) führt den Handler direkt aus, wenn `scan()` leer ist. Jede `@Route`/jeder Handler ohne Annotation ist voll public. By-Design und dokumentiert, aber ein Allow-List-by-Omission-Modell: eine vergessene Annotation auf einem sensiblen View/Endpoint exponiert ihn stumm, statt Deny-by-Default.

**Angriffsszenario:** Ein Entwickler fügt einen neuen Admin-View/-Endpoint hinzu und vergisst die `@VisibleFor`/`@RequiresRole`-Annotation. Der Scanner findet nichts, kein Evaluator läuft, die Ressource ist für anonyme oder beliebige authentifizierte User erreichbar — klassische Missing-Authorization-Exposition, die das Framework nicht surfacet.

**Bewertung (Info):** Kein Code-Defekt, korrekt als Info self-rated. Deliberate, dokumentierte Design-Posture; das „Attack" ist ein Entwickler, der eine Annotation vergisst — kein Angreifer-Fähigkeit gegen das ausgelieferte Framework. Partielle Mitigationen existieren opt-in (`RestAuthenticationFilter.requireAuthenticated`, constraint-loses `@SecureRoute()` fail-closed R035). Was fehlt, ist ein Deny-by-Default-Modus oder ein STRICT-Startup-Diagnostic, das wirklich-unannotierte Routes/Handler enumeriert.

**Remediation / Härtung:** Als Info-Härtung führen. Bestehende Per-Endpoint-Mitigationen als empfohlenen Catch-All dokumentieren: `RestAuthenticationFilter.requireAuthenticated(...)` vor jedem annotationslosen REST-Dispatch, constraint-loses `@SecureRoute()` als Vaadin-Äquivalent. Zum Schließen der generellen Lücke: (a) ein Opt-in-Deny-by-Default-Bootstrap-Flag, das un-annotierte `@Route`-Klassen/REST-Handler als denied behandelt, außer sie tragen einen expliziten `@PublicRoute`/`@PermitAll`-Marker; und (b) ein STRICT-Startup-Diagnostic, das jede un-annotierte `@Route`-Klasse und registrierten REST-Handler auflistet (den bestehenden `SecureRouteDiscovery`-Pass erweitern, der heute nur `@SecureRoute`-Policy-Namen meldet).

**Vorgeschlagener Issue-Titel:** `Opt-in-Deny-by-Default + STRICT-Diagnostic für un-annotierte Routes/REST-Handler (Allow-by-Omission, CWE-862)`

---

### JS-SEC-025 — Credentialed-Origin-Lint übersieht `"null"`-Origin (Info)

**Modul/Datei:** `jSentinel-dx-rest` — `jSentinel-dx-rest/src/main/java/com/svenruppert/jsentinel/dx/rest/bootstrap/RestCorsConfiguration.java:78-80`

**CWE:** CWE-942: Permissive Cross-domain Policy with Untrusted Domains

**Status:** confirmed, Confidence high, keine dokumentierte Limitation.

**Beschreibung:** `isCredentialedWildcard()` — das Safety-Net, das in jedem Modus warnt, in STRICT wirft und in PRODUCTION Live-Publish verweigert (`RestJSentinelBootstrapImpl.java:169-197`) — prüft nur `allowedOrigins.contains("*")` zusammen mit `allowCredentials`. Es fängt den gleichermaßen gefährlichen credentialed `"null"`-Origin nicht, den Sandboxed-Iframes, `data:`/`file:`-Dokumente und manche Redirect-Flows präsentieren und den Browser mit Credentials **honorieren** (anders als `"*"`). Der Builder akzeptiert `allowedOrigins("null") + allowCredentials(true)` frei. Die JavaDoc rahmt diesen Guard als Verteidigung gegen ein „account-takeover hole", sodass die Auslassung den erklärten Zweck untergräbt.

**Angriffsszenario:** Ein Entwickler konfiguriert `.cors(c -> c.allowedOrigins("null").allowCredentials(true))` (häufiger Copy-Paste-Fehler zum „lokalen/File-Testing"). Der Bootstrap warnt selbst in STRICT nicht und published die Config. Der App-CORS-Filter reflektiert `Access-Control-Allow-Origin: null` mit `Allow-Credentials: true`. Der Angreifer hostet eine Seite in einem Sandboxed-Iframe/`data:`-URL (Origin `null`), die credentialed Fetches an die API absetzt und authentifizierte Responses liest — Cross-Origin-Credential-Theft.

**Bewertung (Info):** Von Low herabgestuft: `isCredentialedWildcard()` ist ein Entwickler-Advisory-**Lint**, kein Rendering-Control — jSentinel liefert keinen CORS-Filter (kein `Access-Control-*`-Header wird je emittiert). `RestCorsConfiguration` ist ein DTO, das nur die modul-eigenen Tests zurücklesen; kein Library-/Demo-/Skill-Consumer rendert es. Ganze Oberfläche `@ExperimentalJSentinelApi`. Negligible-Impact-Completeness-Lücke in einer experimentellen Defense-in-Depth-Heuristik.

**Remediation / Härtung:** Low-Cost-Härtung des Advisory-Lints. Den Credentialed-Origin-Check erweitern, sodass `allowCredentials(true)` kombiniert mit einem `allowedOrigins`-Eintrag gleich `"null"` (case-insensitive) denselben ERROR-Warning-Pfad triggert (STRICT-Throw + PRODUCTION-Refuse-Publish); optional eine leere `allowedOrigins`-Liste flaggen, die downstream als Reflect-Any interpretiert wird. Den bestehenden `cors/wildcard-with-credentials`-ERROR wiederverwenden oder einen `cors/credentialed-null-origin`-Geschwister-ERROR ergänzen. Ebenso dokumentieren (JavaDoc + Release-Note), dass diese Methode ein Best-Effort-Developer-Lint und **kein** Header-Rendering-Control ist.

**Vorgeschlagener Issue-Titel:** `RestCorsConfiguration: credentialed "null"-Origin im isCredentialedWildcard-Lint erfassen + Lint-vs-Control-Doku (CWE-942)`

---

### JS-SEC-026 — `RestSecurity.bootstrap()` `decisionMapper`/`errorBodies` recorded-not-wired (Info)

**Modul/Datei:** `jSentinel-dx-rest` (Enforcement in `jSentinel-rest`) — `jSentinel-rest/src/main/java/com/svenruppert/jsentinel/rest/RestAuthorizationFilter.java:60-75`; `RestJSentinelBootstrapImpl.java:133-155`

**CWE:** CWE-1188: Insecure Default Initialization of Resource

**Status:** confirmed, Confidence high, keine dokumentierte Limitation — inkonsistent zur R029-Behandlung (V00.75.20) der Geschwister-Features.

**Beschreibung:** `RestJSentinelBootstrapImpl.install()` (133-155) resolvt einen effektiven `RestDecisionMapper` und eine `RestErrorBodyStrategy` (inkl. `ProblemJsonErrorBodyStrategy` via `.problemJsonErrors()`/`.errorBodies(...)`), speichert sie aber nur als `RegisteredJSentinelService`-Einträge. Der Enforcement-Pfad `RestAuthorizationFilter` hard-wired `new HttpStatusDecisionMapper()` in beiden Constructoren (Zeilen 65, 73) und wird direkt von der App instanziiert (`new RestAuthorizationFilter(subjectResolver)`); er konsumiert nie den bootstrap-konfigurierten Mapper/die Error-Body-Strategy, und nichts in `jSentinel-rest` liest sie aus einem Registry zurück. Ein Entwickler, der `.decisionMapper(...)`/`.errorBodies(...)` aufruft, um Denial-Verhalten zu ändern, erhält keinen Runtime-Effekt.

**Angriffsszenario:** Kein direkter Angreifer-Exploit. Impact ist eine sicherheitsrelevante Fehlvorstellung: ein Operator konfiguriert `.errorBodies(customStrategy)` oder einen strengeren `decisionMapper` im Glauben, das härte die Denial-Responses; der enforcierende Filter ignoriert es stumm, während Diagnostics die Strategy als „registered" melden.

**Bewertung (Info):** Korrekt als Info-Floor. Der tatsächlich laufende Default (`HttpStatusDecisionMapper` + generische `"Unauthorized"`/`"Forbidden"`) ist fail-closed und **konservativer** als die ignorierte Custom-Strategy (die häufigste Wahl `ProblemJsonErrorBodyStrategy` exponiert mehr strukturiertes Detail) — stummes Ignorieren leakt strikt weniger. Echter Defekt: Diagnostic-Honesty/DX, inkonsistent zu R029, der genau dies für die Geschwister (`rateLimit`/`apiKeys`/`refreshTokens`) zu `dx/<feature>-recorded-not-wired`-INFO machte.

**Remediation / Härtung:** Bevorzugt das R029-Präzedens (V00.75.20) anwenden: `RestDecisionMapper`/`RestErrorBodyStrategy` nicht mehr als `RegisteredJSentinelService` emittieren, sondern als INFO `dx/rest-decision-mapper-recorded-not-wired` / `dx/rest-error-body-recorded-not-wired` surfacen und aus dem `BootstrapState` lesbar halten. Parallel tatsächlich verdrahten: effektive Instanzen über einen Holder analog `RestCorsContext` publizieren (`RestDecisionContext.publish/decisionMapper()/errorBodies()`) und `RestAuthorizationFilter` einen Constructor/eine Overload geben, der `RestDecisionMapper` + `RestErrorBodyStrategy` annimmt (adaptiert `HttpStatusDecisionMapper`), oder den Holder lesen lassen; demo-rest + `jsentinel-rest`-Skill (SKILL.md:85) entsprechend aktualisieren. Minimum: in JavaDoc + Startup-Log dokumentieren, dass dies Integration-Hints sind, die die App selbst anwenden muss.

**Vorgeschlagener Issue-Titel:** `RestSecurity: decisionMapper/errorBodies verdrahten oder als recorded-not-wired-INFO surfacen (R029-Angleichung, CWE-1188)`

---

### JS-SEC-027 — Drift-Snapshot-Capture ist Best-Effort-No-op auf dem Raw-`LoginView`-Pfad (Info)

**Modul/Datei:** `jSentinel-vaadin` — `jSentinel-vaadin/src/main/java/com/svenruppert/jsentinel/authorization/LoginView.java:220-251`

**CWE:** CWE-636: Not Failing Securely ('Failing Open')

**Status:** needs-context, Confidence high, dokumentierte Design-Limitation (LoginView-JavaDoc deklariert den „strict three-way no-op"; DX-Bootstrap gated denselben Fall bereits mit ERROR/STRICT-Exception).

**Beschreibung:** `captureJSentinelVersionSnapshot()` ist die einzige Stelle, die den Drift-Snapshot nach dem Login aufzeichnet. Es ist ein Best-Effort-No-op: es kehrt still zurück, wenn `JSentinelVersionStore` oder `SubjectIdResolver` fehlen (223-235), und der Catch-Block swallowt jede `RuntimeException` (248-250, nur WARN). Registriert eine App den `JSentinelVersionEnforcerListener` und einen Version-Store, vergisst aber den `SubjectIdResolver`, wird nie ein Snapshot aufgezeichnet, der Enforcer sieht auf jeder Navigation einen leeren Snapshot und lässt alles durch (81-83 = Pass-Through) — Drift-Detection ist stumm deaktiviert, während die App sie für aktiv hält. Der DX-Bootstrap emittiert für diese Fehlkonfiguration ein ERROR (`security-version-without-subject-id-resolver`); der Non-DX-`LoginView`-Pfad hat kein solches Signal.

**Angriffsszenario:** Ein Operator verdrahtet Drift-Detection (Enforcer-Listener + Version-Store), aber der `SubjectIdResolver` ist nicht auf dem Classpath/registriert. Logins gelingen, kein Snapshot wird gecaptured, jede Navigation passiert den Drift-Check unbedingt. Ein späterer Role-Revoke + Version-Bump wird nie erzwungen, ohne Runtime-Warning, dass die Kontrolle inert ist.

**Bewertung (Info):** Documented-by-design; der empfohlene DX-Bootstrap-Pfad failt laut (Severity ERROR, in V00.73 zur STRICT-Exception promoted — eine STRICT-DX-App bootet mit Store-aber-ohne-Resolver nicht). Inert-by-construction (der Store ist auf `JSentinelVersionKey(TenantId, SubjectId)` gekeyt, ohne Resolver kann der Stack nie funktionieren — es gab nie eine funktionierende Kontrolle zu verlieren). Kein Base-Authorization-Bypass (`AuthorizationListener` evaluiert weiter jede Navigation). Legitimer Rest: der Resolver-Absent-Zweig emittiert null Log.

**Remediation / Härtung:** Keine Korrektheits-Änderung nötig — Verhalten ist documented-by-design und der empfohlene DX-Pfad failt bereits laut. Als Low-Priority-Defense-in-Depth **nur auf dem Manual-Wiring-Pfad**: `LoginView` einen One-Time-WARN (nicht pro Login) emittieren lassen, wenn ein `JSentinelVersionStore` vorhanden ist, aber kein `SubjectIdResolver` resolvbar ist, analog zum DX-Diagnostic, sodass Manual-SPI-Integratoren ein Runtime-Signal erhalten. Den Login-Flow nicht failen.

**Vorgeschlagener Issue-Titel:** `LoginView: One-Time-WARN, wenn Drift-Enforcer aktiv aber Snapshot-Capture mangels SubjectIdResolver inert ist (CWE-636)`

---

### JS-SEC-028 — OIDC-Logout-Basisklasse delegiert lokalen Session-Teardown an Hook (Info)

**Modul/Datei:** `jSentinel-identity-oidc-vaadin` — `jSentinel-identity-oidc-vaadin/src/main/java/com/svenruppert/jsentinel/identity/oidc/vaadin/AbstractOidcLogoutView.java:36-56`

**CWE:** CWE-613: Insufficient Session Expiration

**Status:** needs-context, Confidence high, dokumentierte Design-Limitation (Klassen-JavaDoc weist an, die Session in `onBeforeLogout()` abzubauen; Single-Logout-Härtung explizit auf V00.79+ vertagt).

**Beschreibung:** `AbstractOidcLogoutView` ist eine ausgelieferte Library-Basisklasse für die RP-initiated-Logout-Route. Ihr `beforeEnter` ruft `onBeforeLogout()` (Default: leerer No-op, Zeile 47) und redirected dann den Browser zum OP-`end_session_endpoint` (51-55). Ein Entwickler, der nur die abstrakten `endSessionEndpoint()`/`logoutRequest()` implementiert, erhält einen „Logout", der die OP-Session beendet, aber die lokale Vaadin-Session/das Subject voll authentifiziert lässt — der `SubjectStore` wird nie geleert, die HTTP-Session nie invalidiert. Da die Klasse `LogoutView` heißt, ist der insecure Default ein Footgun.

**Angriffsszenario:** Ein User klickt „Logout"; die App redirected zum IdP-End-Session-Endpoint, aber die lokale Vaadin-Session bleibt authentifiziert (Subject noch gecached). Auf einem Shared-/Kiosk-Rechner, oder wenn der Browser-Back-Button zur App zurückkehrt, landet der nächste Besucher in der noch-authentifizierten Session und kann als voriger User agieren.

**Bewertung (Info):** Von Low herabgestuft: Typ ist **abstract** (läuft nie as-is); die Klassen-JavaDoc mandatiert das korrekte Muster; jede Referenz-Implementierung (Skill-Template `OidcLogoutView.java.tmpl`, SKILL.md §160) baut die Session korrekt ab; kein `extends AbstractOidcLogoutView`-Consumer ohne Override im Repo. `@ExperimentalJSentinelApi` V00.78-Typen, Single-Logout-Härtung auf V00.79+ vertagt. Misuse-Resistance-/Secure-by-Default-Gelegenheit, keine Live-Vulnerability.

**Remediation / Härtung:** Optionale Härtung (Misuse-Resistance): da `jSentinel-identity-oidc-vaadin` bereits von `jSentinel-vaadin` abhängt (`VaadinSessionSubjectStore` ist auf dem Classpath), lokalen Teardown zum Default innerhalb `beforeEnter()` machen — das aktuelle Subject vor dem Redirect clearen — und `onBeforeLogout()` zu einem additiven Extension-Hook statt dem einzigen Teardown-Pfad degradieren. Eine laute `@implSpec`-Notiz ergänzen, die warnt, dass eine Subklasse, die den Default unterdrückt, die RP-Session nach OP-Session-Ende authentifiziert lässt. Den Login-Flow nicht failen.

**Vorgeschlagener Issue-Titel:** `AbstractOidcLogoutView: lokalen Session-Teardown zum Default machen + @implSpec-Warnung (Secure-by-Default, CWE-613)`

---

## Empfohlene Reihenfolge

Priorisiert nach „Secure-by-Default-Fehler auf einem ausgelieferten Pfad" zuerst, dann billige Fixes mit hohem Aufräum-Wert, zuletzt experimentelle/dormant Härtungen.

1. **JS-SEC-003 (Session Fixation)** und **JS-SEC-002 (Mid-Session-Revocation)** zuerst — beide besiegen eine kanonische bzw. ausdrücklich beworbene Kontrolle auf dem Shipped-Pfad; selbst der Hardening-Layer lässt JS-SEC-003 offen. Höchster Real-World-Wert, klare Fixes.
2. **JS-SEC-004 (Audit-PII-Leak)** — unvollständige Remediation einer bereits anerkannten Leak-Klasse (R14), billiger, mechanischer Fix (zwei `subjectIdOf` über den Resolver routen), schließt eine bekannte Lücke halb-offen.
3. **JS-SEC-001 (JWKS-DoS)** — vollständig unauthentifiziert, trivial auslösbar, widerspricht direkt einer Release-Notes-Zusage; Fix ist lokal und günstig.
4. Fail-Open-Härtung auf der stabilen Authz-Oberfläche: **JS-SEC-010** und **JS-SEC-011** — ein-Zeilen-Guards, entfernen echte Footguns auf Stable API und sollten zusammen mit der Zentralisierung der Empty-Constraint-Regel gelandet werden.
5. Trust-Boundary-Input-Härtung, jeweils ein zentraler Guard: **JS-SEC-013 (CRLF-Header)** und **JS-SEC-019 (CRLF-Log)** — kleine Fixes, schützen die Library unabhängig vom Consumer.
6. JWT/OIDC-Konsistenz und Doku-Wahrheit: **JS-SEC-018**, **JS-SEC-005**, **JS-SEC-007**, **JS-SEC-006** — schließen widersprüchliche JavaDoc/Release-Notes-Zusagen und OIDC-Backstops; überwiegend Observability/Backstop, kein Live-Loch.
7. Filesystem-Confidentiality: **JS-SEC-016** und **JS-SEC-017** — dasselbe `OWNER_*`-Muster wiederverwenden, deployment-abhängige lokale Exposition schließen.
8. Propagation-Cache-Härtung: **JS-SEC-015** (unbounded) vor **JS-SEC-014** (Cache-Key-Scope) — beide dormant/experimentell.
9. **JS-SEC-008 / JS-SEC-009 / JS-SEC-012** — Doku-Ehrlichkeit + optionale Parität/Cost-Floor; hauptsächlich Korrektur überzeichneter Garantien.
10. Info-Backlog zuletzt (**JS-SEC-020–028**): Spec-Fidelity- und Secure-by-Default-Misuse-Resistance-Items auf experimentellen Oberflächen; als Routine-Härtung einplanen. **JS-SEC-024** (Deny-by-Default-Diagnostic) und **JS-SEC-026** (recorded-not-wired R029-Angleichung) haben davon den höchsten DX-Wert.

## Methodik & Grenzen

Das Audit lief als reines Source-Review über die Library-Module (`jSentinel-*`) entlang von 12 Finder-Dimensionen; jeder Kandidat wurde adversarial gegen die real erreichbaren Codepfade, die Referenz-Skills/-Demos und die Konzept-/Release-Notes-Dokumente verifiziert, wobei Schweregrade nach tatsächlicher Reachability und Exploitierbarkeit korrigiert und widerlegte Befunde entfernt wurden (die 28 verbleibenden Findings sind mit `file:line` belegt). Es handelt sich **nicht** um einen Penetrationstest: es wurden keine laufenden Deployments, keine dynamische Instrumentierung und keine Netzwerk-/Zeitmessungen gegen eine Live-Instanz durchgeführt, sodass insbesondere die Timing- (JS-SEC-009) und DoS-Magnituden (JS-SEC-001, JS-SEC-008, JS-SEC-015) statische Einschätzungen sind. Als statische Analyse trägt der Bericht ein inhärentes False-Negative-Risiko — Schwächen in ungelesenen Pfaden, in transitiven Dependencies (Vaadin, Nimbus, Eclipse-Store, BouncyCastle) oder erst zur Laufzeit aus Konfiguration/SPI-Wiring entstehende Probleme können unentdeckt geblieben sein. Die `demo-*`-Module wurden ausschließlich stichprobenartig zur Reachability- und Consumer-Pattern-Prüfung herangezogen und nicht systematisch auf eigene Schwachstellen untersucht; ihre bekannte Pre-Existing-Debt ist bewusst außerhalb des Scopes.