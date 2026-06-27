# Konzept V00.75.10: Core-Hardening + Robustheit + Statik-Gate

Version: `00.75.10-SNAPSHOT`
Quellstand: V00.75.00 (Security Event Bus, feature-complete, released)
Zielprojekt: `vaadin-developer/security-for-flow`
Zielbranch: `develop`
Java: `26+`
Build: Maven 4
Lizenz: EUPL 1.2
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

`V00.75.10` ist ein **Hardening- und Robustheits-Tick** auf der bereits
aktiven Maintenance-Linie nach V00.75.00, bevor der OIDC/OAuth2/JWT-Bogen
(V00.76 – V00.79) beginnt. Es führt **keine neue Fachfunktion** und **kein
neues Fachmodul** ein. Es schließt sechs Befunde aus einem externen
Code-Review, die alle am echten Quellcode verifiziert wurden.

Der Charakter ist bewusst defensiv: Typsicherheit dort herstellen, wo
heute nur ein Kommentar vor Fehlgebrauch schützt; ungetestete Fehlpfade
durch Tests festnageln; manuelle Parser gegen kaputten Input härten; den
REST-Transport sauber abbilden; und den großen Architektur-Schuldposten
(globaler statischer Service-Resolver) angehen.

Sechs Arbeitsblöcke (H = Hardening):

1. **H1 — Token-Digest-Typsicherheit.** `TokenService`,
   `PasswordResetService` und `EmailVerificationService` speichern
   Token-Hashes über den `PasswordHasher`-Typ und suchen sie per Hash
   wieder. Mit der gesalzenen Produktiv-Impl (`Pbkdf2PasswordHasher`)
   ist die Wiederfindung strukturell unmöglich. Neuer schmaler
   `TokenHasher`-Vertrag (deterministisch) + `Sha256TokenHasher` in den
   Kern; die alten `PasswordHasher`-Konstruktoren werden deprecatet und
   bekommen einen Laufzeit-Determinismus-Guard.
2. **H2 — Negativtest gegen den Fehlgebrauch.** Ein Test mit echtem
   `Pbkdf2PasswordHasher` beweist, dass Rotation fehlschlägt bzw. der
   Konstruktor ablehnt — kein Mock, echte Impl.
3. **H3 — Statische Analyse als CI-Gate.** `spotbugs.skip=true` fällt
   für `jSentinel-core` / `jSentinel-rest` / `jSentinel-events-*`;
   SpotBugs (+ FindSecBugs) wird als Gate aktiviert. Der bewusst
   begründete Javadoc-`failOnError=false` bleibt unverändert.
4. **H4 — Manuelle JSON-Parser härten.** `WireJson` kapselt alle
   Parserfehler in `EventWireException` (Defense-in-Depth — der
   Decode-Rand netzt heute schon via `Result`, soll aber nicht darauf
   angewiesen sein) + Fuzz-/Malformed-Tests. `JsonResponse` (OIDC)
   bekommt einen echten Guard gegen den ungeschützten
   `Long.parseLong`-Overflow.
5. **H5 — Globaler Service-Resolver entschärfen.** `JSentinelServiceResolver`
   (1028 Zeilen, 32 statische `AtomicReference`-Felder, 10 statische
   Setter, `resetAll()`) wird hinter einen **instanziierbaren
   `JSentinelContext`** gelegt. Die statische Fassade bleibt als
   delegierender Default erhalten (abwärtskompatibel) — aber parallele
   Tests und Multi-App-Embedding werden möglich.
6. **H6 — REST-Transport robuster.** `HttpExchangeRestRequest`
   propagiert `UncheckedIOException` ungemappt; Query-Parameter werden
   nicht URL-dekodiert. Beides wird geschlossen.

V00.75.10 ist additiv über V00.75.00. Die berührten Typen tragen
`@ExperimentalJSentinelApi` (siehe §7); ihre Form darf sich daher in
diesem Tick noch ändern.

---

## 2. Scope-Charakter

V00.75.10 folgt dem etablierten Zehner-Muster (V00.71.10, V00.74.10,
V00.74.20): ein schlanker Snapshot zwischen Major-Feature-Bumps. Die
Patch-Stelle (`00.75.01`, …) bleibt für reine Crash-/Sicherheitspatches
reserviert; der Zehner-Sprung markiert einen bewussten
Hardening-Snapshot.

Abweichend von V00.74.10 ist V00.75.10 **kein DX-Polish, sondern
Substanz-Hardening** — es berührt Kern-Verträge (`TokenHasher`,
`JSentinelContext`) und schaltet ein CI-Gate scharf. Entsprechend sind
die Akzeptanzkriterien (§8) strenger als bei einem reinen Polish-Tick.

Der Scope umfasst **alle sechs Review-Befunde voll ausspezifiziert**,
einschließlich des großen Resolver-Umbaus (H5). H5 ist bewusst so
geschnitten, dass er **abwärtskompatibel** bleibt (statische Fassade
delegiert an einen Default-Context) — der invasive Teil (Konsumenten auf
explizite Contexts umstellen) bleibt optional und wird nicht erzwungen.

---

## 3. Herkunft des Scopes

Die sechs Blöcke stammen aus einem externen Review (2026-06-24), das
gegen den realen Reactor-Stand gegengeprüft wurde. Verifikations-Ergebnis
je Punkt (relevant für die Severity-Gewichtung):

| Befund | Status | Severity | Anmerkung |
|---|---|---|---|
| H1 Token-Hasher-Typ | bestätigt | **hoch** | kein Live-Bug — Demo wired deterministisch (`Sha256TokenHasher`) + Warnkommentar; aber Compiler schützt nicht |
| H2 fehlender Negativtest | bestätigt | hoch | `TokenServiceTest` nutzt nur `FakeHasher`; Smoke-Test prüft nur Längen |
| H3 Statik aus | bestätigt | mittel | SpotBugs global aus; Javadoc-Skip dagegen bewusst begründet (kein Befund) |
| H4 Parser-Robustheit | bestätigt | mittel | events-rest-Publish ist durch `Result`-Rand genetzt (defense-in-depth nötig); OIDC `parseLong` echt ungeschützt |
| H5 Resolver-State | bestätigt | mittel/strukturell | 1028 Zeilen, 32 `AtomicReference`, `resetAll()` ist der Beleg |
| H6 REST-Transport | bestätigt | mittel | `UncheckedIOException` ungemappt; Query-Params nicht URL-dekodiert |

Wichtige Severity-Korrektur gegenüber der Review-Vorlage: H1 ist eine
**Design-/Typsicherheits-Falle, kein ausgelieferter Bug** — die einzige
Produktiv-Verdrahtung (`DemoRestServer`) injiziert deterministische
Hasher und trägt einen expliziten Warnkommentar. Und H4 ist im
events-rest-Publish-Pfad weniger kritisch als zunächst gelesen, weil
`EnvelopeWireCodec.decode()` das Parsen in einen
`CheckedSupplier`/`Result` kapselt, der jedes `Throwable` auf einen
generischen Fehlerstring abbildet (→ `400 "Malformed envelope"`, kein
ungebehandeltes 500). Die echte ungeschützte Stelle ist `JsonResponse`
im OIDC-Propagation-Modul.

---

## 4. Arbeitsblöcke im Detail

### 4.1 H1 — Token-Digest-Typsicherheit

**Problem.** Drei V00.70-Services hashen ein Klartext-Token und suchen es
später per Hash:

- `TokenService.issue/rotate` (`jSentinel-core/authentication`) —
  `hasher.hash(refreshPlain)` → `store.save` / `store.findByHash`.
- `PasswordResetService.request/validate`
  (`jSentinel-core/accountlifecycle`) — identisches Muster.
- `EmailVerificationService.request/validate` — identisches Muster.

Alle drei nehmen einen `PasswordHasher`. Dessen Produktiv-Impl
`Pbkdf2PasswordHasher.hash()` zieht pro Aufruf einen frischen
`SecureRandom`-Salt → derselbe Klartext erzeugt jedes Mal einen anderen
Hash → `findByHash` matcht nie → Rotation/Validierung schlägt **immer**
fehl. Korrektheit hängt heute ausschließlich daran, dass der Konsument
einen *deterministischen* Hasher einsetzt — ein Kommentar in
`DemoRestServer` (Z. 155–158) ist die einzige „Sicherung".

Verschärfend: Der einzige deterministische Hasher des Projekts,
`Sha256TokenHasher`, lebt **im Demo** (`demo-rest`), nicht in der
Library. Das Framework liefert für „Token speichern und per Hash
wiederfinden" keinen typgesicherten, mitgelieferten Pfad — obwohl
`TokenDigestService` (V00.71 Phase-3) das Problem in seiner eigenen
JavaDoc exakt benennt (CWE-208 / CWE-640: „random-salt KDFs cannot be
looked up by hash").

**Designentscheidung.** Wir trennen den Token-Digest-Vertrag vom
Passwort-Hashing-Vertrag — auf Typebene, nicht per Kommentar.

1. Neuer schmaler Vertrag in `jSentinel-core/credential/token`:

```java
/**
 * Deterministic digest for high-entropy tokens (selector/refresh/
 * verification tokens). Same input → same output, NO per-call salt —
 * the digest must be looked up by value. Implementations MUST NOT use a
 * random-salt KDF (CWE-208 / CWE-640).
 */
@ExperimentalJSentinelApi
public interface TokenHasher {
  String hash(char[] token);
}
```

2. `Sha256TokenHasher` wandert aus `demo-rest` in den Kern als
   mitgelieferte Default-Impl (SHA-256 über die Token-Bytes; identisch
   zur Rationale in `TokenDigestService` Z. 46–49). Das Demo nutzt
   künftig die Library-Variante.

3. Die drei Services bekommen `TokenHasher`-Konstruktoren. Die alten
   `PasswordHasher`-Konstruktoren werden `@Deprecated(forRemoval = true)`
   und delegieren während des Deprecation-Fensters über einen Adapter —
   **mit Determinismus-Guard** (Defense-in-Depth, Option B des Reviews):

```java
// Im PasswordHasher→TokenHasher-Adapter, einmalig bei Konstruktion:
String a = delegate.hash(PROBE);
String b = delegate.hash(PROBE);
if (!a.equals(b)) {
  throw new IllegalArgumentException(
      "TokenService requires a deterministic hasher; the supplied "
      + delegate.getClass().getSimpleName()
      + " is salted (its hash() is non-deterministic) and cannot be "
      + "looked up by value. Use a TokenHasher (e.g. Sha256TokenHasher).");
}
```

Damit schlägt ein versehentlich übergebener `Pbkdf2PasswordHasher`
**sofort beim Konstruieren** fehl — laut und mit klarer Botschaft —
statt still bei jeder Rotation. Der Compiler-Pfad (neuer Typ) ist die
primäre Sicherung; der Guard fängt den verbleibenden
Deprecation-Pfad ab.

**Bewusst NICHT in H1.** Die volle Migration der drei Services auf das
reichere Selector/Verifier-Modell von `TokenDigestService` (zwei
Felder, Constant-Time-Vergleich) ist ein größerer Umbau mit
Store-Schema-Wirkung (`RefreshTokenRecord`, `PasswordResetTokenRecord`,
`EmailVerificationTokenRecord`). Sie bleibt ein dokumentierter
Folge-Kandidat (frühestens V00.76, gekoppelt an die JWT-Arbeit). H1
schließt die **Typsicherheitslücke**; es vereinheitlicht nicht das
Token-Modell.

### 4.2 H2 — Negativtest gegen den Fehlgebrauch

**Problem.** `TokenServiceTest` nutzt durchgängig einen deterministischen
`FakeHasher` (Z. 52–59); der „Smoke-Test" (Z. 311) prüft nur
Tokenlängen. Es gibt keinen Test, der den gefährlichen Pfad — gesalzener
Hasher — überhaupt berührt. Dasselbe gilt für `PasswordResetServiceTest`
und `EmailVerificationServiceTest`.

**Lift.** Je Service ein Negativtest mit **echtem** `Pbkdf2PasswordHasher`
(keine Mocks, Memory-Disziplin):

- Über den (deprecateten) `PasswordHasher`-Konstruktor: erwartet
  `IllegalArgumentException` aus dem Determinismus-Guard (H1).
- Zusätzlich ein Test, der ohne Guard (theoretisch) zeigt, dass
  `rotate()` / `validate()` bei salted Hash leer zurückkäme — als
  Dokumentation des Grundes, warum der Guard existiert. Umsetzung über
  einen lokalen, absichtlich nicht-deterministischen `TokenHasher`-Stub
  (deterministischer Aufbau, salted Output), damit der Test den
  Mechanismus prüft, nicht die JCA.

Damit ist der Kontrakt „dieser Service braucht einen deterministischen
Digest" testgebunden und kann nicht stillschweigend wegregressieren.

### 4.3 H3 — Statische Analyse als CI-Gate

**Problem.** `pom.xml` Z. 144: `spotbugs.skip=true` (reaktorweit aus).
Für ein Security-Framework ist eine dauerhaft abgeschaltete
Bytecode-Statik ein Lücke.

**Lift.**

1. SpotBugs + **FindSecBugs**-Plugin als Gate für die
   sicherheitskritischen Kernmodule **zuerst**: `jSentinel-core`,
   `jSentinel-rest`, `jSentinel-events-api`, `jSentinel-events-bus`,
   `jSentinel-events-rest`. Aktivierung modul-lokal über ein
   Maven-Profil (`-Pstatic-analysis`), das im CI-Lauf gesetzt wird;
   lokal bleibt der Schnellbau unbelastet.
2. Einstieg auf `threshold=Medium`, `effort=Max`, mit einem
   **Baseline-Excludes-File** (`spotbugs-exclude.xml`) für die beim
   Erstlauf gefundenen Bestands-Findings — damit das Gate sofort grün
   ist und nur **neue** Findings bricht. Bestands-Findings werden als
   Backlog-Tickets dokumentiert, nicht im selben Tick abgearbeitet.
3. Die übrigen Module (DX, Adapter, Persistence, Demos) folgen in einem
   späteren Tick; ihr `spotbugs.skip` bleibt vorerst.

**Bewusst KEIN Befund.** Der Javadoc-`failOnError=false` (Z. 470) bleibt
unangetastet: er ist mit der modulübergreifenden `@link`-Layering-Realität
explizit begründet (Z. 463–469) und kein Schludern. Error Prone /
Semgrep werden als **Option** dokumentiert (§6), aber nicht im
V00.75.10-Scope aktiviert — ein Statik-Tool scharf zu schalten reicht
für einen Tick; zwei parallel einzuführen erzeugt Noise-Overlap.

### 4.4 H4 — Manuelle JSON-Parser härten

**Problem A — `WireJson` (events-rest).** `string()` wirft bei
abgeschnittenem `\`-Escape (Z. 162: `s.charAt(pos++)`) und bei kaputtem
`\u` (Z. 173: `substring` / `Integer.parseInt`) rohe
`StringIndexOutOfBoundsException` / `NumberFormatException` statt der
Domänen-`EventWireException`. **Einordnung:** Der Publish-Pfad ist heute
durch den `CheckedSupplier`/`Result`-Rand in `EnvelopeWireCodec.decode()`
genetzt (jedes `Throwable` → generischer Fehlerstring → `400`), also
**kein** ungebehandeltes 500. Der Lift ist **Defense-in-Depth**: der
Parser soll seinen Vertrag selbst halten und nicht auf das Catch-all des
Aufrufers angewiesen sein (ein künftiger Aufrufer ohne `Result`-Rand
würde sonst leak­en).

**Problem B — `JsonResponse` (OIDC-Propagation).** Regex-Extraktion mit
`expiresIn()` Z. 53: `Long.parseLong(m.group(1))` über `(\d+)` —
ein sehr langer Ziffernlauf läuft über → **ungefangene**
`NumberFormatException`, die direkt an den Aufrufer propagiert. Hier gibt
es keinen `Result`-Rand. Das ist die genuin ungeschützte Stelle.

**Lift.**

1. `WireJson`: jede `charAt` / `substring` / `parseInt`-Stelle gegen
   Längen-Unterlauf prüfen und alle Parserfehler in `EventWireException`
   kapseln (lone-backslash, truncated `\u`, non-hex `\u`,
   `number()`-Überlauf). Kein Verhaltenswechsel am Publish-Rand — die
   Fehler heißen nur jetzt konsistent `EventWireException` statt JDK-roh.
2. **Fuzz-/Malformed-Korpus-Test** für `WireJson`: ein Test, der eine
   Liste kaputter Eingaben (truncated escapes, unterminated strings,
   missing colons, trailing garbage, riesige Zahlen, tiefe
   Verschachtelung) durchläuft und für **jede** entweder
   `EventWireException` **oder** ein sauberes Ergebnis verlangt — **nie**
   eine JDK-RuntimeException. Property-artig über einen festen, im Test
   eingebetteten Korpus (deterministisch, kein Zufall — Memory-Disziplin
   gegen `Math.random()`).
3. `JsonResponse.expiresIn()`: `parseLong` in `try/catch` →
   `Optional.empty()` bei Overflow/Non-Numeric (die Methode gibt bereits
   `Optional<Long>` zurück — der leere Fall ist die korrekte Antwort auf
   einen kaputten Wert). Begleitende Malformed-Tests (overlong digits,
   fehlende Felder, Wert in verschachteltem Objekt).

### 4.5 H5 — Globalen Service-Resolver entschärfen

**Problem.** `JSentinelServiceResolver`
(`jSentinel-core/authorization/api`) ist ein **statischer globaler
Service-Locator**: 1028 Zeilen, 32 statische `AtomicReference`-Felder, 10
statische Setter, plus `resetAll()` (Z. 971). Die bloße Existenz von
`resetAll()` ist der Beleg für die Kritik:

- **Parallele Tests unmöglich.** Tests teilen globalen mutablen Zustand
  und müssen `resetAll()` aufrufen — JUnit-Parallelisierung würde
  Cross-Test-Leakage erzeugen.
- **Multi-App-Embedding unmöglich.** Zwei unterschiedlich konfigurierte
  jSentinel-Runtimes in einer JVM (z. B. zwei Mandanten-Apps, oder
  Embedding in einem größeren Host) können nicht koexistieren — es gibt
  genau einen globalen Satz Services.

V00.72 hat mit `JSentinelRuntime` bereits eine objektorientierte
Sicht eingeführt, aber die **Backing-Schicht** ist weiterhin der globale
statische Resolver.

**Designentscheidung — abwärtskompatibler Context-Lift.** Wir führen
einen instanziierbaren `JSentinelContext` ein, der die 32 Referenzen
**als Instanzfelder** hält. Die bestehende statische Fassade bleibt
erhalten und **delegiert an einen prozessweiten Default-Context**:

```java
@ExperimentalJSentinelApi
public final class JSentinelContext {
  // 32 Felder, vormals statische AtomicReferences — jetzt pro Instanz
  public Optional<JSentinelAuditService> securityAuditService() { ... }
  public void setSecurityAuditService(JSentinelAuditService svc) { ... }
  // ... alle bisherigen Accessor/Setter, instanzgebunden
  public void resetAll() { ... }  // jetzt nur DIESE Instanz

  public static JSentinelContext createIsolated() { return new JSentinelContext(); }
}

public final class JSentinelServiceResolver {
  private static final JSentinelContext DEFAULT = new JSentinelContext();
  public static JSentinelContext current() { return DEFAULT; }

  // Alle bisherigen statischen Methoden bleiben — delegieren an DEFAULT:
  public static Optional<JSentinelAuditService> securityAuditService() {
    return DEFAULT.securityAuditService();
  }
  public static void resetAll() { DEFAULT.resetAll(); }
  // ...
}
```

**Wirkung:**

- **Bestandscode kompiliert unverändert.** Jeder bestehende
  `JSentinelServiceResolver.securityAuditService()`-Aufruf (u. a. in
  `DemoRestServer`) bleibt gültig und trifft den Default-Context.
- **Neue Tests** können `JSentinelContext.createIsolated()` nutzen und
  laufen damit parallelisierbar, ohne `resetAll()`-Ritual.
- **Multi-App-Embedding** wird möglich, sobald ein Konsument seinen
  eigenen Context durchreicht (opt-in, nicht erzwungen in diesem Tick).

**Bewusst NICHT in H5.** Das *Durchreichen* des Context durch alle
Adapter (Vaadin-Session-gebunden, REST-Request-gebunden, Standalone-
ThreadLocal) ist der invasive Teil und bleibt späteren Versionen
vorbehalten. H5 liefert die **Struktur** (instanziierbarer Context +
delegierende Fassade), nicht die flächendeckende Umstellung. Die
statische Fassade wird **nicht** deprecatet — sie bleibt der bequeme
Default-Pfad für Single-App-Konsumenten.

**Aufteilung in Capability-Resolver** (Review-Alternativvorschlag) wird
**nicht** gewählt: sie bräche jeden bestehenden statischen Aufruf. Der
Context-Lift erreicht dasselbe Ziel (Isolierbarkeit) ohne Bruch.

### 4.6 H6 — REST-Transport robuster

**Problem A.** `HttpExchangeRestRequest.read()` (Z. 52–58) fängt
`IOException` und wirft `UncheckedIOException`. `EventPublishHttpHandler.handle()`
(Z. 74) ruft `read()` ungeschützt — bei Client-Disconnect mid-body
propagiert die `UncheckedIOException` aus `handle()`, und der
JDK-`HttpServer` schließt die Verbindung ungraziös (kein sauberer
Status).

**Problem B.** `queryParameters()` (Z. 88–95) zerlegt den Query-String
mit reinem `split("&")` / `substring`, **ohne** `URLDecoder`. Werte mit
`%`, `+`, `=` kommen falsch dekodiert an — latenter Korrektheitsbug,
sobald ein Handler Query-Werte konsumiert (z. B. ein SSE-Cursor).

**Lift.**

1. `EventPublishHttpHandler.handle()` umschließt `read()` in
   `try/catch (UncheckedIOException e)` → `logger().warn(...)` +
   sauberes `400 "Malformed request"` (Body-Lese-Fehler ist ein
   Client-seitiges Problem). Alternativ — und sauberer — bekommt
   `HttpExchangeRestRequest.read()` selbst eine Variante, die den
   Lesefehler als typisiertes Ergebnis zurückgibt; Entscheidung in der
   Umsetzung, beide schließen den ungemappten Pfad.
2. `queryParameters()`: Key und Value je durch
   `URLDecoder.decode(s, StandardCharsets.UTF_8)`. Tests mit
   `%`-kodierten Werten, `+`-als-Space, leeren Werten und
   Mehrfach-Keys.

---

## 5. Architektonische Entscheidungen

### 5.1 `TokenHasher` neu statt `TokenDigestService` wiederverwenden

`TokenDigestService` (V00.71) ist das *richtige* Modell für **neuen**
Code, hat aber eine andere Form (Selector + Verifier, zwei Felder,
Constant-Time-Vergleich). Die drei V00.70-Services speichern **ein**
Hash-Feld und suchen danach. Sie auf Selector/Verifier umzustellen ist
ein Schema-Eingriff in drei Record-Stores — zu groß für einen
Hardening-Tick und ohne Fachbedarf. Der schmale `TokenHasher`-Vertrag
schließt die Typsicherheitslücke ohne Schema-Wirkung. Das volle
Token-Modell-Unifying bleibt Folge-Kandidat.

### 5.2 Context-Lift statt Capability-Split

Siehe §4.5. Abwärtskompatibilität schlägt Eleganz: Die delegierende
statische Fassade hält jeden Bestandsaufruf am Leben, während der
instanziierbare Context die Isolierbarkeit liefert. Ein Capability-Split
(`AuthnResolver`, `AuthzResolver`, …) wäre sauberer auf der grünen Wiese,
bräche aber jeden der heute gültigen `JSentinelServiceResolver.*`-Aufrufe
— inakzeptabel für einen Maintenance-Tick.

### 5.3 SpotBugs mit Baseline-Excludes statt „erst alles fixen"

Ein Gate, das sofort grün ist und nur **neue** Findings bricht, ist
nachhaltiger als ein großer Erst-Cleanup, der den Tick sprengt. Die
Bestands-Findings werden sichtbar gemacht (Backlog), aber nicht zur
Bedingung des Ticks.

### 5.4 Versions-Stelle: V00.75.10 auf der aktiven Linie

Das Projekt steht bereits auf `00.75.10-SNAPSHOT` (Post-Release-Bump nach
V00.75.00). V00.75.10 belegt diese Linie inhaltlich, statt eine neue
00.75.20 zu öffnen — die Findings sollen auf die schon laufende
Maintenance-Linie, nicht in einen weiteren Versionssprung.

---

## 6. Nicht-Scope

Bewusst **außerhalb** V00.75.10:

- **Volle Token-Modell-Unifizierung** auf `TokenDigestService`
  (Selector/Verifier) für die drei V00.70-Services — Schema-Eingriff,
  Folge-Kandidat ab V00.76.
- **SpotBugs/FindSecBugs für DX-, Adapter-, Persistence-, Demo-Module** —
  späterer Tick; ihr `spotbugs.skip` bleibt.
- **Error Prone / Semgrep** — als Option dokumentiert, in diesem Tick
  nicht scharf geschaltet (ein Statik-Tool pro Tick).
- **Context-Durchreichung durch alle Adapter** (Vaadin/REST/Standalone) —
  der invasive Teil von H5; H5 liefert nur die Struktur.
- **Bestands-SpotBugs-Findings abarbeiten** — als Backlog dokumentiert,
  nicht Tick-Bedingung.
- **`maxLength()` / weitere Parser-Felder** — kein Bedarf, Scope-Creep.

---

## 7. Stable-API-Versprechen

V00.75.10 ändert **keine** V00.73-Stable-Surface. Alle berührten Typen
sind `@ExperimentalJSentinelApi`:

- `TokenService`, `PasswordResetService`, `EmailVerificationService` —
  bereits experimentell; die deprecateten `PasswordHasher`-Konstruktoren
  und neuen `TokenHasher`-Konstruktoren sind daher zulässig.
- Neuer Typ `TokenHasher` + Default `Sha256TokenHasher` —
  `@ExperimentalJSentinelApi`.
- Neuer Typ `JSentinelContext` — `@ExperimentalJSentinelApi`. Die
  statische `JSentinelServiceResolver`-Fassade bleibt formgleich und
  abwärtskompatibel (delegiert, keine Signaturänderung).

Die `@Deprecated(forRemoval = true)`-Markierung der
`PasswordHasher`-Konstruktoren ist eine Ankündigung; die tatsächliche
Entfernung erfolgt frühestens, wenn die Typen Stable-Promotion erhalten
(nicht in V00.75.10).

---

## 8. Akzeptanzkriterien

- Alle 40 `pom.xml`-Dateien tragen `00.75.10-SNAPSHOT`; `./mvnw clean
  install` ist grün auf dem vollen Reactor.
- **H1:** `TokenHasher` + `Sha256TokenHasher` liegen in `jSentinel-core`;
  `demo-rest` nutzt die Library-Variante (kein eigener
  `Sha256TokenHasher` mehr). Die drei Services haben
  `TokenHasher`-Konstruktoren; die `PasswordHasher`-Konstruktoren sind
  `@Deprecated(forRemoval = true)` und enthalten den Determinismus-Guard.
- **H2:** Je Service ein Negativtest mit echtem `Pbkdf2PasswordHasher`,
  der die `IllegalArgumentException` des Guards beweist; kein Mock.
- **H3:** `-Pstatic-analysis` aktiviert SpotBugs + FindSecBugs für
  `jSentinel-core` / `-rest` / `-events-api` / `-events-bus` /
  `-events-rest`; der CI-Lauf führt das Profil; das Gate ist grün
  (Baseline-Excludes vorhanden); ein künstlich eingefügtes neues
  High-Priority-Finding bricht den Build (verifiziert, dann entfernt).
- **H4:** `WireJson` wirft für den eingebetteten Malformed-Korpus
  ausschließlich `EventWireException` (nie JDK-Roh-Runtime);
  `JsonResponse.expiresIn` liefert bei Overflow/Non-Numeric
  `Optional.empty()`; Tests decken beide Pfade ab.
- **H5:** `JSentinelContext` ist instanziierbar; `createIsolated()`
  liefert einen unabhängigen Satz Referenzen; die statische
  `JSentinelServiceResolver`-Fassade delegiert an den Default-Context und
  jeder Bestandsaufruf kompiliert/läuft unverändert; ein Test zeigt zwei
  isolierte Contexts ohne Cross-Leakage.
- **H6:** `EventPublishHttpHandler` mappt den Body-Lese-Fehler auf einen
  sauberen Status (kein ungemapptes `UncheckedIOException`-Propagieren);
  `queryParameters()` URL-dekodiert Key und Value; Tests mit
  `%`/`+`-kodierten Query-Werten sind grün.
- Alle sechs Demos (`demo-vaadin`, `demo-rest`, `demo-vaadin-rest-client`,
  `demo-standalone`, `demo-jsentinel-vaadin`) kompilieren und starten
  ohne Code-Anpassung (außer `demo-rest`s Wechsel auf den
  Library-`Sha256TokenHasher`).
- PIT-Regressions-Check: kein in H1/H4/H5/H6 berührtes Modul fällt unter
  seine V00.75.00-Baseline.
- `RELEASE-NOTES-00.75.10.md` listet die sechs Blöcke H1–H6 sauber
  getrennt, inkl. der Severity-Einordnung aus §3.
- ClickUp: ein Subtask je H-Block, nach jedem Block per
  Completion-Log-Append auf `completed` (Tracker-Disziplin).

---

## 9. Risiken und Gegenmaßnahmen

| Risiko | Gegenmaßnahme |
|---|---|
| `TokenHasher`-Einführung bricht stillschweigend einen Konsumenten, der den `PasswordHasher`-Konstruktor nutzte | Konstruktor bleibt (deprecatet) erhalten; der Determinismus-Guard wirft nur, wenn der Hasher *tatsächlich* salted ist — ein deterministischer `PasswordHasher` (selten, aber legitim) läuft weiter |
| SpotBugs-Erstlauf überflutet mit Bestands-Findings | Baseline-Excludes-File macht das Gate sofort grün; nur neue Findings brechen; Bestand → Backlog |
| FindSecBugs erzeugt False-Positives auf Krypto-Code | gezielte `@SuppressFBWarnings` mit Begründungs-Kommentar nur an verifizierten Stellen; nicht pauschal abschalten |
| Context-Lift (H5) übersieht eine statische Stelle → NPE auf Default-Context | Default-Context wird eager initialisiert (`new JSentinelContext()` als `static final`); alle 10 Setter + 32 Getter werden 1:1 delegiert; Vollabdeckungstest gegen die Fassade |
| Parallele Tests via `createIsolated()` verleiten dazu, auch Adapter-Tests „isoliert" zu glauben, obwohl Adapter weiter den Default-Context nutzen | JavaDoc + RELEASE-NOTES stellen klar: H5 liefert nur die Struktur; Adapter reichen den Context noch nicht durch |
| `WireJson`-Kapselung ändert versehentlich das Publish-Verhalten | Der Decode-Rand bleibt unverändert (`Result.mapError`); nur die Exception-*Klasse* wird konsistent; Bestands-Tests des Publish-Pfads müssen unverändert grün bleiben |
| Demo-`Sha256TokenHasher`-Umzug bricht die demo-rest-Integrationstests | Library-Impl ist byte-identisch zur Demo-Impl (SHA-256, gleiche Kodierung); Integrationstests laufen gegen denselben Digest |

---

## 10. Empfohlene Implementierungs-Reihenfolge

1. **H1 + H2 zuerst** (Security-Kern, klein, zusammengehörig):
   `TokenHasher` + `Sha256TokenHasher` in den Kern, drei Services
   umstellen, Guard einbauen, Negativtests schreiben, `demo-rest`
   umziehen.
2. **H4** (Parser-Härtung): `WireJson`-Kapselung + Malformed-Korpus,
   `JsonResponse`-Guard. Isoliert, untrusted-Input-relevant.
3. **H6** (REST-Transport): zwei kleine, lokale Fixes + Tests.
4. **H3** (Statik-Gate): SpotBugs/FindSecBugs-Profil + Baseline-Excludes;
   bewusst nach H1/H4/H6, damit das Gate gegen den schon gehärteten Stand
   kalibriert wird.
5. **H5** (Context-Lift): der größte Block zuletzt — instanziierbarer
   `JSentinelContext`, delegierende Fassade, Isolations-Test.
6. **`RELEASE-NOTES-00.75.10.md`** schreiben; ClickUp-Subtasks
   abschließen; Tag setzen.

Disziplin durchgängig: keine Mocks (echte Impls / Bootstrap-Setups),
keine Java-Serialisierung, keine Co-Authored-By-/„Generated with"-Footer,
`CLAUDE.md` nie committen, License-Header-Trailing-Spaces vor dem Commit
strippen, Commit-Prefixes je Block (`fix` / `refactor` / `test` /
`build`) ohne Prompt-Referenz. Bindend ist das Runbook
`docs/process/implementation-cycle.md`.

---

## 11. Beziehung zu anderen Versionen

- **V00.70** liefert die drei Token-Services (H1/H2). V00.75.10 ändert
  ihre Token-*Semantik* nicht — nur den Hasher-*Typ*.
- **V00.71** liefert `TokenDigestService` (das Zielmodell für die spätere
  volle Migration) und `Pbkdf2PasswordHasher` (den Auslöser von H1).
- **V00.72** liefert `JSentinelRuntime` — die objektorientierte Sicht,
  deren Backing-Schicht H5 jetzt instanziierbar macht.
- **V00.74** liefert die OIDC-Token-Propagation, in der `JsonResponse`
  (H4-Teil B) lebt.
- **V00.75.00** liefert den Event Bus inkl. `WireJson` / `EnvelopeWireCodec`
  / REST-Bridge (H4-Teil A, H6). V00.75.10 härtet diese frischen
  Komponenten, bevor sie breiter konsumiert werden.
- **V00.76+** (JWT/OAuth2/OIDC) profitiert direkt: der gehärtete
  `JSentinelContext` erleichtert Multi-IdP-Test-Setups; der saubere
  `TokenHasher`-Vertrag ist die Basis für refresh-token-bezogene
  Arbeit.

---

## 12. Ergebnisbild

Nach V00.75.10:

- Ein versehentlich übergebener `Pbkdf2PasswordHasher` an `TokenService`
  schlägt **laut beim Konstruieren** fehl — nicht still bei der ersten
  Rotation. Der korrekte Pfad (`TokenHasher` / `Sha256TokenHasher`) ist
  mitgeliefert und compiler-erzwungen.
- `WireJson` und `JsonResponse` halten ihren Fehler-Vertrag selbst;
  kaputter Input erzeugt typisierte Domänenfehler bzw. `Optional.empty()`,
  nie eine durchschlagende JDK-RuntimeException.
- Neue Tests laufen gegen `JSentinelContext.createIsolated()`
  parallelisierbar; Multi-App-Embedding ist strukturell möglich, ohne
  einen einzigen Bestandsaufruf zu brechen.
- Der REST-Bridge-Transport mappt Lese-Fehler sauber und dekodiert
  Query-Parameter korrekt.
- Ein scharfes SpotBugs/FindSecBugs-Gate schützt die Kernmodule vor neuen
  Bytecode-Findings.

V00.75.10 ist damit **klein im Risiko, gezielt in der Wirkung**:
Typsicherheit statt Kommentar, getestete Fehlpfade statt blinder Flecken,
gehärtete Parser, isolierbarer Zustand, ein scharfes Statik-Gate. Kein
Feature, kein Modul-Add, kein Bruch — genau der Charakter, den ein
Hardening-Tick zwischen zwei Feature-Bögen haben soll.
