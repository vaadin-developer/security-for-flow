# Konzept V00.75.00: Security Event Bus, signierte Envelopes und REST/SSE Bridge

> Zielbild: `v00.75.00` fuehrt einen produktionsfaehigen Security Event
> Bus als eigenes Modul ein. Security Events werden typisiert erzeugt,
> in signierte Security Event Envelopes verpackt, gegen Replay geschuetzt
> und ueber lokale Listener sowie eine REST/SSE Bridge verteilt. Der
> Transportkanal wird ueber bewaehrte Mechanismen wie HTTPS, mTLS, VPN,
> Service Mesh oder Broker-Security abgesichert. Der Event Bus selbst
> garantiert Integritaet, Authentizitaet, Deduplizierbarkeit,
> Reihenfolge pro Producer und Tenant sowie auditierbare
> Verarbeitungsentscheidungen.

## Leitmotiv

`v00.70.00` macht Policies, Persistenz und aktive Sessions
produktionsfaehig. `v00.80.00` soll High-Security, Identity-Integration
und Betrieb/Monitoring staerker ausbauen. `v00.75.00` liegt bewusst
dazwischen: Die Version schafft die Ereignis-Infrastruktur, auf der
Monitoring, SIEM-Integration, Risk-Based Authentication, Session
Revocation, Device Management, Audit-Listener und Identity-Integrationen
spaeter aufbauen koennen.

Der Event Bus ist kein generisches Messaging-System und kein Ersatz fuer
Audit. Er ist eine Security-spezifische Infrastrukturkomponente. Er
transportiert fachlich typisierte Security Events, schuetzt sie ueber
signierte Envelopes und stellt sicher, dass verteilte Framework-Teile
wie REST-Service und Vaadin-Anwendung dieselben sicherheitsrelevanten
Zustandsaenderungen beobachten koennen.

Audit bleibt ein separater Consumer des Event Bus. Ein Audit-Listener
kann Events persistent und revisionsfaehig speichern, aber der Event Bus
selbst entscheidet nicht, welche Events als Audit-Nachweis gelten.

## Kernentscheidungen fuer V00.75.00

- Der Event Bus wird als eigenes Modul im bestehenden Multi-Module-Repo
  umgesetzt.
- Der Scope enthaelt Core API, signierte Envelopes, Replay-Schutz,
  Producer Policy, persistente Stores, In-Memory-Defaults und eine echte
  REST/SSE Bridge.
- Signierte Events sind der Default.
- `Ed25519` ist das Standard-Signaturverfahren.
- `SHA256withECDSA` kann als optionaler Fallback vorbereitet werden.
- Replay-Schutz ist verpflichtend.
- Sequenznummern werden pro `tenantId + producerId` gefuehrt.
- Producer duerfen nur erlaubte Event-Typen publizieren.
- `TenantId` ist in jedem Envelope verpflichtend.
- Fehlerstrategien sind konfigurierbar.
- Der Transportkanal wird nicht im Event Bus kryptografisch
  verschluesselt. Vertraulichkeit des Kanals erfolgt ueber HTTPS, mTLS
  oder vergleichbare Infrastruktur.
- Die Payload-Serialisierung ist wahlweise ueber Canonical JSON oder
  Eclipse Serializer moeglich. Canonical JSON ist der interoperable
  Codec, Eclipse Serializer der Java-native Codec fuer Java-zu-Java
  Setups. Beide Codecs muessen dieselben Signatur- und
  Verifikationsregeln erfuellen.

## Modulzuschnitt

V00.75.00 fuehrt mindestens diese Module ein:

```text
security-events
security-events-rest
```

Optional, aber empfehlenswert:

```text
security-events-testkit
security-events-persistence-eclipsestore
```

Falls die bestehende Persistence-Schicht bereits generisch genug ist,
kann `security-events-persistence-eclipsestore` auch in
`jSentinel-persistence-eclipsestore` integriert werden. Der bevorzugte
Schnitt bleibt jedoch: EventBus-Core kennt nur Store-Interfaces, konkrete
Persistenzmodule liefern Implementierungen.

### security-events

Das Modul `security-events` enthaelt:

- Event-Basistypen
- Event-Kontext
- Event-Kategorien und Severity
- EventBus API
- Publisher API
- Listener API
- Envelope API
- Signer und Verifier API
- Key Management SPI
- Replay Store SPI
- Sequence Store SPI
- Producer Policy SPI
- Event Store SPI fuer persistente Event-Verarbeitung
- In-Memory-Implementierungen
- JDK-KeyStore-basierte einfache Key-Implementierung
- Default-Konfiguration
- Unit- und Contract-Tests fuer Core-Verhalten

Das Modul darf keine Abhaengigkeit auf Vaadin, REST-Frameworks oder
Eclipse Store haben.

### security-events-rest

Das Modul `security-events-rest` enthaelt:

- REST-Endpunkte zum Publizieren oder Abrufen von Envelopes, sofern
  konfiguriert erlaubt
- SSE-Endpunkt fuer abonnierte Event-Streams
- REST/SSE-Serialisierung von `SignedJSentinelEventEnvelope`
- Consumer-Verifikation eingehender Envelopes
- Export-Policy fuer Event-Typen
- Authentifizierungs- und Autorisierungs-Hooks fuer Event-Kanaele
- Cursor- oder Resume-Unterstuetzung fuer SSE-Reconnects
- Fehlerabbildung fuer ungueltige, abgelaufene oder replayte Envelopes

Das Modul setzt voraus, dass der Kanal ueber Standardmechanismen
geschuetzt wird. Es baut keine eigene Transportverschluesselung.

## Abgrenzung zu Audit

Der Security Event Bus beantwortet:

```text
Was ist sicherheitsrelevant passiert und wer soll operativ darauf reagieren?
```

Audit beantwortet:

```text
Welche sicherheitsrelevanten Vorgaenge muessen beweisbar, nachvollziehbar
und revisionsfaehig gespeichert werden?
```

Daraus folgt:

- Der Event Bus publiziert typisierte Security Events.
- Audit ist ein separater Listener.
- Audit entscheidet ueber Persistenz, Retention, Export und
  Manipulationsschutz.
- Der Event Bus darf Audit nicht hart verdrahten.
- Ein Audit-Listener kann als kritischer Listener konfiguriert werden.

Beispiel:

```java
eventBus.subscribe(JSentinelEvent.class, auditListener);
eventBus.subscribe(PolicyDeniedEvent.class, monitoringListener);
eventBus.subscribe(SessionRevokedEvent.class, vaadinSessionListener);
```

## Event-Modell

Security Events sind fachlich typisierte Java-Objekte. Sie sollen nicht
als freie Maps oder unstrukturierte Logtexte modelliert werden.

Basis-Interface:

```java
public interface JSentinelEvent {
  EventId eventId();
  EventType eventType();
  TenantId tenantId();
  SubjectId subjectId();
  Instant occurredAt();
  JSentinelEventSeverity severity();
  JSentinelEventCategory category();
}
```

Fuer Events ohne angemeldeten Benutzer wird ein expliziter technischer
Subject-Wert verwendet, zum Beispiel `SubjectId.SYSTEM`. `TenantId` ist
immer verpflichtend. Systemweite Events nutzen einen definierten
Tenant-Wert, zum Beispiel `TenantId.SYSTEM` oder `TenantId.DEFAULT`, aber
niemals `null`.

### Event-Kategorien

V00.75.00 sollte mindestens diese Kategorien definieren:

```text
AUTHENTICATION
AUTHORIZATION
SESSION
POLICY
ROLE
TOKEN
DEVICE
RATE_LIMIT
ADMIN
AUDIT
SYSTEM
INTEGRITY
```

### Severity

```java
public enum JSentinelEventSeverity {
  DEBUG,
  INFO,
  NOTICE,
  WARNING,
  ERROR,
  CRITICAL
}
```

Severity ist kein Logging-Level-Ersatz. Sie beschreibt die
sicherheitsfachliche Relevanz des Events fuer Monitoring, Alerting und
Incident Handling.

## Wichtige Event-Typen fuer V00.75.00

V00.75.00 muss nicht alle spaeteren High-Security-Events vollstaendig
abbilden, sollte aber die zentralen Integrationspunkte definieren.

### Authentication

```text
LoginSucceededEvent
LoginFailedEvent
LogoutSucceededEvent
PasswordResetRequestedEvent
PasswordResetCompletedEvent
EmailVerificationRequestedEvent
EmailVerifiedEvent
```

### Authorization und Policies

```text
PermissionDeniedEvent
RoleRequiredDeniedEvent
PolicyEvaluatedEvent
PolicyDeniedEvent
StepUpRequiredEvent
```

### Sessions

```text
SessionCreatedEvent
SessionExpiredEvent
SessionRevokedEvent
SessionJSentinelVersionOutdatedEvent
ConcurrentSessionLimitExceededEvent
```

### Rollen und Tenants

```text
RoleAssignedEvent
RoleRevokedEvent
RoleHierarchyChangedEvent
TenantJSentinelPolicyChangedEvent
```

### Tokens und Devices

```text
RememberMeTokenIssuedEvent
RememberMeTokenUsedEvent
RememberMeTokenRevokedEvent
DeviceTrustedEvent
DeviceRevokedEvent
ApiKeyIssuedEvent
ApiKeyUsedEvent
ApiKeyRevokedEvent
RefreshTokenRotatedEvent
RefreshTokenReuseDetectedEvent
```

### Rate Limiting und Abuse

```text
RateLimitExceededEvent
BruteForceThresholdReachedEvent
AccountTemporarilyLockedEvent
SuspiciousLoginDetectedEvent
```

### Bus, Envelope und Integritaet

```text
JSentinelEventEnvelopeRejectedEvent
JSentinelEventReplayDetectedEvent
JSentinelEventSignatureInvalidEvent
JSentinelEventSequenceViolationEvent
JSentinelEventListenerFailedEvent
JSentinelEventDeadLetteredEvent
```

## Security Event Envelope

Jedes transportierte Event wird in einen signierten Envelope verpackt.
Der Envelope enthaelt fachliche Metadaten, technische Producer-Daten,
Replay-Schutz, Sequenzinformationen und Signaturinformationen.

```java
public record SignedJSentinelEventEnvelope(
    EventEnvelopeId envelopeId,
    EventId eventId,
    EventType eventType,
    TenantId tenantId,
    SubjectId subjectId,
    EventProducerId producerId,
    Instant occurredAt,
    Instant issuedAt,
    Instant expiresAt,
    CorrelationId correlationId,
    CausationId causationId,
    EventSequence sequence,
    KeyId keyId,
    SignatureAlgorithm signatureAlgorithm,
    PayloadContentType payloadContentType,
    PayloadHashAlgorithm payloadHashAlgorithm,
    String canonicalPayloadHash,
    byte[] canonicalPayload,
    byte[] signature
) {}
```

### Pflichtfelder

- `envelopeId`: eindeutige ID fuer Deduplikation und Replay-Schutz
- `eventId`: fachliche Event-ID
- `eventType`: typisierte Event-Art
- `tenantId`: verpflichtender Tenant-Kontext
- `subjectId`: fachlicher oder technischer Subject-Kontext
- `producerId`: technischer Herausgeber des Events
- `occurredAt`: fachlicher Zeitpunkt des Ereignisses
- `issuedAt`: Zeitpunkt der Envelope-Erzeugung
- `expiresAt`: Ende der Akzeptanzfrist
- `correlationId`: Korrelation ueber Request, Session oder Prozesskette
- `causationId`: optionaler Bezug auf verursachendes Event
- `sequence`: monotone Sequenz pro `tenantId + producerId`
- `keyId`: Verweis auf den Verifikationsschluessel
- `signatureAlgorithm`: verwendeter Algorithmus
- `canonicalPayloadHash`: Hash ueber den kanonischen Payload
- `canonicalPayload`: serialisiertes, kanonisches Event
- `signature`: Signatur ueber Envelope-Metadaten und Payload-Hash

## Signaturmodell

Die Signatur schuetzt nicht nur den Payload, sondern auch die
sicherheitsrelevanten Envelope-Metadaten. Andernfalls koennten zum
Beispiel `tenantId`, `eventType`, `expiresAt`, `producerId` oder
`sequence` manipuliert werden, ohne den Payload selbst zu veraendern.

Signiert wird eine deterministische Signaturbasis:

```text
envelopeId
eventId
eventType
tenantId
subjectId
producerId
occurredAt
issuedAt
expiresAt
correlationId
causationId
sequence
keyId
signatureAlgorithm
payloadContentType
payloadHashAlgorithm
canonicalPayloadHash
```

Der Payload selbst wird ueber `canonicalPayloadHash` eingebunden. Dadurch
kann der Verifier zuerst den Payload-Hash pruefen und danach die
Signaturbasis validieren.

### Algorithmus

Standard:

```text
Ed25519
```

Optionaler Fallback:

```text
SHA256withECDSA
```

HMAC ist fuer V00.75.00 kein Default. Der Grund: Bei HMAC besitzen
Publisher und Consumer dasselbe Secret. Fuer verteilte Security-Events
ist ein asymmetrisches Modell sauberer:

```text
REST Service signiert mit Private Key.
Vaadin App verifiziert mit Public Key.
```

Damit kann ein Consumer Events pruefen, ohne selbst mit derselben
Autoritaet Events signieren zu koennen.

## Payload-Serialisierung

V00.75.00 unterstuetzt zwei Payload-Codecs wahlweise:

```text
Canonical JSON
Eclipse Serializer
```

Beide Codecs serialisieren nicht beliebige interne Event-Objekte,
sondern ein kontrolliertes kanonisches Payload-Modell. Dadurch bleibt
die Signaturbasis stabiler, versionierbar und testbar.

```text
JSentinelEvent
  -> CanonicalJSentinelEventPayload
  -> JSentinelEventPayloadCodec
  -> canonicalPayload bytes
  -> canonicalPayloadHash
  -> SignedJSentinelEventEnvelope
```

Die wichtigste Regel lautet: Die Signatur haengt an der Bytefolge, die
der ausgewaehlte Codec erzeugt. Deshalb muss jeder Codec deterministische
Bytes liefern und durch Contract Tests abgesichert werden.

### Canonical JSON Codec

Canonical JSON ist der interoperable Codec. Er ist der bevorzugte Codec
fuer REST/SSE, externe Integrationen, Debugging, Dokumentation und
gemischte Systemlandschaften.

Vorteile:

- gut lesbar
- leicht debuggbar
- einfacher Einstieg
- gute REST/SSE-Kompatibilitaet
- gut dokumentierbares Wire Format
- gut geeignet fuer externe Consumer
- geeignet fuer Test-Fixtures und manuelle Analyse

Nachteile:

- kanonische JSON-Regeln muessen strikt definiert werden
- Datums-, Zahlen- und Map-Reihenfolge duerfen keine Mehrdeutigkeit
  erzeugen
- Binary-Daten muessen kodiert werden

Pflichtregeln:

```text
UTF-8
keine Pretty-Print-Whitespace
Objektfelder deterministisch sortiert
Instant-Werte in UTC mit definierter Praezision
keine Floating-Point-Zahlen im kanonischen Modell
keine impliziten Default-Werte
keine unsortierten Maps oder Sets
explizite schemaVersion
explizites eventType-Feld
```

### Eclipse Serializer Codec

Der Eclipse Serializer Codec ist der Java-native Codec fuer Setups, in
denen Producer und Consumer Java-basierte Framework-Komponenten sind,
zum Beispiel REST-Service und Vaadin-Anwendung. Er darf als Alternative
zu Canonical JSON verwendet werden, wenn die Anwendung bewusst ein
Java-natives Binary-Format bevorzugt.

Vorteile:

- passend zum Eclipse-Store-Oekosystem
- Java-Objekte muessen kein `Serializable` implementieren
- gut fuer komplexe Java-Objektstrukturen geeignet
- binaeres Format
- Versioning-Unterstuetzung des Serializers kann fuer Payload-Evolution
  genutzt werden
- weniger JSON-spezifische Kanonisierungsregeln notwendig

Nachteile:

- weniger transparent als JSON
- schlechter manuell debuggbar
- primaer Java-nativ, nicht ideal fuer externe Nicht-Java-Consumer
- Signaturstabilitaet muss explizit per Contract Test nachgewiesen
  werden
- Consumer benoetigen den passenden Codec und kompatible Payload-Typen

Auch beim Eclipse Serializer gilt: Es werden nicht beliebige
`JSentinelEvent`-Implementierungen direkt signiert. Signiert wird die
serialisierte Form von `CanonicalJSentinelEventPayload`.

```text
LoginSucceededEvent
  -> CanonicalJSentinelEventPayload
  -> EclipseSerializerPayloadCodec
  -> canonicalPayload bytes
  -> hash
  -> signature
```

### Deterministisches CBOR

Deterministisches CBOR bleibt als spaeterer Codec vorbereitet, ist aber
nicht Pflichtbestandteil von V00.75.00.

Vorteile:

- kompakter
- besser fuer stabile binaere Signaturen
- geeignet fuer spaetere Broker- oder High-Throughput-Szenarien

Nachteile:

- schlechter lesbar
- mehr Implementierungsaufwand
- hoehere Einstiegshuerde fuer Anwender

### Codec SPI

Die Serialisierung wird ueber ein SPI gekapselt:

```java
public interface JSentinelEventCanonicalizer {
  CanonicalJSentinelEventPayload canonicalize(JSentinelEvent event);
}
```

```java
public interface JSentinelEventPayloadCodec {
  PayloadContentType contentType();
  byte[] encode(CanonicalJSentinelEventPayload payload);
  CanonicalJSentinelEventPayload decode(byte[] bytes);
}
```

Vorgesehene Content Types:

```text
application/vnd.security-event.canonical-json
application/vnd.security-event.eclipse-serializer
```

### Empfehlung

Canonical JSON sollte der interoperable Default fuer Dokumentation,
REST/SSE und externe Integrationen sein. Eclipse Serializer sollte als
wahlweise aktivierbarer Java-nativer Codec bereitgestellt werden. Eine
Anwendung kann den Codec explizit konfigurieren:

```java
JSentinelEventBusConfig config = JSentinelEventBusConfig.builder()
    .payloadCodec(PayloadContentType.ECLIPSE_SERIALIZER)
    .build();
```

Fuer beide Codecs gilt dasselbe Sicherheitsmodell: Payload-Hash,
Envelope-Signatur, Replay-Schutz, Sequenzpruefung und Producer Policy
bleiben unveraendert.

## Key Management

V00.75.00 liefert ein SPI und eine einfache JDK-`KeyStore`-
Implementierung.

### SPI

```java
public interface JSentinelEventSigningKeyProvider {
  KeyId currentKeyId();
  PrivateKey currentSigningKey();
  SignatureAlgorithm currentAlgorithm();
}
```

```java
public interface JSentinelEventVerificationKeyResolver {
  Optional<PublicKey> resolveVerificationKey(KeyId keyId);
  KeyStatus keyStatus(KeyId keyId);
}
```

```java
public enum KeyStatus {
  ACTIVE,
  ACCEPTED_FOR_VERIFICATION,
  REVOKED,
  EXPIRED,
  UNKNOWN
}
```

### JDK-KeyStore-Implementierung

Die einfache Implementierung soll:

- Private Keys aus einem JDK `KeyStore` laden
- Public Keys fuer Verifikation bereitstellen
- `keyId` auf Alias oder explizite Metadaten abbilden
- aktive und alte Keys unterscheiden
- Key Rotation ohne API-Bruch vorbereiten

Nicht-Ziel:

- vollstaendiges Secret Management
- HSM-Integration
- Cloud-KMS-Integration

Diese Integrationen koennen spaeter ueber dasselbe SPI folgen.

## Replay-Schutz

Replay-Schutz ist in V00.75.00 verpflichtend. Ein gueltig signiertes
Event darf nicht beliebig oft erneut verarbeitet werden koennen.

Der Verifier prueft:

```text
1. Envelope syntaktisch gueltig?
2. keyId bekannt und akzeptiert?
3. Payload-Hash korrekt?
4. Signatur korrekt?
5. issuedAt und expiresAt plausibel?
6. envelopeId noch nicht verarbeitet?
7. sequence pro tenantId + producerId gueltig?
8. Producer darf diesen Event-Typ publizieren?
9. Tenant-Kontext fuer Consumer erlaubt?
```

### Replay Store

```java
public interface JSentinelEventReplayStore {
  boolean markSeen(EventEnvelopeId envelopeId, Instant expiresAt);
  boolean hasSeen(EventEnvelopeId envelopeId);
  void purgeExpired(Instant now);
}
```

`markSeen` muss atomar sein. Bei paralleler Verarbeitung darf nur ein
Consumer denselben Envelope erfolgreich markieren.

### Sequence Store

```java
public interface JSentinelEventSequenceStore {
  Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId);
  void updateSequence(TenantId tenantId, EventProducerId producerId, EventSequence sequence);
}
```

Die Sequenz ist monoton pro `tenantId + producerId`. Dadurch kann ein
Consumer Luecken, Wiederholungen und Rueckspruenge erkennen.

### Sequence Policy

Eine konfigurierbare Policy bestimmt, wie streng Sequenzverletzungen
behandelt werden:

```java
public enum SequenceViolationStrategy {
  REJECT,
  DEAD_LETTER,
  ACCEPT_WITH_WARNING
}
```

Fuer `SIGNED_STRICT` sollte `REJECT` der Default sein.

## Producer Policy

Jeder Envelope enthaelt einen `producerId`. Der Bus prueft, ob dieser
Producer den angegebenen Event-Typ fuer den angegebenen Tenant
publizieren darf.

```java
public interface JSentinelEventProducerPolicy {
  boolean mayPublish(EventProducerId producerId, EventType eventType, TenantId tenantId);
}
```

Beispiele:

```text
rest-service-primary darf LoginSucceededEvent publizieren.
rest-service-primary darf RoleAssignedEvent publizieren.
vaadin-client darf SessionRevokedEvent nicht publizieren.
vaadin-client darf UIAccessDeniedEvent publizieren, falls erlaubt.
security-core darf PolicyDeniedEvent publizieren.
```

Diese Policy verhindert, dass ein technisch angebundener Consumer oder
UI-Prozess Events mit zu hoher Autoritaet erzeugt.

## Persistente Stores

V00.75.00 benoetigt persistente Stores fuer Replay, Sequenzen und
optional Event-Zustellung.

### Pflicht-Stores

```text
JSentinelEventReplayStore
JSentinelEventSequenceStore
JSentinelEventDeadLetterStore
```

### Optionaler Store

```text
JSentinelEventEnvelopeStore
```

Der Envelope Store speichert Events fuer Resume, Diagnose oder
operative Verarbeitung. Er ist kein Audit-Store. Wenn ein Event
revisionsfaehig gespeichert werden muss, geschieht das ueber einen
Audit-Listener.

```java
public interface JSentinelEventEnvelopeStore {
  void append(SignedJSentinelEventEnvelope envelope);
  List<SignedJSentinelEventEnvelope> findAfter(JSentinelEventCursor cursor, int limit);
  Optional<SignedJSentinelEventEnvelope> findByEnvelopeId(EventEnvelopeId envelopeId);
}
```

### Dead Letter Store

```java
public interface JSentinelEventDeadLetterStore {
  void store(JSentinelEventDeadLetter deadLetter);
  List<JSentinelEventDeadLetter> findOpen(int limit);
  void markResolved(DeadLetterId id);
}
```

Dead Letters entstehen bei:

- ungueltiger Signatur
- unbekanntem Key
- Replay-Erkennung
- Sequenzverletzung
- Producer-Policy-Verletzung
- Deserialisierungsfehler
- Listener-Fehler, wenn konfiguriert

## Fehlerstrategien

Fehlerverhalten ist konfigurierbar. Es darf nicht global hart verdrahtet
sein, weil unterschiedliche Anwendungen unterschiedliche
Sicherheitsanforderungen haben.

```java
public enum JSentinelEventFailureStrategy {
  LOG_AND_CONTINUE,
  DEAD_LETTER,
  RETRY,
  REJECT,
  FAIL_CLOSED
}
```

Strategien sollten pro Kategorie oder Event-Typ konfigurierbar sein:

```java
JSentinelEventBusConfig config = JSentinelEventBusConfig.builder()
    .defaultFailureStrategy(JSentinelEventFailureStrategy.DEAD_LETTER)
    .strategy(JSentinelEventCategory.INTEGRITY, JSentinelEventFailureStrategy.FAIL_CLOSED)
    .strategy(JSentinelEventCategory.SESSION, JSentinelEventFailureStrategy.REJECT)
    .build();
```

### Listener-Fehler

Listener duerfen das Framework nicht unkontrolliert destabilisieren.

Anforderungen:

- Listener koennen als kritisch oder nicht kritisch registriert werden.
- Nicht-kritische Listener-Fehler werden als Event gemeldet und je nach
  Konfiguration dead-lettered.
- Kritische Listener koennen `FAIL_CLOSED` ausloesen.
- Fehler beim Fehler-Event duerfen keine Endlosschleife erzeugen.

## EventBus API

```java
public interface JSentinelEventBus {
  void publish(JSentinelEvent event);

  CompletionStage<Void> publishAsync(JSentinelEvent event);

  <E extends JSentinelEvent> Registration subscribe(
      Class<E> eventType,
      JSentinelEventListener<? super E> listener
  );

  <E extends JSentinelEvent> Registration subscribe(
      Class<E> eventType,
      JSentinelEventListenerOptions options,
      JSentinelEventListener<? super E> listener
  );
}
```

```java
@FunctionalInterface
public interface JSentinelEventListener<E extends JSentinelEvent> {
  void onJSentinelEvent(E event);
}
```

```java
public interface Registration extends AutoCloseable {
  @Override
  void close();
}
```

## Publish-Pipeline

Beim Publizieren eines lokalen Security Events:

```text
JSentinelEvent
  -> Event-Kontext vervollstaendigen
  -> Producer Policy pruefen
  -> Sequenz reservieren
  -> Payload kanonisieren
  -> Payload Hash berechnen
  -> Envelope bauen
  -> Envelope signieren
  -> Replay Store markieren
  -> optional Envelope Store append
  -> lokale Listener dispatchen
  -> optionale Transporte beliefern
```

Das Reservieren der Sequenz und das Persistieren des Replay-Zustands
muessen konsistent erfolgen. Bei Store-Backends kann dafuer eine
transaktionale oder zumindest atomare Implementierung notwendig sein.

## Consume-Pipeline

Beim Empfang eines Envelopes von REST/SSE oder einem spaeteren Broker:

```text
SignedJSentinelEventEnvelope
  -> syntaktisch validieren
  -> Public Key ueber keyId aufloesen
  -> Payload Hash pruefen
  -> Signatur pruefen
  -> Zeitfenster pruefen
  -> Replay Store markieren
  -> Sequenz pruefen und aktualisieren
  -> Producer Policy pruefen
  -> Payload deserialisieren
  -> lokale Listener dispatchen
  -> optional Envelope Store append
```

Ein Envelope darf erst an fachliche Listener weitergegeben werden, wenn
Verifikation, Replay-Schutz, Sequenzpruefung und Producer Policy
erfolgreich waren.

## Verifikationsresultate

Die Verifikation darf nicht nur `boolean` liefern. Fuer Audit,
Monitoring und Diagnose braucht es strukturierte Ergebnisse.

```java
public sealed interface JSentinelEventVerificationResult {
  record Valid(SignedJSentinelEventEnvelope envelope) implements JSentinelEventVerificationResult {}
  record InvalidSignature(String reason) implements JSentinelEventVerificationResult {}
  record UnknownKey(KeyId keyId) implements JSentinelEventVerificationResult {}
  record KeyRevoked(KeyId keyId) implements JSentinelEventVerificationResult {}
  record Expired(Instant expiresAt) implements JSentinelEventVerificationResult {}
  record PayloadHashMismatch(EventEnvelopeId envelopeId) implements JSentinelEventVerificationResult {}
  record ReplayDetected(EventEnvelopeId envelopeId) implements JSentinelEventVerificationResult {}
  record SequenceViolation(
      TenantId tenantId,
      EventProducerId producerId,
      EventSequence expected,
      EventSequence actual
  ) implements JSentinelEventVerificationResult {}
  record ProducerNotAllowed(
      EventProducerId producerId,
      EventType eventType,
      TenantId tenantId
  ) implements JSentinelEventVerificationResult {}
}
```

## REST/SSE Bridge

Die REST/SSE Bridge verbindet getrennte Prozesse, insbesondere
REST-Service und Vaadin-Anwendung.

### Ziel

Die Vaadin-Anwendung soll sicherheitsrelevante Ereignisse des
REST-Service zeitnah verarbeiten koennen:

```text
RoleAssignedEvent
RoleRevokedEvent
SessionRevokedEvent
SessionJSentinelVersionOutdatedEvent
PolicyChangedEvent
StepUpRequiredEvent
TokenRevokedEvent
```

Nicht jedes Event muss an die UI exportiert werden. Ein Export-Filter
entscheidet, welche Event-Typen ueber die Bridge sichtbar werden.

```java
public interface JSentinelEventExportPolicy {
  boolean shouldExport(SignedJSentinelEventEnvelope envelope, JSentinelEventSubscriber subscriber);
}
```

### SSE-Endpunkt

Beispielhafte Endpunkte:

```text
GET /security/events/sse
GET /security/events/sse?tenantId=default
GET /security/events/sse?cursor=...
```

Der Server sendet signierte Envelopes:

```text
event: security-event
id: <cursor>
data: <serialized SignedJSentinelEventEnvelope>
```

Bei Fehlern:

```text
event: security-event-error
data: <structured error>
```

### Resume und Cursor

SSE-Verbindungen koennen abbrechen. Deshalb braucht die Bridge einen
Cursor:

```java
public record JSentinelEventCursor(
    TenantId tenantId,
    EventProducerId producerId,
    EventSequence sequence
) {}
```

Alternativ kann ein globaler Store-Cursor verwendet werden, sofern der
Envelope Store eine stabile Ordnung garantiert.

### REST-Publish-Endpunkt

Ein Publish-Endpunkt ist optional und muss streng autorisiert werden.
Nicht jeder Consumer darf Events publizieren.

```text
POST /security/events
Content-Type: application/json
```

Der Server akzeptiert nur signierte Envelopes, die alle
Verifikationsschritte bestehen.

### Sicherheit des Kanals

Die Bridge setzt voraus:

- HTTPS in Produktion
- optional mTLS fuer Service-zu-Service-Kommunikation
- klare Authentifizierung des Consumers
- tenant-bezogene Autorisierung fuer Event-Abonnements
- keine Secrets im Payload
- begrenzte Event-Retention fuer Resume

Die Bridge verschluesselt den Payload nicht selbst. Das ist bewusst
ausserhalb des Scopes, weil der Transportkanal ueber bewaehrte
Infrastruktur geschlossen wird.

## Konfiguration

Beispiel:

```java
JSentinelEventBusConfig config = JSentinelEventBusConfig.builder()
    .mode(JSentinelEventBusMode.SIGNED)
    .signatureAlgorithm(SignatureAlgorithm.ED25519)
    .defaultTtl(Duration.ofMinutes(5))
    .replayProtectionRequired(true)
    .sequenceScope(SequenceScope.TENANT_AND_PRODUCER)
    .defaultFailureStrategy(JSentinelEventFailureStrategy.DEAD_LETTER)
    .strictProducerPolicy(true)
    .tenantRequired(true)
    .build();
```

Modi:

```java
public enum JSentinelEventBusMode {
  UNSIGNED_LOCAL,
  SIGNED,
  SIGNED_STRICT
}
```

`SIGNED` ist der Default. `UNSIGNED_LOCAL` ist nur fuer Tests und sehr
einfache lokale Setups gedacht. `SIGNED_STRICT` ist fuer verteilte
Produktionssysteme vorgesehen.

## Integration in bestehende Module

### security-core

`jSentinel-core` publiziert Events an zentralen Stellen:

- Login Erfolg und Fehler
- Logout
- Policy-Auswertung
- Permission Denied
- Role Required Denied
- Session Security Version outdated
- Role Assignment geaendert
- Token verwendet oder widerrufen

Der Core darf aber nicht von REST oder Vaadin abhaengen. Er kennt nur
die EventBus API.

### security-rest

`jSentinel-rest` integriert:

- REST/SSE Bridge
- REST Security Events fuer `401` und `403`
- API-Key-Events
- Token-Events
- Rate-Limit-Events
- Export von signierten Envelopes an autorisierte Consumer

### security-vaadin

`jSentinel-vaadin` konsumiert Events aus der Bridge:

- Session widerrufen -> UI-Session invalidieren
- Role Refresh noetig -> Subject neu laden oder Logout erzwingen
- Step-Up erforderlich -> Step-Up Route triggern
- Policy geaendert -> UI-Zugriff neu bewerten

Vaadin sollte nur die Event-Typen abonnieren, die fuer aktive UI-Sessions
relevant sind.

### security-persistence-eclipsestore

Die Eclipse-Store-Persistenz implementiert:

- Replay Store
- Sequence Store
- Dead Letter Store
- optional Envelope Store

Die Root-Klasse bleibt implementierungsintern und darf nicht Teil der
oeffentlichen API werden.

## Datenschutz und Payload-Sicherheit

Security Events duerfen keine Secrets enthalten.

Nicht erlaubt:

- Passwoerter
- API Keys im Klartext
- Refresh Tokens im Klartext
- Remember-Me Tokens im Klartext
- Session Secrets
- Recovery Codes
- vollstaendige kryptografische Schluessel

Erlaubt:

- Token-ID
- Hash-Fingerprint
- gekuerzte oder normalisierte IP-Adresse, je nach Konfiguration
- Device-ID
- User-Agent-Fingerprint
- fachlicher Fehlercode

Die Redaction sollte als SPI vorbereitet werden:

```java
public interface JSentinelEventRedactor {
  JSentinelEvent redact(JSentinelEvent event);
}
```

## Tests und Abnahmekriterien

### Core-Tests

- Event wird in Envelope verpackt.
- Envelope enthaelt alle Pflichtfelder.
- `TenantId` ist immer vorhanden.
- Ed25519-Signatur wird erzeugt und erfolgreich verifiziert.
- Manipulierter Payload wird abgelehnt.
- Manipulierter `tenantId` wird abgelehnt.
- Manipulierter `eventType` wird abgelehnt.
- Manipulierter `expiresAt` wird abgelehnt.
- Unbekannter Key wird abgelehnt.
- Revoked Key wird abgelehnt.

### Replay- und Sequence-Tests

- Derselbe `envelopeId` wird nur einmal akzeptiert.
- Abgelaufene Envelopes werden abgelehnt.
- Sequenz steigt pro `tenantId + producerId`.
- Ruecksprung der Sequenz wird erkannt.
- Doppelte Sequenz wird erkannt.
- Luecke in der Sequenz wird gemaess Konfiguration behandelt.

### Producer-Policy-Tests

- Erlaubter Producer darf erlaubten Event-Typ publizieren.
- Erlaubter Producer darf nicht automatisch alle Event-Typen
  publizieren.
- Nicht erlaubter Producer wird abgelehnt.
- Tenant-spezifische Producer-Regeln werden beachtet.

### REST/SSE-Tests

- SSE sendet signierte Envelopes.
- Reconnect mit Cursor funktioniert.
- Export-Policy filtert Event-Typen korrekt.
- Consumer ohne Berechtigung erhaelt keine Events.
- Ungueltige eingehende Envelopes werden abgelehnt.
- Replay ueber REST wird erkannt.

### Store-Contract-Tests

- Replay Store ist atomar.
- Sequence Store aktualisiert Sequenzen konsistent.
- Dead Letter Store speichert strukturierte Fehler.
- Envelope Store liefert stabile Cursor-Reihenfolge.

## Nicht-Ziele fuer V00.75.00

- keine eigene Transportverschluesselung fuer SSE
- kein Ersatz fuer Kafka, RabbitMQ, Pulsar oder NATS
- keine vollstaendige SIEM-Integration
- keine HSM- oder Cloud-KMS-Implementierung
- keine WebAuthn- oder OIDC-Implementierung
- kein Tamper-Evident Audit als Teil des Event Bus
- keine generische Workflow Engine

## Roadmap nach V00.75.00

V00.75.00 schafft die Grundlage fuer:

- Monitoring und Metrics in V00.80.00
- SIEM- und Webhook-Integrationen
- Risk-Based Authentication
- Device- und Remember-Me-Management
- MFA- und Step-Up-Flows
- Tamper-Evident Audit als separater Listener
- Streaming-Transporte fuer Kafka, NATS, RabbitMQ oder Pulsar
- Cloud-KMS- und HSM-KeyProvider

## Zusammenfassung

`v00.75.00` macht Security Events zu einem belastbaren
Framework-Baustein. Events werden nicht nur lokal verteilt, sondern als
signierte, replay-geschuetzte und tenant-aware Envelopes modelliert.
REST-Service und Vaadin-Anwendung koennen dadurch sicherheitsrelevante
Zustandsaenderungen prozessuebergreifend austauschen, ohne dass der
Event Bus selbst Transportverschluesselung oder Audit-Persistenz
uebernehmen muss.

Die Payload-Serialisierung ist als wahlbarer Codec-Schnitt festgelegt:
Canonical JSON dient als interoperabler Codec, Eclipse Serializer als
Java-native Alternative. Vor der Implementierung muessen die Contract
Tests fuer deterministische Codec-Bytes und Signaturstabilitaet exakt
ausformuliert werden.
