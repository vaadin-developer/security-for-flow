# Security for Flow – Konzept für Passwort- und Credential-Sicherheit

Version: `00.71.00`  
Quellstand: Featureliste v9  
Zielprojekt: `vaadin-developer/security-for-flow`  
Java: `26+`  
Build: Maven  
Lizenz: EUPL 1.2  
Status: Architektur- und Umsetzungskonzept

---

## 1. Executive Summary

Dieses Konzept beschreibt die Passwort- und Credential-Sicherheit für `security-for-flow` in Version `00.71.00`. Ziel ist eine robuste, dependency-arme und krypto-agile Schicht, die sichere Defaults bietet, optionale Krypto-Provider sauber kapselt, künftige Policy-Änderungen kontrolliert unterstützt und den Lebenszyklus von Credentials abbildet.

Der Kern (`security-core`) bleibt ohne neue externe Runtime-Abhängigkeiten. Er stellt PBKDF2 über JDK/JCA/JCE bereit, definiert Provider-SPIs, Codec, Validator, Policy, Rehash-Entscheidungen, sichere Failure-Pfade und zentrale Ergebnisobjekte. Moderne Verfahren wie Argon2id, bcrypt und scrypt werden in ein optionales Modul `security-crypto-bc` ausgelagert.

Die bisherige experimentelle `PasswordHasher`-/`Pbkdf2PasswordHasher`-Struktur wird nicht als stabile öffentliche API betrachtet. Da keine produktiven Altbestände oder stabilen externen Konsumenten bestehen, darf die neue Architektur sauber geschnitten werden. Es gibt keine Pflicht zur Kompatibilität mit bisherigen experimentellen Hashformaten.

---

## 2. Scope und Non-Scope

### 2.1 Scope für Version `00.71.00`

In Scope sind:

- Passwort-Hashing mit sicherem Core-Default.
- Provider-fähige Hashing-Architektur.
- Selbstbeschreibendes Umschlagformat mit Formatversion und Policy-Version.
- Explizite Ergebnisobjekte statt primitiver Boolean-Rückgaben.
- Sichere, generische Failure-Pfade gegen User Enumeration und Timing-Leaks.
- Rehash- und Policy-Evolution für künftige eigene Versionen.
- KDF-Ausführungslimit gegen Ressourcenerschöpfung.
- Vorbereitung auf Pepper, Credential Lifecycle, Reset/Recovery, Abuse Detection und Tenant-Kontexte.
- Dokumentierbare CWE-/ASVS-/NIST-Traceability.

### 2.2 Non-Scope für die erste Implementierungsphase

Nicht Teil von Phase 1a sind:

- Argon2id, bcrypt und scrypt.
- BouncyCastle-Modul.
- FIPS-Modus.
- HSM/KMS-/PKCS#11-Integration.
- Have-I-Been-Pwned-Anbindung.
- Vollständiger CredentialStore.
- Vollständige Reset-/Recovery-Flows.
- Vollständige Abuse Detection.
- WebAuthn, Passkeys oder TOTP.
- Import fremder Bestands-Hashes.
- Kompatibilität mit bisherigen experimentellen Hashformaten.

---

## 3. Architektonische Leitlinien

Die Architektur folgt diesen Regeln:

1. **Keine Eigenentwicklung kryptographischer Primitive.**  
   Primitive werden ausschließlich aus JDK/JCA/JCE oder geprüften Provider-Bibliotheken bezogen.

2. **Dependency-armer Kern.**  
   `security-core` erhält keine neuen externen Runtime-Abhängigkeiten.

3. **Explizite Provider-Auswahl.**  
   Provider werden lokal pro Operation ausgewählt. Die globale JCA-Provider-Reihenfolge wird nicht still verändert.

4. **Kein stilles Downgrade.**  
   Ein fehlender konfigurierter Provider oder Algorithmus führt zu kontrolliertem Fehler, sofern die Policy keinen expliziten Fallback erlaubt.

5. **Keine primitive Boolean-Verifikation.**  
   `verify(...)` liefert ein strukturiertes `CredentialVerificationResult`; `hash(...)` liefert `PasswordHashResult`; `needsRehash(...)` liefert `RehashDecision`.

6. **Generische öffentliche Fehler, genaue interne Auditdaten.**  
   UI- und API-nahe Schichten verwenden nur generische öffentliche Fehler. Interne Audit-Typen dürfen differenzieren.

7. **Policy-Evolution statt Altformat-Migration.**  
   Das erste produktive Schreibformat ist das neue Umschlagformat. Ältere experimentelle Formate werden nicht garantiert unterstützt.

8. **Atomicity bei sicherheitsrelevanten Updates.**  
   Rehash, Passwortwechsel, Reset und Statuswechsel dürfen keine Blind-Overwrites erzeugen.

---

## 4. Modulstrategie

| Modul | Aufgabe | Abhängigkeit | Rolle |
|---|---|---:|---|
| `security-core` | Core-SPIs, Codec, Validator, PBKDF2, Policy, Rehash, Dummy-Failure-Pfade, KDF-Limiter | keine neuen Runtime-Dependencies | Pflichtmodul |
| `security-crypto-bc` | Argon2id, bcrypt, scrypt, Resource Estimates, algorithmusspezifische Validatoren | `bcprov` | optional |
| `security-crypto-bcfips` | FIPS-Profil mit zulässigen Providern/Algorithmen | abhängig vom Provider | optional |
| `security-credentials-hibp` | k-Anonymitätsprüfung gegen externen Dienst | JDK `HttpClient` ausreichend | optional |
| `security-credentials-recovery` | Reset-/Recovery-Flows | keine zwingende | optional oder Core-nah |
| `security-credentials-abuse` | Credential Stuffing, Spraying, multidimensionales Rate Limiting | keine zwingende | optional |
| `security-credentials-import` | Brownfield-Import fremder Hashformate | abhängig vom Quellformat | zurückgestellt |
| `demo-*` | Vaadin-/REST-/Standalone-Demos | projektabhängig | Beispielcode |
| `docs` | Betriebsleitfäden, Traceability, Standards-Mapping | keine | Dokumentation |

---

## 5. Core-Architektur

### 5.1 Verifikationspipeline

Die zentrale Pipeline lautet:

```text
parse → validate → resolveProvider → resolvePepper → verify → rehashDecision
```

Bedeutung:

- `parse`: syntaktisches Lesen des Umschlags, keine KDFs, keine Policy-Entscheidungen.
- `validate`: generische Envelope-Grenzen, Core-Parameter und Policy-Zulässigkeit prüfen.
- `resolveProvider`: passenden Provider anhand des gespeicherten Algorithmus auflösen.
- `resolvePepper`: in Phase 1a nur Hook mit `NoOpPepperService`.
- `verify`: Provider führt KDF und konstantzeitnahen Vergleich aus.
- `rehashDecision`: Policy entscheidet, ob eine Aufwertung erforderlich ist.

### 5.2 Zentrale Typen

Die Kernschicht führt diese Typen ein:

```text
PasswordHashingService
PasswordHashProvider
PasswordHashPolicy
PasswordHashCodec
PasswordHashValidator
PasswordHashParameterValidator
KdfExecutionLimiter
KdfResourceBudget
PepperService / NoOpPepperService
DummyVerificationService
PasswordHashResult
CredentialVerificationResult
RehashDecision
ProviderVerificationResult
CredentialType
SecretValue
```

### 5.3 CredentialType

`CredentialType` ist in Phase 1a nur ein diskriminierendes Metadatum. Unterstützt wird ausschließlich:

```text
PASSWORD
```

Weitere Typen wie `WEBAUTHN`, `TOTP`, `API_TOKEN` oder `REMEMBER_ME` werden später durch eigene Services modelliert. Sie werden nicht durch den Passwort-Hashing-Pfad geschleust.

---

## 6. Hashing-Modell

### 6.1 Core-Default

Der Core-Default ist:

```text
PBKDF2WithHmacSHA256
```

Der konkrete Iterationswert wird über `PasswordHashPolicy` definiert. Später kann eine Kalibrierung auf Ziel-Rechenzeit erfolgen.

### 6.2 Modernes Profil

Das Profil `modern` bevorzugt `Argon2id`, aber nur wenn `security-crypto-bc` vorhanden und das Profil explizit aktiviert ist. Fehlt der Provider, muss die Initialisierung kontrolliert fehlschlagen, sofern kein expliziter Policy-Fallback erlaubt ist.

### 6.3 FIPS-Profil

Das FIPS-Profil ist eine eigene bewusste Betriebsart. Es ist nicht gleichbedeutend mit Argon2id, bcrypt oder scrypt. In der Praxis wird das FIPS-Profil für Passwortspeicherung typischerweise auf PBKDF2 mit zulässigem HMAC-Verfahren und zugelassenem Provider hinauslaufen.

---

## 7. Umschlagformat

Das erste produktive Schreibformat ist ein eigenes selbstbeschreibendes Envelope-Format. Es enthält mindestens:

```text
formatVersion
credentialType
algorithm
providerId
policyVersion
parameters
innerHash
optionalPepperKeyId
```

Die Formatversion ist strikt von der Policy-Version getrennt:

- `formatVersion`: Wie wird der Umschlag gelesen?
- `policyVersion`: Nach welcher Sicherheitsrichtlinie wurde der Hash erzeugt?

Unbekannte neuere Formatversionen werden klar abgelehnt. Eigene ältere Formatversionen können in späteren Versionen dekodiert, als rehash-bedürftig markiert oder kontrolliert abgelehnt werden.

---

## 8. Failure-Path- und Enumeration-Schutz

Das System darf nach außen nicht unterscheiden zwischen:

- unbekanntem Benutzer,
- falschem Passwort,
- defektem Hash,
- fehlendem Provider,
- unbekanntem Algorithmus,
- unbekanntem Pepper-Key.

Die öffentliche Reaktion bleibt generisch. Intern dürfen Audit-Events differenzieren.

Der Dummy-Pfad führt bei unbekannten oder technisch fehlerhaften Zuständen eine vergleichbare, nicht zwingend identische KDF-Arbeit gegen einen Dummy-Hash aus. Bei fehlendem Zielprovider wird ein verfügbarer Default-Dummy-Provider der aktiven Policy verwendet.

---

## 9. KDF-Ressourcensteuerung

Phase 1a enthält einen `KdfExecutionLimiter` zur Begrenzung gleichzeitig laufender KDF-Operationen. Überzählige Anfragen werden mit beschränkter Wartezeit gedrosselt oder generisch abgewiesen. Diese Abweisung darf kein neues Unterscheidungssignal erzeugen.

Für speicherharte Verfahren wird das Speicherbudget erst mit den Provider-Modulen relevant. Der Core definiert dafür generische Strukturen; Provider liefern `ResourceEstimate`-Werte.

---

## 10. Credential Lifecycle

Der Credential-Lifecycle umfasst mindestens diese Zustände:

```text
ACTIVE
MUST_CHANGE
RESET_PENDING
COMPROMISED
LOCKED
DISABLED
REHASH_REQUIRED
DEPRECATED_ALGORITHM
```

Der Core liefert Status- und Entscheidungsobjekte, aber keine Vaadin-spezifischen UI-Aktionen.

---

## 11. Reset und Recovery

Reset-Tokens verwenden ein Selector-/Verifier-Modell:

```text
token = selector.verifier
```

- Der `selector` dient als Lookup-Key.
- Der `verifier` ist geheim.
- Persistiert werden nur Selector, Verifier-Digest, Ablaufzeit, Status und Audit-Metadaten.
- Der Verifier wird konstantzeitnah geprüft.
- Der Verbrauch erfolgt atomar.

Reset-, Remember-Me- und vergleichbare Token verwenden einen eigenen `TokenDigestService`. Sie verwenden nicht den random-salt Password-Hashing-Pfad für Lookup-by-Hash.

---

## 12. Persistenz und Atomicity

Die `CredentialStore`-Abstraktion kapselt persistente Credential-Updates. Wichtige Operationen sind:

```text
loadCredential(...)
updateHashIfCurrent(...)
updateStatusIfCurrent(...)
storeResetTokenDigest(...)
consumeResetTokenIfCurrent(...)
```

Transparente Rehashes verwenden `originalEncodedHash` aus `CredentialVerificationResult`, damit Updates per Compare-and-Swap erfolgen können.

---

## 13. Abuse Detection

Abuse Detection ist mehrdimensional:

- pro Benutzer,
- pro IP,
- pro Tenant,
- pro Device-Kontext,
- global,
- Reset-spezifisch,
- Spraying-spezifisch,
- Credential-Stuffing-spezifisch.

Öffentliche Reaktionen dürfen nicht offenbaren, ob ein Benutzer oder Tenant existiert.

---

## 14. Compliance und Traceability

Die Umsetzung wird über separate Dokumente auf CWE, OWASP ASVS V2 und NIST SP 800-63B abgebildet. Die Traceability erfolgt über stabile Feature-IDs (`PWH-*`) und die Zielversion `00.71.00`.

---

## 15. Implementierungsphasen

### Phase 1a – Minimal tragfähiger Hashing-Kern

Umfasst:

- `PasswordHashingService`
- `PasswordHashProvider`-SPI
- Ergebnisobjekte
- Envelope/Codec
- Validator
- PBKDF2-Provider
- Policy
- Verifikationspipeline
- Dummy-Verifikation
- KDF-Ausführungslimit
- Bootstrap-/Demo-Anbindung

### Phase 1b – Optionales BouncyCastle-Modul

Umfasst:

- Argon2id
- bcrypt
- scrypt
- Resource Estimates
- algorithmusspezifische Validatoren
- Cross-Provider-Tests

### Phase 2 – Pepper und Secret Handling

Umfasst:

- echter Pepper-HMAC
- Pepper-Key-ID
- Rotation
- `SecretValue`
- sichere Eingabebehandlung

### Phase 3 – Credential Lifecycle, Reset und atomare Persistierung

Umfasst:

- `CredentialStatus`
- Passwortwechsel
- Reset-Tokens
- `CredentialStore`
- CAS-Updates

### Phase 4 – Abuse Detection und Context-Aware Policy

Umfasst:

- Rate Limiting
- Credential Stuffing
- Password Spraying
- Kontext-Policy
- Passwort-Historie

### Phase 5 – Betrieb, Compliance und Mandantenfähigkeit

Umfasst:

- HIBP-Opt-in
- FIPS-Profil
- Emergency Playbooks
- Tenant Policies
- Standards-Mapping

---

## 16. Ableitung von Implementierungsprompts

Ein Implementierungsprompt darf nur ein kohärentes Feature-Cluster enthalten. Er muss enthalten:

- Zielversion `00.71.00`
- Zielmodule
- Scope
- Non-Goals
- Architekturregeln
- konkrete API-Typen
- Verhalten
- Tests
- relevante CWE-Abdeckung
- Definition of Done

Die erste Prompt-Serie umfasst Phase 1a:

1. Core Result Types
2. Password Hash Envelope and Codec
3. Password Hash Policy and Validator
4. Password Hash Provider SPI
5. PBKDF2 Provider
6. Verification Pipeline
7. Dummy Verification and KDF Limiter
8. Bootstrap and Demo Integration
