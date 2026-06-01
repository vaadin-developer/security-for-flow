# Security for Flow – Implementierungsplan `00.71.00`

Zielprojekt: `vaadin-developer/security-for-flow`  
Basis: Featureliste v9  
Sprache: Java 26  
Build: Maven  
Lizenz: EUPL 1.2

---

## 1. Ziel dieses Plans

Dieser Plan übersetzt das Konzept zur Passwort- und Credential-Sicherheit in reviewbare Implementierungseinheiten. Die Implementierung erfolgt nicht als großer Monolith, sondern in kleinen, testbaren Prompts.

Die erste Umsetzungsserie beschränkt sich auf **Phase 1a – Minimal tragfähiger Hashing-Kern**.

---

## 2. Grundregeln für alle Prompts

Jeder Prompt muss diese Regeln wiederholen:

- Keine neuen Runtime-Abhängigkeiten in `security-core`.
- Keine Eigenentwicklung kryptographischer Primitive.
- Keine primitiven Boolean-Verifikationsergebnisse als alleiniges Ergebnis.
- Keine stille Änderung der globalen JCA-Provider-Reihenfolge.
- Keine Geheimnisse in Logs, Exceptions oder `toString()`.
- Öffentliche Fehler bleiben generisch.
- Interne Audit-/Failure-Typen dürfen differenzieren.
- Kein Kompatibilitätsmodus für bisherige experimentelle Hashformate.
- Zielversion ist `00.71.00`.

---

## 3. Prompt-Reihenfolge für Phase 1a

| Nr. | Datei | Ziel | Hauptfeatures |
|---:|---|---|---|
| 001 | `001-core-result-types.md` | Unveränderliche Ergebnis- und Entscheidungstypen | PWH-A10, PWH-A15, PWH-A16 |
| 002 | `002-password-hash-envelope-codec.md` | Umschlagformat und Codec | PWH-A3, PWH-A16, PWH-I2, PWH-I3 |
| 003 | `003-password-hash-policy-validator.md` | Policy, Parametergrenzen und Validator | PWH-A5, PWH-C1, PWH-C10 |
| 004 | `004-password-hash-provider-spi.md` | Provider-SPI und Registry | PWH-A2, PWH-A13, PWH-J1-J4 |
| 005 | `005-pbkdf2-provider.md` | JDK-only PBKDF2-Provider | PWH-A4, PWH-A8, PWH-A12, PWH-I1 |
| 006 | `006-verification-pipeline.md` | Orchestrierte Pipeline | PWH-A6, PWH-A7, PWH-A14, PWH-C2-C3 |
| 007 | `007-dummy-verification-and-kdf-limiter.md` | Dummy-Verifikation und KDF-Limiter | PWH-A9, PWH-H9, PWH-I7, PWH-I12 |
| 008 | `008-bootstrap-and-demo-integration.md` | Integration in Bootstrap, Vaadin-/REST-Demos | PWH-G1, PWH-G4, PWH-G5, PWH-G6 |

---

## 4. Phase-1a-Ergebnis

Nach Abschluss der ersten acht Prompts existiert:

- ein neuer `PasswordHashingService`,
- eine Provider-SPI,
- ein erstes produktives Envelope-Format,
- eine Policy- und Validator-Schicht,
- ein JDK-only PBKDF2-Provider,
- strukturierte Ergebnisobjekte,
- eine sichere Verifikationspipeline,
- Dummy-Failure-Pfade,
- ein KDF-Concurrency-Limiter,
- Bootstrap-/Demo-Anbindung.

Nicht vorhanden sind dann bewusst noch:

- BouncyCastle-Provider,
- echter Pepper-HMAC,
- CredentialStore,
- Reset-/Recovery-Flows,
- Abuse Detection,
- FIPS,
- HIBP,
- Brownfield-Import.

---

## 5. Review- und Merge-Strategie

Jeder Prompt sollte als eigener PR umgesetzt werden. Ein PR ist nur mergefähig, wenn:

- der Maven-Build grün ist,
- neue Unit-Tests vorhanden sind,
- kein Secret in Logs/Exceptions/`toString()` exponiert wird,
- die neuen Typen unveränderlich oder klar lebenszyklusgesteuert sind,
- die Architekturregeln eingehalten sind,
- JavaDoc an sicherheitsrelevanten APIs vorhanden ist.

---

## 6. Nachgelagerte Phasen

Nach Phase 1a folgen:

1. **Phase 1b:** `security-crypto-bc` mit Argon2id, bcrypt, scrypt und Resource Estimates.
2. **Phase 2:** echter Pepper-HMAC, Pepper-Rotation und `SecretValue`.
3. **Phase 3:** Credential Lifecycle, Reset und atomare Persistenz.
4. **Phase 4:** Abuse Detection und Context-Aware Password Policy.
5. **Phase 5:** Betrieb, FIPS, HIBP, Tenant-Policies und Compliance-Mapping.
