# CWE-zentrierte Feature-Abdeckung für `security-for-flow`

**Zielversion der aufgeführten Features:** `00.71.00`

Grundlage: Featureliste v8 und daraus abgeleitetes Feature-zu-CWE-Mapping.

Diese Datei dreht die Perspektive um: Statt **Feature → CWE** zeigt sie **CWE → beschreibende Feature-Namen mit Feature-ID und Zielversion**. Dadurch ist schneller erkennbar, welche fachlichen Bausteine zusammen eine Schwachstellenklasse adressieren und in welcher Zielversion sie vorgesehen sind.

Hinweis: „Abdeckung“ bedeutet hier **Risikoreduktion/Mitigation**. Eine CWE wird in der Regel nicht durch ein einzelnes Feature vollständig beseitigt, sondern durch ein Cluster aus Implementierungsfeatures, Tests, Betriebsregeln und Dokumentation.

## Übersicht

| CWE | CWE-Titel | Direkt abdeckende Feature-Namen | Unterstützende Features / Tests / Governance |
| --- | --- | ---: | ---: |
| CWE-16 | Configuration | 2 | 0 |
| CWE-20 | Improper Input Validation | 8 | 3 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | 15 | 0 |
| CWE-203 | Observable Discrepancy | 11 | 1 |
| CWE-208 | Observable Timing Discrepancy | 3 | 1 |
| CWE-209 | Generation of Error Message Containing Sensitive Information | 7 | 0 |
| CWE-223 | Omission of Security-relevant Information | 3 | 3 |
| CWE-256 | Plaintext Storage of a Password | 1 | 0 |
| CWE-257 | Storing Passwords in a Recoverable Format | 3 | 0 |
| CWE-284 | Improper Access Control | 10 | 1 |
| CWE-287 | Improper Authentication | 25 | 4 |
| CWE-306 | Missing Authentication for Critical Function | 5 | 0 |
| CWE-307 | Improper Restriction of Excessive Authentication Attempts | 15 | 3 |
| CWE-312 | Cleartext Storage of Sensitive Information | 12 | 0 |
| CWE-321 | Use of Hard-coded Cryptographic Key | 10 | 1 |
| CWE-325 | Missing Cryptographic Step | 11 | 2 |
| CWE-326 | Inadequate Encryption Strength | 8 | 0 |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm | 35 | 8 |
| CWE-330 | Use of Insufficiently Random Values | 5 | 2 |
| CWE-338 | Use of Cryptographically Weak Pseudo-Random Number Generator | 4 | 2 |
| CWE-362 | Race Condition | 9 | 1 |
| CWE-367 | Time-of-check Time-of-use Race Condition | 9 | 1 |
| CWE-400 | Uncontrolled Resource Consumption | 14 | 3 |
| CWE-521 | Weak Password Requirements | 14 | 2 |
| CWE-522 | Insufficiently Protected Credentials | 50 | 7 |
| CWE-532 | Insertion of Sensitive Information into Log File | 8 | 0 |
| CWE-613 | Insufficient Session Expiration | 2 | 0 |
| CWE-620 | Unverified Password Change | 3 | 0 |
| CWE-639 | Authorization Bypass Through User-Controlled Key | 2 | 0 |
| CWE-640 | Weak Password Recovery Mechanism for Forgotten Password | 13 | 1 |
| CWE-759 | Use of a One-Way Hash without a Salt | 1 | 2 |
| CWE-760 | Use of a One-Way Hash with a Predictable Salt | 1 | 1 |
| CWE-770 | Allocation of Resources Without Limits or Throttling | 9 | 1 |
| CWE-778 | Insufficient Logging | 13 | 6 |
| CWE-798 | Use of Hard-coded Credentials | 3 | 0 |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | 6 | 1 |
| CWE-863 | Incorrect Authorization | 4 | 0 |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort | 21 | 7 |
| CWE-1104 | Use of Unmaintained Third Party Components | 4 | 1 |
| CWE-1240 | Use of a Cryptographic Primitive with a Risky Implementation | 3 | 1 |

## Detaillierte CWE-zu-Feature-Zuordnung

## CWE-16 – Configuration

**Direkt abdeckende Feature-Namen**

- Zentrale Konfiguration im bestehenden Lade-Stil (`PWH-H5`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Startvalidierung der Konfiguration (`PWH-H6`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_


## CWE-20 – Improper Input Validation

**Direkt abdeckende Feature-Namen**

- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Umschlag-Formatversion getrennt von der Policy-Version (`PWH-A16`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Format-Deprecation für eigene alte Formatversionen (`PWH-C4`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Obergrenzen-Validierung der Hash-Parameter (`PWH-C10`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Längen- und Encoding-Policy (`PWH-E4`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Startvalidierung der Konfiguration (`PWH-H6`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Roundtrip-Tests des Codecs (`PWH-I2`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Malformed-Input-Tests (`PWH-I3`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Unsupported-Algorithm-Tests (`PWH-I4`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor

**Direkt abdeckende Feature-Namen**

- Generische öffentliche Fehler, differenzierte interne Audit-Typen (`PWH-A11`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Deterministische Nullsetzung sensibler Arrays (`PWH-E2`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Optionales Modul für k-Anonymitätsabfrage (`PWH-F3`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-credentials-hibp`_
- Einheitliche öffentliche Fehlermeldung (`PWH-G4`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Messpunkte für Dauer je `hash` und `verify` (`PWH-H1`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Audit- und Metriksignale (`PWH-N8`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- `SecretValue` oder `PasswordSecret` (`PWH-P1`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- `AutoCloseable`-Lifecycle (`PWH-P2`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kontrollierte Konvertierung nach UTF-8 (`PWH-P3`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kein Geheimnis in `toString()` (`PWH-P4`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Destroyed-State (`PWH-P5`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Tests gegen versehentliche Exposition (`PWH-P7`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: Tests_
- Tenant-sichere Auditdaten (`PWH-R5`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-203 – Observable Discrepancy

**Direkt abdeckende Feature-Namen**

- Neue `PasswordHashingService`-Architektur statt Stabilisierung der experimentellen `PasswordHasher`-API (`PWH-A1`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Konstantzeitnaher Vergleich gekapselt (`PWH-A8`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Explizite Ergebnisobjekte statt Boolean-Rückgaben (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Generische öffentliche Fehler, differenzierte interne Audit-Typen (`PWH-A11`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Pepper-symmetrischer Dummy-Pfad (`PWH-D8`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Einheitliche öffentliche Fehlermeldung (`PWH-G4`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Interne Fehlerklassifikation (`PWH-G5`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Generische Reset-Fehlermeldungen (`PWH-L6`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Generische öffentliche Reaktion (`PWH-N7`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Timing-sensitive Failure-Path-Tests (`PWH-I7`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-208 – Observable Timing Discrepancy

**Direkt abdeckende Feature-Namen**

- Konstantzeitnaher Vergleich gekapselt (`PWH-A8`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Pepper-symmetrischer Dummy-Pfad (`PWH-D8`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Timing-sensitive Failure-Path-Tests (`PWH-I7`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-209 – Generation of Error Message Containing Sensitive Information

**Direkt abdeckende Feature-Namen**

- Explizite Ergebnisobjekte statt Boolean-Rückgaben (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Generische öffentliche Fehler, differenzierte interne Audit-Typen (`PWH-A11`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitliche öffentliche Fehlermeldung (`PWH-G4`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Interne Fehlerklassifikation (`PWH-G5`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Generische Reset-Fehlermeldungen (`PWH-L6`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Generische öffentliche Reaktion (`PWH-N7`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-223 – Omission of Security-relevant Information

**Direkt abdeckende Feature-Namen**

- Algorithmusverteilung (`PWH-H2`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Rehash-Zähler (`PWH-H3`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Credential-Lifecycle-Metriken (`PWH-H7`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Audit-Review-Checkliste (`PWH-Q7`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Feature-ID-basierte Traceability-Matrix (`PWH-S3`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._
- Lückenverfolgung (`PWH-S4`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-256 – Plaintext Storage of a Password

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_


## CWE-257 – Storing Passwords in a Recoverable Format

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Keine pauschale Offline-Rotation ohne Passwort (`PWH-D5`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `docs`, `security-core`_
- Sichere Historien-Speicherung (`PWH-O6`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core` / `CredentialStore`_


## CWE-284 – Improper Access Control

**Direkt abdeckende Feature-Namen**

- Minimaler `CredentialType`-Haken (`PWH-A15`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `CredentialStatus`-Modell (`PWH-K1`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `CredentialLifecycleService` (`PWH-K2`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- UI-/API-neutrale Statusentscheidung (`PWH-K9`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `TenantCredentialContext` (`PWH-R1`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische `PasswordHashPolicy` (`PWH-R2`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische Pepper-Key-Auflösung (`PWH-R3`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifisches Rate Limiting (`PWH-R4`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-credentials-abuse`_
- Tenant-sichere Auditdaten (`PWH-R5`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Default für Single-Tenant-Anwendungen (`PWH-R7`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Lifecycle-Status-Tests (`PWH-I10`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-287 – Improper Authentication

**Direkt abdeckende Feature-Namen**

- Neue `PasswordHashingService`-Architektur statt Stabilisierung der experimentellen `PasswordHasher`-API (`PWH-A1`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Explizite Ergebnisobjekte statt Boolean-Rückgaben (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Provider-Auswahl bei der Verifikation anhand der im Hash kodierten Algorithmuskennung (`PWH-A13`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Minimaler `CredentialType`-Haken (`PWH-A15`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Unicode-Normalisierung (`PWH-E3`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- `CompromisedPasswordChecker`-SPI (`PWH-F1`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Konfigurierbares Verhalten bei Prüfausfall (`PWH-F4`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Prüfung nur zum Festlegungs-/Änderungszeitpunkt (`PWH-F5`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`, `security-credentials-hibp`_
- Verzahnung mit `LoginAttemptPolicy` (`PWH-G2`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Demo-Integration für Vaadin und REST (`PWH-G6`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `demo-*`_
- `CredentialStatus`-Modell (`PWH-K1`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `CredentialLifecycleService` (`PWH-K2`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- Sicherer Passwortwechsel (`PWH-K3`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Demo_
- Re-Authentifikation vor sensitiven Credential-Operationen (`PWH-K4`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Integrationsschicht_
- Session-Handling nach Passwortwechsel (`PWH-K5`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: Integrationsschicht / Demo_
- Forced Password Change (`PWH-K6`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `PasswordResetTokenService` (`PWH-L1`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Reset setzt Credential-Status (`PWH-L7`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Keine Account-Zustandsänderung vor gültigem Token (`PWH-L10`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Persistenzneutrale Demos (`PWH-M7`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `demo-*`_
- `AbuseDetectionService` (`PWH-N1`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` oder `security-credentials-abuse`_
- Password-Spraying-Erkennung (`PWH-N3`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Credential-Stuffing-Signale (`PWH-N4`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Progressive Reaktion (`PWH-N6`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Lifecycle-Status-Tests (`PWH-I10`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Emergency Policy Override (`PWH-Q4`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mass Forced Password Change (`PWH-Q5`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core` / Integrationsschicht; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf OWASP ASVS V2 (Authentication) (`PWH-S1`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-306 – Missing Authentication for Critical Function

**Direkt abdeckende Feature-Namen**

- Minimaler `CredentialType`-Haken (`PWH-A15`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Konfigurierbares Verhalten bei Prüfausfall (`PWH-F4`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Integration in den Bootstrap-Flow (`PWH-G1`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Re-Authentifikation vor sensitiven Credential-Operationen (`PWH-K4`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Integrationsschicht_
- Keine Account-Zustandsänderung vor gültigem Token (`PWH-L10`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_


## CWE-307 – Improper Restriction of Excessive Authentication Attempts

**Direkt abdeckende Feature-Namen**

- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände (`PWH-A9`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Verzahnung mit `LoginAttemptPolicy` (`PWH-G2`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Demo-Integration für Vaadin und REST (`PWH-G6`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `demo-*`_
- Abuse- und Rate-Limit-Metriken (`PWH-H8`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core` oder `security-credentials-abuse`_
- Begrenzung gleichzeitiger KDF-Berechnungen (`PWH-H9`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Reset-Rate-Limiting (`PWH-L9`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `security-credentials-abuse`_
- `AbuseDetectionService` (`PWH-N1`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` oder `security-credentials-abuse`_
- Mehrdimensionales Rate Limiting (`PWH-N2`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Password-Spraying-Erkennung (`PWH-N3`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Credential-Stuffing-Signale (`PWH-N4`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Reset-Abuse-Erkennung (`PWH-N5`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Progressive Reaktion (`PWH-N6`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Generische öffentliche Reaktion (`PWH-N7`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core`_
- Cluster-/Multi-Node-Fähigkeit als Integrationsanforderung (`PWH-N9`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: docs / Integrationsschicht_
- Tenant-spezifisches Rate Limiting (`PWH-R4`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-credentials-abuse`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Abuse-Detection-Tests (`PWH-I11`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-credentials-abuse`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Reset-Abuse-Response-Playbook (`PWH-Q6`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf OWASP ASVS V2 (Authentication) (`PWH-S1`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-312 – Cleartext Storage of Sensitive Information

**Direkt abdeckende Feature-Namen**

- Optionaler PKCS#11-/HSM-Key-Provider (`PWH-D7`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: separates optionales Modul oder `security-crypto-bcfips`_
- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Deterministische Nullsetzung sensibler Arrays (`PWH-E2`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Gehashte Speicherung von Reset-Tokens (`PWH-L3`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Selector-/Verifier-Modell für Reset-Tokens (`PWH-L11`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gemeinsame Token-Digest-Abstraktion (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Sichere Historien-Speicherung (`PWH-O6`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core` / `CredentialStore`_
- `SecretValue` oder `PasswordSecret` (`PWH-P1`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- `AutoCloseable`-Lifecycle (`PWH-P2`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kontrollierte Konvertierung nach UTF-8 (`PWH-P3`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Destroyed-State (`PWH-P5`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Interoperabilität mit bestehenden `char[]`-APIs (`PWH-P6`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_


## CWE-321 – Use of Hard-coded Cryptographic Key

**Direkt abdeckende Feature-Namen**

- Pepper-Key-ID im gespeicherten Hashwert (`PWH-D2`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- `PepperService`-SPI (`PWH-D3`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Rotation bei erfolgreicher Verifikation (`PWH-D4`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Lokale Pepper-Quelle für Demo und Entwicklung (`PWH-D6`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `demo-*` oder optionales Beispielmodul_
- Optionaler PKCS#11-/HSM-Key-Provider (`PWH-D7`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: separates optionales Modul oder `security-crypto-bcfips`_
- Pepper-symmetrischer Dummy-Pfad (`PWH-D8`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Schlüssel-Erzeugung und initiales Einbringen (`PWH-D9`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`, `docs`_
- Policy-Transition „ohne Pepper → mit Pepper“ (`PWH-D10`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Rotationsfenster mit mehreren gültigen Pepper-Schlüsseln (`PWH-D11`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Tenant-spezifische Pepper-Key-Auflösung (`PWH-R3`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Pepper-Compromise-Playbook (`PWH-Q1`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-325 – Missing Cryptographic Step

**Direkt abdeckende Feature-Namen**

- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Provider-Auswahl bei der Verifikation anhand der im Hash kodierten Algorithmuskennung (`PWH-A13`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Umschlag-Formatversion getrennt von der Policy-Version (`PWH-A16`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Policy-Versionierung (`PWH-C2`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Format-Deprecation für eigene alte Formatversionen (`PWH-C4`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Keine Pflicht zur Altformat-Kompatibilität (`PWH-C5`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `docs`, `security-core`_
- Algorithmus-Fallback über Policy, nicht über Implementierungszufall (`PWH-C7`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Pepper als post-KDF-HMAC über den abgeleiteten Schlüssel (`PWH-D1`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Lokale Provider-Auswahl pro kryptographischer Operation (`PWH-J1`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Known-Answer-Testvektoren je Verfahren (`PWH-I1`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: jeweiliges Modul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Roundtrip-Tests des Codecs (`PWH-I2`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-326 – Inadequate Encryption Strength

**Direkt abdeckende Feature-Namen**

- Zentrale `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Modern-Profil mit Argon2id als bevorzugtem Verfahren (`PWH-B6`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Kein stilles Downgrade bei fehlendem BC-Modul (`PWH-B7`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-core`, `security-crypto-bc`_
- Zentrale Parameter-Richtlinie je Algorithmus (`PWH-C1`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Deprecation-Richtlinie nach Stichtag oder Parametersatz (`PWH-C6`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Algorithmus-Fallback über Policy, nicht über Implementierungszufall (`PWH-C7`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- FIPS-Profil als separate bewusste Betriebsart (`PWH-J8`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-crypto-bcfips`, `docs`_


## CWE-327 – Use of a Broken or Risky Cryptographic Algorithm

**Direkt abdeckende Feature-Namen**

- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Zentrale `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `needsRehash` auf Basis der Policy (`PWH-A6`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Transparente Aufwertung bei erfolgreicher Verifikation (`PWH-A7`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Provider-Auswahl bei der Verifikation anhand der im Hash kodierten Algorithmuskennung (`PWH-A13`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Umschlag-Formatversion getrennt von der Policy-Version (`PWH-A16`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Neues Modul `security-crypto-bc` (`PWH-B1`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Argon2id-Provider (`PWH-B2`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- bcrypt-Provider (`PWH-B3`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- scrypt-Provider (`PWH-B4`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Registrierung per `ServiceLoader` (`PWH-B5`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Modern-Profil mit Argon2id als bevorzugtem Verfahren (`PWH-B6`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Kein stilles Downgrade bei fehlendem BC-Modul (`PWH-B7`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-core`, `security-crypto-bc`_
- Cross-Provider- und Roundtrip-Tests (`PWH-B8`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Zentrale Parameter-Richtlinie je Algorithmus (`PWH-C1`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Policy-Versionierung (`PWH-C2`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Transparenter Rehash bei erfolgreicher Verifikation (`PWH-C3`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Format-Deprecation für eigene alte Formatversionen (`PWH-C4`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Keine Pflicht zur Altformat-Kompatibilität (`PWH-C5`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `docs`, `security-core`_
- Deprecation-Richtlinie nach Stichtag oder Parametersatz (`PWH-C6`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Algorithmus-Fallback über Policy, nicht über Implementierungszufall (`PWH-C7`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Optionale Vorverdichtung überlanger Passwörter nur mit Pepper-HMAC (`PWH-E5`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Aktive Provider- und Policy-Auskunft (`PWH-H4`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Zentrale Konfiguration im bestehenden Lade-Stil (`PWH-H5`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Startvalidierung der Konfiguration (`PWH-H6`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Lokale Provider-Auswahl pro kryptographischer Operation (`PWH-J1`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Konfigurierbarer JCA-/JCE-Provider pro Primitive (`PWH-J2`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Keine Veränderung der globalen JVM-Provider-Reihenfolge ohne expliziten Opt-in (`PWH-J3`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Algorithmuswechsel über Policy (`PWH-J5`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Dokumentierte JDK-Distributionsentscheidung (`PWH-J6`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `docs`_
- SBOM und Provenienznachweis für kryptographischen Pfad (`PWH-J7`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`, `security-crypto-bc`, Build_
- FIPS-Profil als separate bewusste Betriebsart (`PWH-J8`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-crypto-bcfips`, `docs`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Dokumentation zu Password-Shucking-Risiken (`PWH-E6`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Known-Answer-Testvektoren je Verfahren (`PWH-I1`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: jeweiliges Modul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Unsupported-Algorithm-Tests (`PWH-I4`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Differentialtests für BC-Provider (`PWH-I5`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-crypto-bc`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Algorithm-Compromise-Playbook (`PWH-Q2`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Provider-Compromise-Playbook (`PWH-Q3`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Emergency Policy Override (`PWH-Q4`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Rollback-Grenzen dokumentieren (`PWH-Q8`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-330 – Use of Insufficiently Random Values

**Direkt abdeckende Feature-Namen**

- Pepper-Schlüssel-Erzeugung und initiales Einbringen (`PWH-D9`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`, `docs`_
- Konfigurierbarer JCA-/JCE-Provider pro Primitive (`PWH-J2`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Konfigurierbare Entropiequelle (`PWH-J4`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Kryptographisch starke Reset-Tokens (`PWH-L2`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Gemeinsame Token-Digest-Abstraktion (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator

**Direkt abdeckende Feature-Namen**

- Pepper-Schlüssel-Erzeugung und initiales Einbringen (`PWH-D9`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`, `docs`_
- Konfigurierbarer JCA-/JCE-Provider pro Primitive (`PWH-J2`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Konfigurierbare Entropiequelle (`PWH-J4`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Kryptographisch starke Reset-Tokens (`PWH-L2`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-362 – Race Condition

**Direkt abdeckende Feature-Namen**

- Single-use Reset-Tokens (`PWH-L4`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- `CredentialStore`-Abstraktion (`PWH-M1`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Atomarer Rehash per Compare-and-Swap (`PWH-M2`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Passwortwechsel (`PWH-M3`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Reset-Token-Verbrauch (`PWH-M4`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Optimistic-Locking-Metadaten (`PWH-M5`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Keine Blind-Overwrites bei Rehash (`PWH-M6`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Persistenzneutrale Demos (`PWH-M7`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `demo-*`_
- Race-Condition-Testfälle (`PWH-M8`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: Tests_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Race-Condition-Tests für Rehash und Reset (`PWH-I9`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core` / Integrationsmodul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-367 – Time-of-check Time-of-use Race Condition

**Direkt abdeckende Feature-Namen**

- Single-use Reset-Tokens (`PWH-L4`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- `CredentialStore`-Abstraktion (`PWH-M1`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Atomarer Rehash per Compare-and-Swap (`PWH-M2`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Passwortwechsel (`PWH-M3`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Reset-Token-Verbrauch (`PWH-M4`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Optimistic-Locking-Metadaten (`PWH-M5`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Keine Blind-Overwrites bei Rehash (`PWH-M6`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Persistenzneutrale Demos (`PWH-M7`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `demo-*`_
- Race-Condition-Testfälle (`PWH-M8`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: Tests_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Race-Condition-Tests für Rehash und Reset (`PWH-I9`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core` / Integrationsmodul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-400 – Uncontrolled Resource Consumption

**Direkt abdeckende Feature-Namen**

- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Parameter-Kalibrierung (`PWH-C8`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Persistierbare Kalibrierungsprofile (`PWH-C9`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Obergrenzen-Validierung der Hash-Parameter (`PWH-C10`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Längen- und Encoding-Policy (`PWH-E4`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Konfigurierbares Verhalten bei Prüfausfall (`PWH-F4`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Prüfung nur zum Festlegungs-/Änderungszeitpunkt (`PWH-F5`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`, `security-credentials-hibp`_
- Begrenzung gleichzeitiger KDF-Berechnungen (`PWH-H9`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Providerbasiertes Ressourcenbudget für speicherharte Verfahren (`PWH-H10`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`, Provider-Module_
- Reset-Rate-Limiting (`PWH-L9`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `security-credentials-abuse`_
- Mehrdimensionales Rate Limiting (`PWH-N2`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Cluster-/Multi-Node-Fähigkeit als Integrationsanforderung (`PWH-N9`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: docs / Integrationsschicht_
- Mindestlänge und maximale Länge (`PWH-O4`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Malformed-Input-Tests (`PWH-I3`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Abuse-Detection-Tests (`PWH-I11`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-credentials-abuse`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Ressourcenbudget-Tests (`PWH-I12`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`, Provider-Module; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-521 – Weak Password Requirements

**Direkt abdeckende Feature-Namen**

- Unicode-Normalisierung (`PWH-E3`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Längen- und Encoding-Policy (`PWH-E4`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- `CompromisedPasswordChecker`-SPI (`PWH-F1`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Einsteckbare Stärkeabschätzung (`PWH-F2`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Optionales Modul für k-Anonymitätsabfrage (`PWH-F3`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-credentials-hibp`_
- Prüfung nur zum Festlegungs-/Änderungszeitpunkt (`PWH-F5`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`, `security-credentials-hibp`_
- Lokale Blocklisten als souveräner Default (`PWH-F6`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core` oder optionales Datenmodul_
- Keine periodische Rotation als Default (`PWH-K7`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`, `docs`_
- `PasswordContext` (`PWH-O1`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Kontextbezogene Blocklist-Prüfung (`PWH-O2`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Keine Composition Rules als Default (`PWH-O3`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`, `docs`_
- Mindestlänge und maximale Länge (`PWH-O4`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Passwort-Historie optional (`PWH-O5`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Reuse-Prüfung gegen alte eigene Policies (`PWH-O7`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Trade-off-Dokumentation zur Passwort-Historie (`PWH-O8`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Mapping auf NIST SP 800-63B (`PWH-S2`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-522 – Insufficiently Protected Credentials

**Direkt abdeckende Feature-Namen**

- Neue `PasswordHashingService`-Architektur statt Stabilisierung der experimentellen `PasswordHasher`-API (`PWH-A1`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag (`PWH-A3`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Zentrale `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `needsRehash` auf Basis der Policy (`PWH-A6`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Transparente Aufwertung bei erfolgreicher Verifikation (`PWH-A7`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Argon2id-Provider (`PWH-B2`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- bcrypt-Provider (`PWH-B3`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- scrypt-Provider (`PWH-B4`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Kein stilles Downgrade bei fehlendem BC-Modul (`PWH-B7`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-core`, `security-crypto-bc`_
- Transparenter Rehash bei erfolgreicher Verifikation (`PWH-C3`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Keine Pflicht zur Altformat-Kompatibilität (`PWH-C5`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `docs`, `security-core`_
- Pepper als post-KDF-HMAC über den abgeleiteten Schlüssel (`PWH-D1`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Key-ID im gespeicherten Hashwert (`PWH-D2`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- `PepperService`-SPI (`PWH-D3`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Rotation bei erfolgreicher Verifikation (`PWH-D4`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Keine pauschale Offline-Rotation ohne Passwort (`PWH-D5`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `docs`, `security-core`_
- Lokale Pepper-Quelle für Demo und Entwicklung (`PWH-D6`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `demo-*` oder optionales Beispielmodul_
- Optionaler PKCS#11-/HSM-Key-Provider (`PWH-D7`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: separates optionales Modul oder `security-crypto-bcfips`_
- Policy-Transition „ohne Pepper → mit Pepper“ (`PWH-D10`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Rotationsfenster mit mehreren gültigen Pepper-Schlüsseln (`PWH-D11`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Optionale Vorverdichtung überlanger Passwörter nur mit Pepper-HMAC (`PWH-E5`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- `CompromisedPasswordChecker`-SPI (`PWH-F1`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Einsteckbare Stärkeabschätzung (`PWH-F2`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Optionales Modul für k-Anonymitätsabfrage (`PWH-F3`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-credentials-hibp`_
- Lokale Blocklisten als souveräner Default (`PWH-F6`, Version `00.71.00`)  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core` oder optionales Datenmodul_
- Integration in den Bootstrap-Flow (`PWH-G1`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Demo-Integration für Vaadin und REST (`PWH-G6`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `demo-*`_
- Zentrale Konfiguration im bestehenden Lade-Stil (`PWH-H5`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- FIPS-Profil als separate bewusste Betriebsart (`PWH-J8`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-crypto-bcfips`, `docs`_
- Sicherer Passwortwechsel (`PWH-K3`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Demo_
- Forced Password Change (`PWH-K6`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `PasswordResetTokenService` (`PWH-L1`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gehashte Speicherung von Reset-Tokens (`PWH-L3`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Selector-/Verifier-Modell für Reset-Tokens (`PWH-L11`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gemeinsame Token-Digest-Abstraktion (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- `CredentialStore`-Abstraktion (`PWH-M1`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Kontextbezogene Blocklist-Prüfung (`PWH-O2`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Passwort-Historie optional (`PWH-O5`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Sichere Historien-Speicherung (`PWH-O6`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core` / `CredentialStore`_
- Reuse-Prüfung gegen alte eigene Policies (`PWH-O7`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- `SecretValue` oder `PasswordSecret` (`PWH-P1`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kontrollierte Konvertierung nach UTF-8 (`PWH-P3`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Interoperabilität mit bestehenden `char[]`-APIs (`PWH-P6`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Tenant-spezifische `PasswordHashPolicy` (`PWH-R2`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische Pepper-Key-Auflösung (`PWH-R3`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Dokumentation zu Password-Shucking-Risiken (`PWH-E6`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Trade-off-Dokumentation zur Passwort-Historie (`PWH-O8`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Pepper-Compromise-Playbook (`PWH-Q1`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mass Forced Password Change (`PWH-Q5`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core` / Integrationsschicht; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Rollback-Grenzen dokumentieren (`PWH-Q8`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf OWASP ASVS V2 (Authentication) (`PWH-S1`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._
- Mapping auf NIST SP 800-63B (`PWH-S2`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-532 – Insertion of Sensitive Information into Log File

**Direkt abdeckende Feature-Namen**

- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String` (`PWH-E1`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Audit über `SecurityAuditService` (`PWH-G3`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Messpunkte für Dauer je `hash` und `verify` (`PWH-H1`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Audit für Lifecycle-Ereignisse (`PWH-K8`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- Reset-Audit ohne Token-Werte (`PWH-L8`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Audit- und Metriksignale (`PWH-N8`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Kein Geheimnis in `toString()` (`PWH-P4`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Tests gegen versehentliche Exposition (`PWH-P7`, Version `00.71.00`)  
  _Epic: SecretValue API und Secret Handling; Modul: Tests_


## CWE-613 – Insufficient Session Expiration

**Direkt abdeckende Feature-Namen**

- Session-Handling nach Passwortwechsel (`PWH-K5`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: Integrationsschicht / Demo_
- Zeitlich begrenzte Reset-Tokens (`PWH-L5`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_


## CWE-620 – Unverified Password Change

**Direkt abdeckende Feature-Namen**

- Sicherer Passwortwechsel (`PWH-K3`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Demo_
- Re-Authentifikation vor sensitiven Credential-Operationen (`PWH-K4`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Integrationsschicht_
- Atomarer Passwortwechsel (`PWH-M3`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_


## CWE-639 – Authorization Bypass Through User-Controlled Key

**Direkt abdeckende Feature-Namen**

- `TenantCredentialContext` (`PWH-R1`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen (`PWH-R6`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-640 – Weak Password Recovery Mechanism for Forgotten Password

**Direkt abdeckende Feature-Namen**

- `PasswordResetTokenService` (`PWH-L1`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Kryptographisch starke Reset-Tokens (`PWH-L2`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Gehashte Speicherung von Reset-Tokens (`PWH-L3`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Single-use Reset-Tokens (`PWH-L4`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Zeitlich begrenzte Reset-Tokens (`PWH-L5`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Generische Reset-Fehlermeldungen (`PWH-L6`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Reset setzt Credential-Status (`PWH-L7`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Reset-Rate-Limiting (`PWH-L9`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `security-credentials-abuse`_
- Keine Account-Zustandsänderung vor gültigem Token (`PWH-L10`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Selector-/Verifier-Modell für Reset-Tokens (`PWH-L11`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gemeinsame Token-Digest-Abstraktion (`PWH-L12`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Atomarer Reset-Token-Verbrauch (`PWH-M4`, Version `00.71.00`)  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Reset-Abuse-Erkennung (`PWH-N5`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Reset-Abuse-Response-Playbook (`PWH-Q6`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-759 – Use of a One-Way Hash without a Salt

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-760 – Use of a One-Way Hash with a Predictable Salt

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt (`PWH-I6`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-770 – Allocation of Resources Without Limits or Throttling

**Direkt abdeckende Feature-Namen**

- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung (`PWH-A14`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Parameter-Kalibrierung (`PWH-C8`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Persistierbare Kalibrierungsprofile (`PWH-C9`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Obergrenzen-Validierung der Hash-Parameter (`PWH-C10`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Begrenzung gleichzeitiger KDF-Berechnungen (`PWH-H9`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Providerbasiertes Ressourcenbudget für speicherharte Verfahren (`PWH-H10`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`, Provider-Module_
- Mehrdimensionales Rate Limiting (`PWH-N2`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Cluster-/Multi-Node-Fähigkeit als Integrationsanforderung (`PWH-N9`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: docs / Integrationsschicht_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Ressourcenbudget-Tests (`PWH-I12`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`, Provider-Module; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-778 – Insufficient Logging

**Direkt abdeckende Feature-Namen**

- Explizite Ergebnisobjekte statt Boolean-Rückgaben (`PWH-A10`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Audit über `SecurityAuditService` (`PWH-G3`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Interne Fehlerklassifikation (`PWH-G5`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Messpunkte für Dauer je `hash` und `verify` (`PWH-H1`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Algorithmusverteilung (`PWH-H2`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Rehash-Zähler (`PWH-H3`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Aktive Provider- und Policy-Auskunft (`PWH-H4`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Credential-Lifecycle-Metriken (`PWH-H7`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Abuse- und Rate-Limit-Metriken (`PWH-H8`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core` oder `security-credentials-abuse`_
- Audit für Lifecycle-Ereignisse (`PWH-K8`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- Reset-Audit ohne Token-Werte (`PWH-L8`, Version `00.71.00`)  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Audit- und Metriksignale (`PWH-N8`, Version `00.71.00`)  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Tenant-sichere Auditdaten (`PWH-R5`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Pepper-Compromise-Playbook (`PWH-Q1`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Algorithm-Compromise-Playbook (`PWH-Q2`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Reset-Abuse-Response-Playbook (`PWH-Q6`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Audit-Review-Checkliste (`PWH-Q7`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Feature-ID-basierte Traceability-Matrix (`PWH-S3`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._
- Lückenverfolgung (`PWH-S4`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-798 – Use of Hard-coded Credentials

**Direkt abdeckende Feature-Namen**

- `PepperService`-SPI (`PWH-D3`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Lokale Pepper-Quelle für Demo und Entwicklung (`PWH-D6`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `demo-*` oder optionales Beispielmodul_
- Integration in den Bootstrap-Flow (`PWH-G1`, Version `00.71.00`)  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_


## CWE-829 – Inclusion of Functionality from Untrusted Control Sphere

**Direkt abdeckende Feature-Namen**

- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader` (`PWH-A2`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Neues Modul `security-crypto-bc` (`PWH-B1`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Registrierung per `ServiceLoader` (`PWH-B5`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Keine Veränderung der globalen JVM-Provider-Reihenfolge ohne expliziten Opt-in (`PWH-J3`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Dokumentierte JDK-Distributionsentscheidung (`PWH-J6`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `docs`_
- SBOM und Provenienznachweis für kryptographischen Pfad (`PWH-J7`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`, `security-crypto-bc`, Build_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Provider-Compromise-Playbook (`PWH-Q3`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-863 – Incorrect Authorization

**Direkt abdeckende Feature-Namen**

- UI-/API-neutrale Statusentscheidung (`PWH-K9`, Version `00.71.00`)  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `TenantCredentialContext` (`PWH-R1`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische `PasswordHashPolicy` (`PWH-R2`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Default für Single-Tenant-Anwendungen (`PWH-R7`, Version `00.71.00`)  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-916 – Use of Password Hash With Insufficient Computational Effort

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256` (`PWH-A4`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Zentrale `PasswordHashPolicy` (`PWH-A5`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `needsRehash` auf Basis der Policy (`PWH-A6`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Transparente Aufwertung bei erfolgreicher Verifikation (`PWH-A7`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults (`PWH-A12`, Version `00.71.00`)  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Argon2id-Provider (`PWH-B2`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- bcrypt-Provider (`PWH-B3`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- scrypt-Provider (`PWH-B4`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Modern-Profil mit Argon2id als bevorzugtem Verfahren (`PWH-B6`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Cross-Provider- und Roundtrip-Tests (`PWH-B8`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Zentrale Parameter-Richtlinie je Algorithmus (`PWH-C1`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Policy-Versionierung (`PWH-C2`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Transparenter Rehash bei erfolgreicher Verifikation (`PWH-C3`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Deprecation-Richtlinie nach Stichtag oder Parametersatz (`PWH-C6`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Parameter-Kalibrierung (`PWH-C8`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Persistierbare Kalibrierungsprofile (`PWH-C9`, Version `00.71.00`)  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Pepper als post-KDF-HMAC über den abgeleiteten Schlüssel (`PWH-D1`, Version `00.71.00`)  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Optionale Vorverdichtung überlanger Passwörter nur mit Pepper-HMAC (`PWH-E5`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Providerbasiertes Ressourcenbudget für speicherharte Verfahren (`PWH-H10`, Version `00.71.00`)  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`, Provider-Module_
- Algorithmuswechsel über Policy (`PWH-J5`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Reuse-Prüfung gegen alte eigene Policies (`PWH-O7`, Version `00.71.00`)  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Dokumentation zu Password-Shucking-Risiken (`PWH-E6`, Version `00.71.00`)  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Known-Answer-Testvektoren je Verfahren (`PWH-I1`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: jeweiliges Modul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Differentialtests für BC-Provider (`PWH-I5`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-crypto-bc`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter (`PWH-I8`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Algorithm-Compromise-Playbook (`PWH-Q2`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Emergency Policy Override (`PWH-Q4`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf NIST SP 800-63B (`PWH-S2`, Version `00.71.00`)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-1104 – Use of Unmaintained Third Party Components

**Direkt abdeckende Feature-Namen**

- Neues Modul `security-crypto-bc` (`PWH-B1`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Registrierung per `ServiceLoader` (`PWH-B5`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Dokumentierte JDK-Distributionsentscheidung (`PWH-J6`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `docs`_
- SBOM und Provenienznachweis für kryptographischen Pfad (`PWH-J7`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`, `security-crypto-bc`, Build_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Provider-Compromise-Playbook (`PWH-Q3`, Version `00.71.00`)  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-1240 – Use of a Cryptographic Primitive with a Risky Implementation

**Direkt abdeckende Feature-Namen**

- Cross-Provider- und Roundtrip-Tests (`PWH-B8`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates (`PWH-B9`, Version `00.71.00`)  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Lokale Provider-Auswahl pro kryptographischer Operation (`PWH-J1`, Version `00.71.00`)  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Differentialtests für BC-Provider (`PWH-I5`, Version `00.71.00`)  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-crypto-bc`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## Lesart für Implementierung und Review

- **Direkt abdeckende Feature-Namen** sind die Features, die im Runtime-Verhalten, in der API oder in der Architektur unmittelbar gegen die CWE wirken.
- **Unterstützende Features** sind Tests, Playbooks, Dokumentation, Traceability oder Governance-Regeln. Sie beseitigen keine Runtime-Schwachstelle allein, sind aber für dauerhafte Absicherung und Nachweis wichtig.
- Für Implementierungsprompts eignet sich weiterhin die ursprüngliche Feature-Sicht. Für Security-Reviews, Gap-Analyse und Audit ist diese CWE-zentrierte Sicht besser lesbar.
