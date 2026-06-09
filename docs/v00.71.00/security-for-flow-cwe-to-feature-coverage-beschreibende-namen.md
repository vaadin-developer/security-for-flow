# CWE-zentrierte Feature-Abdeckung für `security-for-flow`

Grundlage: Featureliste v8 und daraus abgeleitetes Feature-zu-CWE-Mapping.

Diese Datei dreht die Perspektive um: Statt **Feature → CWE** zeigt sie **CWE → beschreibende Feature-Namen**. Die Feature-IDs werden bewusst nicht als primäres Lesemittel verwendet. Dadurch ist schneller erkennbar, welche fachlichen Bausteine zusammen eine Schwachstellenklasse adressieren.

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

- Zentrale Konfiguration im bestehenden Lade-Stil  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Startvalidierung der Konfiguration  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_


## CWE-20 – Improper Input Validation

**Direkt abdeckende Feature-Namen**

- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Umschlag-Formatversion getrennt von der Policy-Version  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Format-Deprecation für eigene alte Formatversionen  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Obergrenzen-Validierung der Hash-Parameter  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Längen- und Encoding-Policy  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Startvalidierung der Konfiguration  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Roundtrip-Tests des Codecs  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Malformed-Input-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Unsupported-Algorithm-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-200 – Exposure of Sensitive Information to an Unauthorized Actor

**Direkt abdeckende Feature-Namen**

- Generische öffentliche Fehler, differenzierte interne Audit-Typen  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String`  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Deterministische Nullsetzung sensibler Arrays  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Optionales Modul für k-Anonymitätsabfrage  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-credentials-hibp`_
- Einheitliche öffentliche Fehlermeldung  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Messpunkte für Dauer je `hash` und `verify`  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Audit- und Metriksignale  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- `SecretValue` oder `PasswordSecret`  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- `AutoCloseable`-Lifecycle  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kontrollierte Konvertierung nach UTF-8  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kein Geheimnis in `toString()`  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Destroyed-State  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Tests gegen versehentliche Exposition  
  _Epic: SecretValue API und Secret Handling; Modul: Tests_
- Tenant-sichere Auditdaten  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-203 – Observable Discrepancy

**Direkt abdeckende Feature-Namen**

- Neue `PasswordHashingService`-Architektur statt Stabilisierung der experimentellen `PasswordHasher`-API  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Konstantzeitnaher Vergleich gekapselt  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Explizite Ergebnisobjekte statt Boolean-Rückgaben  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Generische öffentliche Fehler, differenzierte interne Audit-Typen  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Pepper-symmetrischer Dummy-Pfad  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Einheitliche öffentliche Fehlermeldung  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Interne Fehlerklassifikation  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Generische Reset-Fehlermeldungen  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Generische öffentliche Reaktion  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Timing-sensitive Failure-Path-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-208 – Observable Timing Discrepancy

**Direkt abdeckende Feature-Namen**

- Konstantzeitnaher Vergleich gekapselt  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Pepper-symmetrischer Dummy-Pfad  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Timing-sensitive Failure-Path-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-209 – Generation of Error Message Containing Sensitive Information

**Direkt abdeckende Feature-Namen**

- Explizite Ergebnisobjekte statt Boolean-Rückgaben  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Generische öffentliche Fehler, differenzierte interne Audit-Typen  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitliche öffentliche Fehlermeldung  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Interne Fehlerklassifikation  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Generische Reset-Fehlermeldungen  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Generische öffentliche Reaktion  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-223 – Omission of Security-relevant Information

**Direkt abdeckende Feature-Namen**

- Algorithmusverteilung  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Rehash-Zähler  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Credential-Lifecycle-Metriken  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Audit-Review-Checkliste  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Feature-ID-basierte Traceability-Matrix  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._
- Lückenverfolgung  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-256 – Plaintext Storage of a Password

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_


## CWE-257 – Storing Passwords in a Recoverable Format

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Keine pauschale Offline-Rotation ohne Passwort  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `docs`, `security-core`_
- Sichere Historien-Speicherung  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core` / `CredentialStore`_


## CWE-284 – Improper Access Control

**Direkt abdeckende Feature-Namen**

- Minimaler `CredentialType`-Haken  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `CredentialStatus`-Modell  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `CredentialLifecycleService`  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- UI-/API-neutrale Statusentscheidung  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `TenantCredentialContext`  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische `PasswordHashPolicy`  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische Pepper-Key-Auflösung  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifisches Rate Limiting  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-credentials-abuse`_
- Tenant-sichere Auditdaten  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Default für Single-Tenant-Anwendungen  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Lifecycle-Status-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-287 – Improper Authentication

**Direkt abdeckende Feature-Namen**

- Neue `PasswordHashingService`-Architektur statt Stabilisierung der experimentellen `PasswordHasher`-API  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Explizite Ergebnisobjekte statt Boolean-Rückgaben  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Provider-Auswahl bei der Verifikation anhand der im Hash kodierten Algorithmuskennung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Minimaler `CredentialType`-Haken  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Unicode-Normalisierung  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- `CompromisedPasswordChecker`-SPI  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Konfigurierbares Verhalten bei Prüfausfall  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Prüfung nur zum Festlegungs-/Änderungszeitpunkt  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`, `security-credentials-hibp`_
- Verzahnung mit `LoginAttemptPolicy`  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Demo-Integration für Vaadin und REST  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `demo-*`_
- `CredentialStatus`-Modell  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `CredentialLifecycleService`  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- Sicherer Passwortwechsel  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Demo_
- Re-Authentifikation vor sensitiven Credential-Operationen  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Integrationsschicht_
- Session-Handling nach Passwortwechsel  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: Integrationsschicht / Demo_
- Forced Password Change  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `PasswordResetTokenService`  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Reset setzt Credential-Status  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Keine Account-Zustandsänderung vor gültigem Token  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Persistenzneutrale Demos  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `demo-*`_
- `AbuseDetectionService`  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` oder `security-credentials-abuse`_
- Password-Spraying-Erkennung  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Credential-Stuffing-Signale  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Progressive Reaktion  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Lifecycle-Status-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Emergency Policy Override  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mass Forced Password Change  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core` / Integrationsschicht; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf OWASP ASVS V2 (Authentication)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-306 – Missing Authentication for Critical Function

**Direkt abdeckende Feature-Namen**

- Minimaler `CredentialType`-Haken  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Konfigurierbares Verhalten bei Prüfausfall  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Integration in den Bootstrap-Flow  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Re-Authentifikation vor sensitiven Credential-Operationen  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Integrationsschicht_
- Keine Account-Zustandsänderung vor gültigem Token  
  _Epic: Password Reset und Recovery; Modul: `security-core`_


## CWE-307 – Improper Restriction of Excessive Authentication Attempts

**Direkt abdeckende Feature-Namen**

- Dummy-Verifikation für nicht vorhandene Benutzer und fehlerhafte Hashzustände  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Verzahnung mit `LoginAttemptPolicy`  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Demo-Integration für Vaadin und REST  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `demo-*`_
- Abuse- und Rate-Limit-Metriken  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core` oder `security-credentials-abuse`_
- Begrenzung gleichzeitiger KDF-Berechnungen  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Reset-Rate-Limiting  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `security-credentials-abuse`_
- `AbuseDetectionService`  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` oder `security-credentials-abuse`_
- Mehrdimensionales Rate Limiting  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Password-Spraying-Erkennung  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Credential-Stuffing-Signale  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Reset-Abuse-Erkennung  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_
- Progressive Reaktion  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Generische öffentliche Reaktion  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core`_
- Cluster-/Multi-Node-Fähigkeit als Integrationsanforderung  
  _Epic: Abuse Detection und Rate Limiting; Modul: docs / Integrationsschicht_
- Tenant-spezifisches Rate Limiting  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-credentials-abuse`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Abuse-Detection-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-credentials-abuse`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Reset-Abuse-Response-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf OWASP ASVS V2 (Authentication)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-312 – Cleartext Storage of Sensitive Information

**Direkt abdeckende Feature-Namen**

- Optionaler PKCS#11-/HSM-Key-Provider  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: separates optionales Modul oder `security-crypto-bcfips`_
- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String`  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Deterministische Nullsetzung sensibler Arrays  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Gehashte Speicherung von Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Selector-/Verifier-Modell für Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gemeinsame Token-Digest-Abstraktion  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Sichere Historien-Speicherung  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core` / `CredentialStore`_
- `SecretValue` oder `PasswordSecret`  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- `AutoCloseable`-Lifecycle  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kontrollierte Konvertierung nach UTF-8  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Destroyed-State  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Interoperabilität mit bestehenden `char[]`-APIs  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_


## CWE-321 – Use of Hard-coded Cryptographic Key

**Direkt abdeckende Feature-Namen**

- Pepper-Key-ID im gespeicherten Hashwert  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- `PepperService`-SPI  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Rotation bei erfolgreicher Verifikation  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Lokale Pepper-Quelle für Demo und Entwicklung  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `demo-*` oder optionales Beispielmodul_
- Optionaler PKCS#11-/HSM-Key-Provider  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: separates optionales Modul oder `security-crypto-bcfips`_
- Pepper-symmetrischer Dummy-Pfad  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Schlüssel-Erzeugung und initiales Einbringen  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`, `docs`_
- Policy-Transition „ohne Pepper → mit Pepper“  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Rotationsfenster mit mehreren gültigen Pepper-Schlüsseln  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Tenant-spezifische Pepper-Key-Auflösung  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Pepper-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-325 – Missing Cryptographic Step

**Direkt abdeckende Feature-Namen**

- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Provider-Auswahl bei der Verifikation anhand der im Hash kodierten Algorithmuskennung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Umschlag-Formatversion getrennt von der Policy-Version  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Policy-Versionierung  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Format-Deprecation für eigene alte Formatversionen  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Keine Pflicht zur Altformat-Kompatibilität  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `docs`, `security-core`_
- Algorithmus-Fallback über Policy, nicht über Implementierungszufall  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Pepper als post-KDF-HMAC über den abgeleiteten Schlüssel  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Lokale Provider-Auswahl pro kryptographischer Operation  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Known-Answer-Testvektoren je Verfahren  
  _Epic: Tests und Reproduzierbarkeit; Modul: jeweiliges Modul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Roundtrip-Tests des Codecs  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-326 – Inadequate Encryption Strength

**Direkt abdeckende Feature-Namen**

- Zentrale `PasswordHashPolicy`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Modern-Profil mit Argon2id als bevorzugtem Verfahren  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Kein stilles Downgrade bei fehlendem BC-Modul  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-core`, `security-crypto-bc`_
- Zentrale Parameter-Richtlinie je Algorithmus  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Deprecation-Richtlinie nach Stichtag oder Parametersatz  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Algorithmus-Fallback über Policy, nicht über Implementierungszufall  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- FIPS-Profil als separate bewusste Betriebsart  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-crypto-bcfips`, `docs`_


## CWE-327 – Use of a Broken or Risky Cryptographic Algorithm

**Direkt abdeckende Feature-Namen**

- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Zentrale `PasswordHashPolicy`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `needsRehash` auf Basis der Policy  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Transparente Aufwertung bei erfolgreicher Verifikation  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Provider-Auswahl bei der Verifikation anhand der im Hash kodierten Algorithmuskennung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Umschlag-Formatversion getrennt von der Policy-Version  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Neues Modul `security-crypto-bc`  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Argon2id-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- bcrypt-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- scrypt-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Registrierung per `ServiceLoader`  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Modern-Profil mit Argon2id als bevorzugtem Verfahren  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Kein stilles Downgrade bei fehlendem BC-Modul  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-core`, `security-crypto-bc`_
- Cross-Provider- und Roundtrip-Tests  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Zentrale Parameter-Richtlinie je Algorithmus  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Policy-Versionierung  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Transparenter Rehash bei erfolgreicher Verifikation  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Format-Deprecation für eigene alte Formatversionen  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Keine Pflicht zur Altformat-Kompatibilität  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `docs`, `security-core`_
- Deprecation-Richtlinie nach Stichtag oder Parametersatz  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Algorithmus-Fallback über Policy, nicht über Implementierungszufall  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Optionale Vorverdichtung überlanger Passwörter nur mit Pepper-HMAC  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Aktive Provider- und Policy-Auskunft  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Zentrale Konfiguration im bestehenden Lade-Stil  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Startvalidierung der Konfiguration  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Lokale Provider-Auswahl pro kryptographischer Operation  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Konfigurierbarer JCA-/JCE-Provider pro Primitive  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Keine Veränderung der globalen JVM-Provider-Reihenfolge ohne expliziten Opt-in  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Algorithmuswechsel über Policy  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Dokumentierte JDK-Distributionsentscheidung  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `docs`_
- SBOM und Provenienznachweis für kryptographischen Pfad  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`, `security-crypto-bc`, Build_
- FIPS-Profil als separate bewusste Betriebsart  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-crypto-bcfips`, `docs`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Dokumentation zu Password-Shucking-Risiken  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Known-Answer-Testvektoren je Verfahren  
  _Epic: Tests und Reproduzierbarkeit; Modul: jeweiliges Modul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Unsupported-Algorithm-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Differentialtests für BC-Provider  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-crypto-bc`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Algorithm-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Provider-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Emergency Policy Override  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Rollback-Grenzen dokumentieren  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-330 – Use of Insufficiently Random Values

**Direkt abdeckende Feature-Namen**

- Pepper-Schlüssel-Erzeugung und initiales Einbringen  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`, `docs`_
- Konfigurierbarer JCA-/JCE-Provider pro Primitive  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Konfigurierbare Entropiequelle  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Kryptographisch starke Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Gemeinsame Token-Digest-Abstraktion  
  _Epic: Password Reset und Recovery; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-338 – Use of Cryptographically Weak Pseudo-Random Number Generator

**Direkt abdeckende Feature-Namen**

- Pepper-Schlüssel-Erzeugung und initiales Einbringen  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`, `docs`_
- Konfigurierbarer JCA-/JCE-Provider pro Primitive  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Konfigurierbare Entropiequelle  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Kryptographisch starke Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-362 – Race Condition

**Direkt abdeckende Feature-Namen**

- Single-use Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- `CredentialStore`-Abstraktion  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Atomarer Rehash per Compare-and-Swap  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Passwortwechsel  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Reset-Token-Verbrauch  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Optimistic-Locking-Metadaten  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Keine Blind-Overwrites bei Rehash  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Persistenzneutrale Demos  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `demo-*`_
- Race-Condition-Testfälle  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: Tests_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Race-Condition-Tests für Rehash und Reset  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core` / Integrationsmodul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-367 – Time-of-check Time-of-use Race Condition

**Direkt abdeckende Feature-Namen**

- Single-use Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- `CredentialStore`-Abstraktion  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Atomarer Rehash per Compare-and-Swap  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Passwortwechsel  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Atomarer Reset-Token-Verbrauch  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Optimistic-Locking-Metadaten  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Keine Blind-Overwrites bei Rehash  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Persistenzneutrale Demos  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `demo-*`_
- Race-Condition-Testfälle  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: Tests_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Race-Condition-Tests für Rehash und Reset  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core` / Integrationsmodul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-400 – Uncontrolled Resource Consumption

**Direkt abdeckende Feature-Namen**

- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Parameter-Kalibrierung  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Persistierbare Kalibrierungsprofile  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Obergrenzen-Validierung der Hash-Parameter  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Längen- und Encoding-Policy  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Konfigurierbares Verhalten bei Prüfausfall  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Prüfung nur zum Festlegungs-/Änderungszeitpunkt  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`, `security-credentials-hibp`_
- Begrenzung gleichzeitiger KDF-Berechnungen  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Providerbasiertes Ressourcenbudget für speicherharte Verfahren  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`, Provider-Module_
- Reset-Rate-Limiting  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `security-credentials-abuse`_
- Mehrdimensionales Rate Limiting  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Cluster-/Multi-Node-Fähigkeit als Integrationsanforderung  
  _Epic: Abuse Detection und Rate Limiting; Modul: docs / Integrationsschicht_
- Mindestlänge und maximale Länge  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Malformed-Input-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Abuse-Detection-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-credentials-abuse`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Ressourcenbudget-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`, Provider-Module; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-521 – Weak Password Requirements

**Direkt abdeckende Feature-Namen**

- Unicode-Normalisierung  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Längen- und Encoding-Policy  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- `CompromisedPasswordChecker`-SPI  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Einsteckbare Stärkeabschätzung  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Optionales Modul für k-Anonymitätsabfrage  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-credentials-hibp`_
- Prüfung nur zum Festlegungs-/Änderungszeitpunkt  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`, `security-credentials-hibp`_
- Lokale Blocklisten als souveräner Default  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core` oder optionales Datenmodul_
- Keine periodische Rotation als Default  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`, `docs`_
- `PasswordContext`  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Kontextbezogene Blocklist-Prüfung  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Keine Composition Rules als Default  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`, `docs`_
- Mindestlänge und maximale Länge  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Passwort-Historie optional  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Reuse-Prüfung gegen alte eigene Policies  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Trade-off-Dokumentation zur Passwort-Historie  
  _Epic: Context-Aware Password Policy und Password History; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Mapping auf NIST SP 800-63B  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-522 – Insufficiently Protected Credentials

**Direkt abdeckende Feature-Namen**

- Neue `PasswordHashingService`-Architektur statt Stabilisierung der experimentellen `PasswordHasher`-API  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Einheitlicher selbstbeschreibender Codec; standardkonformer PHC-/MCF-String je Verfahren in eigenem Umschlag  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Zentrale `PasswordHashPolicy`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `needsRehash` auf Basis der Policy  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Transparente Aufwertung bei erfolgreicher Verifikation  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Argon2id-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- bcrypt-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- scrypt-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Kein stilles Downgrade bei fehlendem BC-Modul  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-core`, `security-crypto-bc`_
- Transparenter Rehash bei erfolgreicher Verifikation  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Keine Pflicht zur Altformat-Kompatibilität  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `docs`, `security-core`_
- Pepper als post-KDF-HMAC über den abgeleiteten Schlüssel  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Key-ID im gespeicherten Hashwert  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- `PepperService`-SPI  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Pepper-Rotation bei erfolgreicher Verifikation  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Keine pauschale Offline-Rotation ohne Passwort  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `docs`, `security-core`_
- Lokale Pepper-Quelle für Demo und Entwicklung  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `demo-*` oder optionales Beispielmodul_
- Optionaler PKCS#11-/HSM-Key-Provider  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: separates optionales Modul oder `security-crypto-bcfips`_
- Policy-Transition „ohne Pepper → mit Pepper“  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Rotationsfenster mit mehreren gültigen Pepper-Schlüsseln  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String`  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Optionale Vorverdichtung überlanger Passwörter nur mit Pepper-HMAC  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- `CompromisedPasswordChecker`-SPI  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Einsteckbare Stärkeabschätzung  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core`_
- Optionales Modul für k-Anonymitätsabfrage  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-credentials-hibp`_
- Lokale Blocklisten als souveräner Default  
  _Epic: Qualitäts- und Kompromittierungsprüfung; Modul: `security-core` oder optionales Datenmodul_
- Integration in den Bootstrap-Flow  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Demo-Integration für Vaadin und REST  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `demo-*`_
- Zentrale Konfiguration im bestehenden Lade-Stil  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- FIPS-Profil als separate bewusste Betriebsart  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-crypto-bcfips`, `docs`_
- Sicherer Passwortwechsel  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Demo_
- Forced Password Change  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `PasswordResetTokenService`  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gehashte Speicherung von Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Selector-/Verifier-Modell für Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gemeinsame Token-Digest-Abstraktion  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- `CredentialStore`-Abstraktion  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core`_
- Kontextbezogene Blocklist-Prüfung  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Passwort-Historie optional  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- Sichere Historien-Speicherung  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core` / `CredentialStore`_
- Reuse-Prüfung gegen alte eigene Policies  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_
- `SecretValue` oder `PasswordSecret`  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Kontrollierte Konvertierung nach UTF-8  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Interoperabilität mit bestehenden `char[]`-APIs  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Tenant-spezifische `PasswordHashPolicy`  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische Pepper-Key-Auflösung  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Dokumentation zu Password-Shucking-Risiken  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Trade-off-Dokumentation zur Passwort-Historie  
  _Epic: Context-Aware Password Policy und Password History; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Pepper-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mass Forced Password Change  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core` / Integrationsschicht; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Rollback-Grenzen dokumentieren  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf OWASP ASVS V2 (Authentication)  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._
- Mapping auf NIST SP 800-63B  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-532 – Insertion of Sensitive Information into Log File

**Direkt abdeckende Feature-Namen**

- Verarbeitung über `SecretValue`, `char[]` und `byte[]` statt `String`  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Audit über `JSentinelAuditService`  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Messpunkte für Dauer je `hash` und `verify`  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Audit für Lifecycle-Ereignisse  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- Reset-Audit ohne Token-Werte  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Audit- und Metriksignale  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Kein Geheimnis in `toString()`  
  _Epic: SecretValue API und Secret Handling; Modul: `security-core`_
- Tests gegen versehentliche Exposition  
  _Epic: SecretValue API und Secret Handling; Modul: Tests_


## CWE-613 – Insufficient Session Expiration

**Direkt abdeckende Feature-Namen**

- Session-Handling nach Passwortwechsel  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: Integrationsschicht / Demo_
- Zeitlich begrenzte Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core`_


## CWE-620 – Unverified Password Change

**Direkt abdeckende Feature-Namen**

- Sicherer Passwortwechsel  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Demo_
- Re-Authentifikation vor sensitiven Credential-Operationen  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core` / Integrationsschicht_
- Atomarer Passwortwechsel  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_


## CWE-639 – Authorization Bypass Through User-Controlled Key

**Direkt abdeckende Feature-Namen**

- `TenantCredentialContext`  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Kein Tenant-Leak in Fehlermeldungen  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-640 – Weak Password Recovery Mechanism for Forgotten Password

**Direkt abdeckende Feature-Namen**

- `PasswordResetTokenService`  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Kryptographisch starke Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Gehashte Speicherung von Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Single-use Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `CredentialStore`_
- Zeitlich begrenzte Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Generische Reset-Fehlermeldungen  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Reset setzt Credential-Status  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Reset-Rate-Limiting  
  _Epic: Password Reset und Recovery; Modul: `security-core` / `security-credentials-abuse`_
- Keine Account-Zustandsänderung vor gültigem Token  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Selector-/Verifier-Modell für Reset-Tokens  
  _Epic: Password Reset und Recovery; Modul: `security-core` oder `security-credentials-recovery`_
- Gemeinsame Token-Digest-Abstraktion  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Atomarer Reset-Token-Verbrauch  
  _Epic: Credential Store und Persistenzkonsistenz; Modul: `security-core` / Integrationsschicht_
- Reset-Abuse-Erkennung  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-credentials-abuse`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Reset-Abuse-Response-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-759 – Use of a One-Way Hash without a Salt

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-760 – Use of a One-Way Hash with a Predictable Salt

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Deterministischer Testmodus mit festem Salt  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-770 – Allocation of Resources Without Limits or Throttling

**Direkt abdeckende Feature-Namen**

- Trennung von Parsing, Validierung, Provider-Auflösung, Pepper-Auflösung, Verifikation und Rehash-Entscheidung  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Parameter-Kalibrierung  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Persistierbare Kalibrierungsprofile  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Obergrenzen-Validierung der Hash-Parameter  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Begrenzung gleichzeitiger KDF-Berechnungen  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Providerbasiertes Ressourcenbudget für speicherharte Verfahren  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`, Provider-Module_
- Mehrdimensionales Rate Limiting  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Cluster-/Multi-Node-Fähigkeit als Integrationsanforderung  
  _Epic: Abuse Detection und Rate Limiting; Modul: docs / Integrationsschicht_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Ressourcenbudget-Tests  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`, Provider-Module; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## CWE-778 – Insufficient Logging

**Direkt abdeckende Feature-Namen**

- Explizite Ergebnisobjekte statt Boolean-Rückgaben  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Audit über `JSentinelAuditService`  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Interne Fehlerklassifikation  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_
- Messpunkte für Dauer je `hash` und `verify`  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Algorithmusverteilung  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Rehash-Zähler  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Aktive Provider- und Policy-Auskunft  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Credential-Lifecycle-Metriken  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`_
- Abuse- und Rate-Limit-Metriken  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core` oder `security-credentials-abuse`_
- Audit für Lifecycle-Ereignisse  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- Reset-Audit ohne Token-Werte  
  _Epic: Password Reset und Recovery; Modul: `security-core`_
- Audit- und Metriksignale  
  _Epic: Abuse Detection und Rate Limiting; Modul: `security-core` / optionales Modul_
- Tenant-sichere Auditdaten  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Pepper-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Algorithm-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Reset-Abuse-Response-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Audit-Review-Checkliste  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Feature-ID-basierte Traceability-Matrix  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._
- Lückenverfolgung  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-798 – Use of Hard-coded Credentials

**Direkt abdeckende Feature-Namen**

- `PepperService`-SPI  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Lokale Pepper-Quelle für Demo und Entwicklung  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `demo-*` oder optionales Beispielmodul_
- Integration in den Bootstrap-Flow  
  _Epic: Integration in den bestehenden Sicherheits-Workflow; Modul: `security-core`_


## CWE-829 – Inclusion of Functionality from Untrusted Control Sphere

**Direkt abdeckende Feature-Namen**

- `PasswordHashProvider`-SPI mit Auflösung per `ServiceLoader`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Neues Modul `security-crypto-bc`  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Registrierung per `ServiceLoader`  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Keine Veränderung der globalen JVM-Provider-Reihenfolge ohne expliziten Opt-in  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Dokumentierte JDK-Distributionsentscheidung  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `docs`_
- SBOM und Provenienznachweis für kryptographischen Pfad  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`, `security-crypto-bc`, Build_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Provider-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-863 – Incorrect Authorization

**Direkt abdeckende Feature-Namen**

- UI-/API-neutrale Statusentscheidung  
  _Epic: Credential Lifecycle und Passwortänderung; Modul: `security-core`_
- `TenantCredentialContext`  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Tenant-spezifische `PasswordHashPolicy`  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_
- Default für Single-Tenant-Anwendungen  
  _Epic: Tenant-spezifische Credential Policies; Modul: `security-core`_


## CWE-916 – Use of Password Hash With Insufficient Computational Effort

**Direkt abdeckende Feature-Namen**

- JDK-Provider für `PBKDF2WithHmacSHA256`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Zentrale `PasswordHashPolicy`  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- `needsRehash` auf Basis der Policy  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Transparente Aufwertung bei erfolgreicher Verifikation  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Sichere Core-Defaults  
  _Epic: Core-Hashing-Fundament; Modul: `security-core`_
- Argon2id-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- bcrypt-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- scrypt-Provider  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Modern-Profil mit Argon2id als bevorzugtem Verfahren  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Cross-Provider- und Roundtrip-Tests  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Zentrale Parameter-Richtlinie je Algorithmus  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Policy-Versionierung  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Transparenter Rehash bei erfolgreicher Verifikation  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Deprecation-Richtlinie nach Stichtag oder Parametersatz  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Parameter-Kalibrierung  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Persistierbare Kalibrierungsprofile  
  _Epic: Krypto-Agilität, Policy-Evolution und Rehash; Modul: `security-core`_
- Pepper als post-KDF-HMAC über den abgeleiteten Schlüssel  
  _Epic: Sekret- und Pepper-Verwaltung; Modul: `security-core`_
- Optionale Vorverdichtung überlanger Passwörter nur mit Pepper-HMAC  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `security-core`_
- Providerbasiertes Ressourcenbudget für speicherharte Verfahren  
  _Epic: Beobachtbarkeit, Betrieb und KDF-Ressourcensteuerung; Modul: `security-core`, Provider-Module_
- Algorithmuswechsel über Policy  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_
- Reuse-Prüfung gegen alte eigene Policies  
  _Epic: Context-Aware Password Policy und Password History; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Dokumentation zu Password-Shucking-Risiken  
  _Epic: Eingabehygiene und sichere Behandlung; Modul: `docs`; Bezug: Dokumentations-/Governance-Kontrolle: unterstützt korrekte Umsetzung und Betrieb._
- Known-Answer-Testvektoren je Verfahren  
  _Epic: Tests und Reproduzierbarkeit; Modul: jeweiliges Modul; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Differentialtests für BC-Provider  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-crypto-bc`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Produktivsperre für Testparameter  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-core`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._
- Algorithm-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Emergency Policy Override  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `security-core`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._
- Mapping auf NIST SP 800-63B  
  _Epic: Compliance- und Standards-Nachweis; Modul: `docs`; Bezug: Governance/Nachweis: schafft Traceability, beseitigt aber keine Runtime-Schwachstelle allein._


## CWE-1104 – Use of Unmaintained Third Party Components

**Direkt abdeckende Feature-Namen**

- Neues Modul `security-crypto-bc`  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Registrierung per `ServiceLoader`  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Dokumentierte JDK-Distributionsentscheidung  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `docs`_
- SBOM und Provenienznachweis für kryptographischen Pfad  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`, `security-crypto-bc`, Build_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Provider-Compromise-Playbook  
  _Epic: Emergency Playbooks und Betriebsreaktionen; Modul: `docs`; Bezug: Betriebsreaktion/Playbook: reduziert Schadensdauer und Fehlreaktionen bei Incidents._


## CWE-1240 – Use of a Cryptographic Primitive with a Risky Implementation

**Direkt abdeckende Feature-Namen**

- Cross-Provider- und Roundtrip-Tests  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Algorithmusspezifische Parameter-Validatoren und Resource Estimates  
  _Epic: Optionales BouncyCastle-Provider-Modul; Modul: `security-crypto-bc`_
- Lokale Provider-Auswahl pro kryptographischer Operation  
  _Epic: Provider-Agilität und Distributionsvertrauen; Modul: `security-core`_

**Unterstützende Features, Tests, Governance oder Playbooks**

- Differentialtests für BC-Provider  
  _Epic: Tests und Reproduzierbarkeit; Modul: `security-crypto-bc`; Bezug: Assurance/Test: verhindert Regressionen gegen die zugeordneten Schwachstellen._


## Lesart für Implementierung und Review

- **Direkt abdeckende Feature-Namen** sind die Features, die im Runtime-Verhalten, in der API oder in der Architektur unmittelbar gegen die CWE wirken.
- **Unterstützende Features** sind Tests, Playbooks, Dokumentation, Traceability oder Governance-Regeln. Sie beseitigen keine Runtime-Schwachstelle allein, sind aber für dauerhafte Absicherung und Nachweis wichtig.
- Für Implementierungsprompts eignet sich weiterhin die ursprüngliche Feature-Sicht. Für Security-Reviews, Gap-Analyse und Audit ist diese CWE-zentrierte Sicht besser lesbar.
