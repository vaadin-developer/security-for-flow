# Angriffsvektoren und adressierende Features – `security-for-flow`

> Zuordnung der Angriffsvektoren zu den Features der Passwort- und Credential-Schicht (v7, Epics A–S).
> Die Spalte „Adressierende Features" nennt die zugehörigen PWH-IDs.

Hinweise zur Lesart: Die meisten Maßnahmen *erschweren* einen Angriff erheblich oder *verhindern* eine bestimmte Ausnutzung, statt absolute Sicherheit zu garantieren; mehrere Vektoren werden erst im Zusammenspiel mehrerer Features abgedeckt. Einige Maßnahmen sind als SPI angelegt und entfalten ihre Wirkung erst durch eine anwendungsseitige Implementierung – etwa die atomaren Updates des `CredentialStore` (abhängig von der Persistenzschicht) oder die Abuse-Erkennung, die in verteilten Deployments einen gemeinsamen Zähler-/Event-Speicher voraussetzt (PWH-N9).

| Kategorie | Angriffsvektor | Kurzbeschreibung | Adressierende Features |
| --- | --- | --- | --- |
| Offline-Hash-Angriffe | Offline-Brute-Force / Wörterbuchangriff | Massenhaftes Durchprobieren von Kandidaten gegen eine gestohlene Hash-Datenbank | PWH-A4, PWH-A5, PWH-A12, PWH-B2, PWH-B3, PWH-B4, PWH-C1, PWH-C8, PWH-D1 |
| Offline-Hash-Angriffe | GPU-/ASIC-/FPGA-beschleunigtes Cracking | Massive Parallelisierung billiger Rechenleistung gegen die KDF | PWH-B2, PWH-B4, PWH-C8 |
| Offline-Hash-Angriffe | Rainbow-Tables / Vorberechnung | Vorberechnete Hash-Tabellen gegen ungesalzene oder global gesalzene Werte | PWH-A3, PWH-A4 |
| Offline-Hash-Angriffe | Verwertung eines reinen DB-Leaks ohne Pepper | Angreifer erbeutet die Hash-Datenbank, aber nicht das separat gehaltene Pepper-Geheimnis | PWH-D1, PWH-D2, PWH-D7, PWH-D9, PWH-D11 |
| Offline-Hash-Angriffe | Veraltete, nicht aufgewertete Parameter | Alte, zu schwach parametrierte Hashes bleiben unverändert und leicht knackbar | PWH-A6, PWH-A7, PWH-C2, PWH-C3, PWH-C6 |
| Format-/Algorithmus-Manipulation | Algorithmus-Downgrade / stilles Fallback | Erzwungenes Zurückfallen auf ein schwächeres Verfahren bei fehlendem Provider | PWH-B7, PWH-A13, PWH-C7 |
| Format-/Algorithmus-Manipulation | Gefälschte oder unbekannte Algorithmuskennung | Manipulierte Kennung im Hash soll ein unsicheres Fallback oder einen Absturz auslösen | PWH-A13, PWH-I4, PWH-B7 |
| Format-/Algorithmus-Manipulation | Format-Confusion / Vorwärts-Inkompatibilität | Fehlerhafte oder zukünftige Umschlagformate werden fehlinterpretiert | PWH-A16, PWH-A14, PWH-I2, PWH-I3 |
| Format-/Algorithmus-Manipulation | Standardisiert geschwächtes Verfahren | Verdacht gegen eine Primitive erfordert Wechsel des Algorithmus, nicht nur der Implementierung | PWH-C7, PWH-J5 |
| Ressourcen-/DoS-Angriffe | Ressourcenerschöpfung durch teure Hashing-Last | Login-Flut erzwingt viele teure KDF-Läufe und erschöpft CPU/Speicher | PWH-H9, PWH-H10, PWH-N2, PWH-N6, PWH-G2 |
| Ressourcen-/DoS-Angriffe | Crafted-Parameter- / „Decompression-Bomb"-Angriff | Manipulierter oder importierter Hash mit extremen Parametern erzwingt Speicher-/Rechenexplosion | PWH-C10, PWH-A14, PWH-I3 |
| Online-Anmeldeangriffe | Online-Brute-Force gegen ein Konto | Wiederholte Anmeldeversuche gegen einen einzelnen Benutzer | PWH-G2, PWH-N2, PWH-N6, PWH-H9 |
| Online-Anmeldeangriffe | Credential Stuffing | Wiederverwendung andernorts geleakter Zugangsdaten in großer Zahl | PWH-F1, PWH-F3, PWH-F6, PWH-N4, PWH-N2 |
| Online-Anmeldeangriffe | Password Spraying | Wenige häufige Passwörter gegen sehr viele Benutzerkonten | PWH-N3, PWH-N2 |
| Enumeration & Seitenkanäle | Benutzer-/Konto-Enumeration (Antwort und Timing) | Rückschluss auf die Existenz eines Kontos aus Fehlermeldung oder Antwortzeit | PWH-A9, PWH-A11, PWH-G4, PWH-D8, PWH-L6, PWH-N7, PWH-I7 |
| Enumeration & Seitenkanäle | Timing-Seitenkanal beim Hash-Vergleich | Laufzeitabhängiger Vergleich verrät korrekte Präfixe des Hashes | PWH-A8 |
| Enumeration & Seitenkanäle | Mandanten-Enumeration / Tenant-Leak | Öffentliche Fehler offenbaren Existenz oder Zuordnung eines Mandanten | PWH-R6, PWH-R5 |
| Passwortqualität | Schwache oder erratbare Passwörter | Triviale oder bereits kompromittierte Passwörter werden akzeptiert | PWH-F1, PWH-F2, PWH-O1, PWH-O2, PWH-O4 |
| Passwortqualität | Kontext-triviales Passwort | Passwort enthält Benutzername, E-Mail, Domain oder Anwendungsnamen | PWH-O1, PWH-O2 |
| Passwortqualität | Passwort-Wiederverwendung bei Wechsel | Erneutes Setzen eines kürzlich verwendeten Passworts | PWH-O5, PWH-O6, PWH-O7 |
| bcrypt-spezifisch | bcrypt-72-Byte-Trunkierung | Zeichen jenseits von 72 Byte werden ignoriert und schwächen lange Passwörter | PWH-E5, PWH-E6, PWH-B3 |
| bcrypt-spezifisch | Password Shucking | Vorgelagerter ungesicherter Hash erlaubt Vorfilterung gegen bcrypt-Werte | PWH-E5, PWH-E6 |
| Reset / Recovery | Reset-Token-Erraten / Brute-Force | Vorhersagbare oder zu kurze Tokens werden durchprobiert | PWH-L2, PWH-L5, PWH-L9, PWH-N5 |
| Reset / Recovery | Reset-Token-Diebstahl aus der Datenbank | Erbeutete Token-Datenbank erlaubt direkte Übernahme | PWH-L3 |
| Reset / Recovery | Reset-Token-Replay / Mehrfachnutzung | Wiederholte oder parallele Nutzung desselben Tokens | PWH-L4, PWH-M4, PWH-L5 |
| Reset / Recovery | Reset-Missbrauch / Mail-Bombing / Recovery-Enumeration | Massenhafte Reset-Anfragen oder Rückschluss auf Konten über den Reset-Flow | PWH-L6, PWH-L9, PWH-L10, PWH-N5 |
| Credential-Lifecycle | Kontoübernahme via Passwortwechsel ohne Re-Authentifikation | Übernommene Sitzung ändert das Passwort ohne erneuten Identitätsnachweis | PWH-K3, PWH-K4 |
| Credential-Lifecycle | Fortbestehende Sitzungen nach Kompromittierung/Wechsel | Alte Sitzungen oder Credentials bleiben nach einem Vorfall gültig | PWH-K5, PWH-K6, PWH-Q5 |
| Persistenz / Nebenläufigkeit | Race Condition / Lost Update (TOCTOU) | Parallele Rehash-, Wechsel- oder Reset-Operationen überschreiben einander inkonsistent | PWH-M2, PWH-M3, PWH-M4, PWH-M5 |
| Persistenz / Nebenläufigkeit | Migrations-Blind-Overwrite | Transparente Migration überschreibt eine zwischenzeitliche Passwortänderung | PWH-M6, PWH-M2 |
| Geheimnis-Exposition | Geheimnis-Leak über Logs, `toString()` oder Heap | Klartextpasswort, Pepper oder Hash-Zwischenwert gelangt in Logs oder Speicherabbilder | PWH-P1, PWH-P3, PWH-P4, PWH-P5, PWH-E2, PWH-P7 |
| Geheimnis-Exposition | Geheimnis-/Token-Leak über Audit oder Fehlermeldungen | Audit-Einträge oder Fehlertexte enthalten Tokens, Schlüssel oder Hashwerte | PWH-G3, PWH-K8, PWH-L8, PWH-R5, PWH-A11 |
| Lieferkette / Krypto-Vertrauen | Kompromittierter oder geschwächter Krypto-Provider oder JDK | Manipulierte Implementierung oder geschwächte Voreinstellung im kryptographischen Pfad | PWH-J1, PWH-J2, PWH-J3, PWH-J6, PWH-J7, PWH-J8 |
| Lieferkette / Krypto-Vertrauen | Schwache oder subvertierte Zufallsquelle | Vorhersagbare Salts, Tokens oder Pepper-Schlüssel durch manipulierten RNG | PWH-J4, PWH-L2, PWH-D9 |
| Betrieb / Konfiguration | Test-/Schwachparameter versehentlich in Produktion | Testmodus, fester Salt oder absichtlich schwache Parameter sind produktiv aktiv | PWH-I8, PWH-I6, PWH-H6, PWH-A12 |
| Betrieb / Konfiguration | Fehlende Notfallreaktion bei Kompromittierung | Kein definierter Reaktionsweg für geleakten Pepper, schwaches Verfahren oder Provider-Vorfall | PWH-Q1, PWH-Q2, PWH-Q3, PWH-Q4, PWH-Q5, PWH-Q6, PWH-Q8 |

## Anmerkung zur Vollständigkeit

Nicht jeder Vektor wird allein durch die Credential-Schicht abgedeckt. Sitzungsverwaltung, Brute-Force-Sperren und Drosselung greifen auf die bereits in der Projekt-Roadmap genannten Bausteine `SessionPolicy`, `LoginAttemptPolicy` und `LogoutService` zurück; die hier genannten Features liefern dafür die Signale und Schnittstellen, nicht die vollständige Implementierung. Der strategische `CredentialType`-Haken (PWH-A15) ist kein Gegenmittel gegen einen Angriff, sondern die Voraussetzung, später stärkere Faktoren wie Passkeys als eigene Credential-Typen zu ergänzen, und ist daher hier nicht als Angriffsvektor geführt.
