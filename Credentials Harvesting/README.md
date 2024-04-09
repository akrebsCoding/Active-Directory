# Introduction

### Welcome to Credentials Harvesting

Hier gehen wir mal durch, wie wir als Red Teamer Credentials erhalten, wiederverwenden oder fälschen werden.

Credential Harvesting bezieht sich auf das besorgen von Credentials wie Login informationen, Account Namen und Passwörter. Es ist eine Technik zum exfiltrieren von Credentials aus ganz unterschiedlichen Orten in einem System wie Clear-Text-Files, Registrys oder Memory Dumps etc.

Legemetierte Credentials zu bekommen hat immer Vorteile wie:

- Zugang zu anderen Systemen (Lateral Movement)
- Es wird schwerer uns zu entdecken
- Wir haben die Möglichkeit zur Erstellung und Pflege von Accounts, die uns helfen unsere Ziele als Red Teamner zu erreichen.

### Lernziele

- Verstehen der Methode zum extrahieren von Credentials auf lokalen Windows Maschinen
- Erlernen wie man Zugang zur Windows Memory bekommt und Clear-Text Passwörter und Authenzifizierungstickets dumpt, lokal als auch remote.
- Einführung in den Windows Credential Manager und wie man Credentials aus diesem extrahiert
- Erlernen von Methoden wie man Credentials für einen Domain Controller extrahiert
- Erkundung des Local Administrator Password Solution (LAPS) Feature
- Einführung in AD Attacken die zur Beschaffung von AD Credentials dienen

# Credentials Harvesting

### Credentials Harvesting

Credentials Harvesting ist ein Begriff für den Zugriff auf Benutzer- und Systemanmeldeinformationen. Dabei handelt es sich um eine Technik zum Suchen oder Stehlen gespeicherter Anmeldeinformationen, einschließlich Netzwerk-Sniffing, bei der ein Angreifer übermittelte Anmeldeinformationen erfasst.

In welchen Formen lassen sich Credentials finden?

- Account Details (usernames und passwords)
- Hashes wie bspw. NTLM Hashes
- Authentication Tickets wie TGT oder TGS
- Alle Informationen die dabei helfen, sich Zugang zu einem System zu beschaffen (private Keys etc.)

Allgemein gesagt gibt es zwei Arten von Credential Harvesting, einmal Extern und einmal Intern. Bei Extern handelt es sich in der Regel um Phishing Attacken die einen Benutzer dazu bringen sollen, seine Zugangsdaten preis zu geben. Beim internen Credential Harvesting gibt es verschiedene Ansätze auf die wir jetzt weiter eingehen.

# Credential Access

### Clear-text files

Angreifer können einen kompromittierten Computer nach Anmeldeinformationen in lokalen oder Remote-Dateisystemen durchsuchen. Klartextdateien können vertrauliche Informationen enthalten, die von einem Benutzer erstellt wurden und Passwörter, private Schlüssel usw. enthalten. Das MITRE ATT&CK-Framework definiert sie als Unsecured Credentials: Credentials In Files [T1552.001](https://attack.mitre.org/techniques/T1552/001/).

Clear-Text Files die interessant sein könnten:

    - Commands history
    - Configuration files (Web App, FTP files, etc.)
    - Other Files related to Windows Applications (Internet Browsers, Email Clients, etc.)
    - Backup files
    - Shared files and folders
    - Registry
    - Source code 








