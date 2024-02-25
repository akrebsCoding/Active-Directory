#  Why AD Enumeration 

### AD Enumeration

Sobald wir über diese erste Reihe von AD-Anmeldeinformationen und die Mittel verfügen, um uns damit im Netzwerk zu authentifizieren, eröffnet sich eine ganz neue Welt an Möglichkeiten! Mit authentifiziertem Zugriff können wir mit der Enumeration verschiedener Details zur AD-Einrichtung und -Struktur beginnen, selbst mit sehr niedrig privilegiertem Zugriff.

Während eines Red-Team-Engagements führt dies in der Regel dazu, dass wir irgendeine Form von Privileg-Eskalation oder laterale Bewegung durchführen können, um zusätzlichen Zugriff zu erhalten, bis wir ausreichende Berechtigungen haben, um unsere Ziele zu erreichen. In den meisten Fällen sind Enumeration und Ausnutzung eng miteinander verbunden. Sobald ein Angriffspfad, der durch die Enumerationphase aufgezeigt wurde, ausgenutzt wurde, wird erneut eine Enumeration von dieser neuen privilegierten Position aus durchgeführt, wie im Diagramm unten dargestellt.

![alt text](images/image1.png)

Lernziele
In diesem Netzwerk werden wir verschiedene Methoden behandeln, die zur Enumeration von AD verwendet werden können. Dies ist keineswegs eine vollständige Liste, da verfügbare Methoden in der Regel stark situationsabhängig sind und von dem erlangten Einbruch abhängen. Wir werden jedoch die folgenden Techniken zur Enumeration von AD behandeln:

    - Die AD-Snap-Ins der Microsoft Management Console.
    
    - Die Net-Befehle der Eingabeaufforderung.
    
    - Die AD-RSAT-Cmdlets von PowerShell.
    
    - Bloodhound.



# Credential Injection 

Bevor wir uns mit AD-Objekten und Enumeration beschäftigen, sollten wir zunächst über Methoden zur Anmeldedateninjektion sprechen. Wie du im Breaching AD-Netzwerk gesehen haben wirst, werden Anmeldedaten oft gefunden, ohne dass ein mit der Domäne verbundener Computer kompromittiert wurde. Bestimmte Enumerationstechniken erfordern möglicherweise eine bestimmte Konfiguration, um zu funktionieren.

Du kannst mit einer Kali-Maschine unglaublich weit kommen, indem du AD-Enumeration durchführst. Wenn du jedoch wirklich umfassende Enumeration und sogar Ausnutzung betreiben möchtest, musst du deinen Gegner verstehen und nachahmen können. Daher benötigst du eine Windows-Maschine. Dadurch können wir mehrere integrierte Methoden verwenden, um unsere Enumeration und Exploits zu inszenieren. In diesem Netzwerk werden wir eines dieser integrierten Tools erkunden, das als "runas.exe" bezeichnet wird.

### Runas Explained

Hast du schon einmal AD-Anmeldeinformationen gefunden, aber keinen Ort, um dich damit anzumelden? Runas könnte die Antwort sein, nach der du gesucht hast!

Bei Sicherheitsbewertungen hast du oft Netzwerkzugriff und hast gerade AD-Anmeldeinformationen entdeckt, hast aber keine Möglichkeit oder Berechtigungen, eine neue domänengebundene Maschine zu erstellen. Daher benötigen wir die Möglichkeit, diese Anmeldeinformationen auf einer von uns kontrollierten Windows-Maschine zu verwenden.

Wenn wir die AD-Anmeldeinformationen im Format "Benutzername:Passwort" haben, können wir Runas, ein legitimes Windows-Binary, verwenden, um die Anmeldeinformationen in den Speicher einzuspeisen. Der übliche Runas-Befehl würde ungefähr so aussehen:

>runas.exe /netonly /user:<domain>\<username> cmd.exe

Lassen Sie uns die Parameter genauer betrachten:

    - /netonly: Da wir nicht in der Domäne eingebunden sind, möchten wir die Anmeldeinformationen für die Netzwerkauthentifizierung laden, aber nicht gegen einen Domänencontroller authentifizieren. Daher werden Befehle, die lokal auf dem Computer ausgeführt werden, im Kontext Ihres Standard-Windows-Kontos ausgeführt, aber alle Netzwerkverbindungen erfolgen unter Verwendung des hier angegebenen Kontos.

    - /user: Hier geben wir die Details der Domäne und des Benutzernamens an. Es ist immer ratsam, den vollqualifizierten Domänennamen (FQDN) anstelle des NetBIOS-Namens der Domäne zu verwenden, da dies bei der Auflösung hilft.

    - cmd.exe: Dies ist das Programm, das wir ausführen möchten, sobald die Anmeldeinformationen eingefügt sind. Dies kann geändert werden, aber die sicherste Wahl ist cmd.exe, da Sie dann damit alles starten können, wozu Sie berechtigt sind, mit den eingefügten Anmeldeinformationen.

Wenn Sie diesen Befehl ausführen, werden Sie aufgefordert, ein Passwort einzugeben. Beachten Sie, dass wir den /netonly-Parameter hinzugefügt haben, sodass die Anmeldeinformationen nicht direkt von einem Domänencontroller überprüft werden. Es wird also jedes Passwort akzeptiert. Wir müssen dennoch bestätigen, dass die Netzwerkanmeldeinformationen erfolgreich und korrekt geladen werden.

Hinweis: Wenn Sie Ihre eigene Windows-Maschine verwenden, sollten Sie sicherstellen, dass Sie Ihre erste Eingabeaufforderung als Administrator ausführen. Dadurch wird ein Administrator-Token in CMD eingefügt. Wenn Sie Tools ausführen, die lokale Administratorrechte erfordern, von Ihrer durch Runas gestarteten CMD aus, wird das Token bereits verfügbar sein. Dies gewährt Ihnen keine administrativen Rechte im Netzwerk, stellt jedoch sicher, dass alle lokalen Befehle, die Sie ausführen, mit administrativen Berechtigungen ausgeführt werden.


### It's Always DNS

Hinweis: Diese nächsten Schritte müssen Sie nur durchführen, wenn Sie Ihre eigene Windows-Maschine für die Übung verwenden. Es ist jedoch eine gute Kenntnis, zu lernen, wie man sie durchführt, da es bei Red-Team-Übungen hilfreich sein kann.

Nach Eingabe des Passworts wird ein neues Eingabeaufforderungsfenster geöffnet. Jetzt müssen wir immer noch überprüfen, ob unsere Anmeldeinformationen funktionieren. Der sicherste Weg, dies zu tun, besteht darin, SYSVOL aufzulisten. Jedes AD-Konto, unabhängig von den Berechtigungen, kann den Inhalt des SYSVOL-Verzeichnisses lesen.

SYSVOL ist ein Ordner, der auf allen Domänencontrollern existiert. Es handelt sich um einen freigegebenen Ordner, der die Gruppenrichtlinienobjekte (GPOs) und Informationen sowie andere domänenbezogene Skripte speichert. Es ist eine wesentliche Komponente für Active Directory, da es diese GPOs an alle Computer in der Domäne liefert. Domänenbeigetretene Computer können dann diese GPOs lesen und die entsprechenden anwenden, um domänenweite Konfigurationsänderungen von einem zentralen Ort aus vorzunehmen.

Bevor wir SYSVOL auflisten können, müssen wir unsere DNS konfigurieren. Manchmal haben Sie Glück, und die interne DNS wird automatisch über DHCP oder die VPN-Verbindung für Sie konfiguriert, aber nicht immer (wie in diesem TryHackMe-Netzwerk). Es ist gut zu verstehen, wie man es manuell macht. Ihre sicherste Wahl für einen DNS-Server ist normalerweise ein Domänencontroller. Unter Verwendung der IP des Domänencontrollers können wir die folgenden Befehle in einem PowerShell-Fenster ausführen:

```
$dnsip = "<DC IP>"
$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip
```

Natürlich wird 'Ethernet' die Schnittstelle sein, die mit dem Ziel-Netzwerk verbunden ist. Wir können überprüfen, ob DNS funktioniert, indem wir Folgendes ausführen:

>nslookup za.tryhackme.com

Was nun zur DC-IP aufgelöst werden sollte, da dies der Ort ist, an dem der FQDN gehostet wird. Jetzt, da DNS funktioniert, können wir endlich unsere Anmeldeinformationen testen. Wir können den folgenden Befehl verwenden, um eine netzwerkbasierte Auflistung des SYSVOL-Verzeichnisses zu erzwingen:

```
za\gordon.stevens@THMJMP1 C:\Users\gordon.stevens>dir \\za.tryhackme.com\sysvol\   
 Volume in drive \\za.tryhackme.com\sysvol is Windows                              
 Volume Serial Number is 1634-22A9                                                 
                                                                                   
 Directory of \\za.tryhackme.com\sysvol                                            
                                                                                   
02/24/2022  09:57 PM    <DIR>          .                                           
02/24/2022  09:57 PM    <DIR>          ..                                          
02/24/2022  09:57 PM    <JUNCTION>     za.tryhackme.com [C:\Windows\SYSVOL\domain] 
               0 File(s)              0 bytes                                      
               3 Dir(s)  51,590,135,808 bytes free
```


### IP vs Hostnames

Frage: Gibt es einen Unterschied zwischen ***dir \\za.tryhackme.com\SYSVOL*** und ***dir \\DC-IP\SYSVOL*** und warum die große Aufregung um DNS?

Es gibt durchaus einen Unterschied, der sich auf die verwendete Authentifizierungsmethode zurückführen lässt. Wenn wir den Hostnamen angeben, wird zuerst versucht, eine Kerberos-Authentifizierung durchzuführen. Da die Kerberos-Authentifizierung Hostnamen in den Tickets verwendet, können wir, wenn wir stattdessen die IP angeben, den Authentifizierungstyp auf NTLM erzwingen. Obwohl dies auf den ersten Blick für uns gerade keine Rolle spielt, ist es gut, diese geringfügigen Unterschiede zu verstehen, da sie es Ihnen ermöglichen können, während einer Red-Team-Bewertung unauffälliger zu bleiben. In einigen Fällen überwachen Organisationen Overpass- und Pass-the-Hash-Angriffe. Die Erzwingung der NTLM-Authentifizierung ist ein guter Trick, um in solchen Fällen unerkannt zu bleiben.

### Using Injected Credentials

Nun, da wir unsere AD-Anmeldeinformationen in den Speicher injiziert haben, fängt der Spaß an. Mit der Option /netonly werden alle Netzwerkkommunikationen diese eingefügten Anmeldeinformationen für die Authentifizierung verwenden. Dies umfasst alle Netzwerkkommunikationen von Anwendungen, die aus diesem Eingabeaufforderungsfenster ausgeführt werden.

Hier wird es mächtig. Hatten Sie jemals den Fall, dass eine MS SQL-Datenbank die Windows-Authentifizierung verwendet und Sie nicht in der Domäne eingebunden waren? Starten Sie MS SQL Studio aus diesem Eingabeaufforderungsfenster; obwohl es Ihren lokalen Benutzernamen anzeigt, klicken Sie auf Anmelden, und es wird im Hintergrund die AD-Anmeldeinformationen zur Authentifizierung verwenden! Wir können dies sogar verwenden, um uns bei Webanwendungen anzumelden, die die NTLM-Authentifizierung verwenden.

Das werden wir in der nächsten Aufgabe für unsere erste AD-Enumerierungstechnik verwenden.

# Enumeration through Microsoft Management Console

