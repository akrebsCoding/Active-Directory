# Persistence through Credentials

Wenn wir davon reden, unsere Zugänge zu sichern, dann haben wir meist Low sowie High Privilege Accounts bereits im Besitz.
Wir sichern im Prinzip über unseren High Privilege Accounts unseren Zugang zum Netzwerk mit einem Low-Priv Account.

Um dauerhaften Zugang zu sichern, können wir Credentials nutzen. Diese Methode ist aber relativ unsicher, da User ihre Zugangsdaten im Laufe der Zeit ändern können. 
Mit Credentials sind hier neben Username-Passwort auch Passwort Hashes gemeint.

### DC Sync

Große Organisationen verfügen in der Regel über mehrere Domain Controller an unterschiedlichen Orten. Ansonsten würden Authentifizierungen einfach viel zu lange dauern. Wenn ein Unternehmen bspw. 3 Standorte hat, befinden sich an allen Standorten Domain Controller, die das Netzwerk abbilden bzw. replizieren. Dazu läuft auf den DC ein Prozess der KCC Knowledge Consistency Checker heißt und neben der Abbildung der Topologie auch für die Synchronisation der Domain Controller untereinander zuständig ist. Dazu wird das Remote Procedure Calls Protokoll (RPC) genutzt. Was wird bspw. Synchronisiert? Sowas wie Passwortänderungen oder neue Objekte in einer Domain.
Das ist auch der Grund, wieso man nach einem Passwordchange einige Minuten warten sollte. Die DC müssen sich erst noch synchronisieren bevor wir uns in andere Standorte des Unternehmens einloggen können.

Aber nicht nur Domain Controller können eine Synchronisation iniitieren, das können auch Benutzer der Domain Admin Gruppe.
Wenn wir Zugangsdaten so eines Benutzers haben, können wir diese Nutzen, um eine DC Sync Attacke zu starten und somit Zugangsdaten zu ernten.

### Not All Credentials Are Created Equal

Bevor wir eine DC Sync Attacke starten, schauen wir uns erstmal an, was für potentielle Creds wir ernten können.
Das erste was wir mit unserem privilegierten Account machen, ist das dumpen anderer privilegierter Zugangsdaten. Dabei müssen wir aber immer im Hinterkopf behalten, dass im Falle einer Entdeckung des Angriffs dies auch die Passwörter sind, die als erstes geändert werden.

Daher ist es vielleicht sinnvoller, Zugangsdaten zu ähnlich privilegierten zu dumpen. Auch mit diesen ist es möglich, unseren Zugang zu sichern, und dabei auch noch dem Blue Team über die Schulter zu sehen. Welche Accounts wären dafür geeignet?

    - Accounts die lokale Admins auf mehreren Maschinen sind. 
    In Unternehmen gibt es auf Computern meistens ein oder zwei Gruppen die zu den lokalen Admins gehören.

    - Accounts die Delegationsberechtigung haben. 
    Damit können wir Golden und Silver Tickets erstellen und Kerberos Delegation Attacken starten.

    - Accounts für privilegierte AD Services.
    Wenn wir Konten privilegierter Dienste wie Exchange, Windows Server Update Services (WSUS) oder System Center Configuration Manager (SCCM) kompromittieren, könnten wir AD-Exploitation nutzen, um wieder privilegierten Fuß zu fassen. 

### DCSyncALL



