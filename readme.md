# Totally Secure Webshop

Dieser Webshop beinhaltet (aktuell 5) Sicherheitslücken die je nach Bedarf aktiviert oder deaktiviert werden können.
Ich empfehle immer nur eine Lücke zu öffnen um nicht ausversehen die Aufgabe über eine andere Lücke zu lösen, da zum Beispiel 2 aufgaben damit gelöst werden sich in den Admin Account einzuloggen.

Um den Webserver zu starten folgendes Kommando verwenden:

FLASK_APP=app.py flask run

Danach sollte der Webserver unter http://localhost:5000/ erreichbar sein.

Auf jeder seite sollte unten links ein Button mit der Aufschrift "CTF-Steuerung öffnen" sein. 
Mit diesem Button kann man sich eine Übersicht über das CTF verschaffen. 
Zum einen ist es in diesem Dialog möglich seine Flaggen auf die richtigkeit zu prüfen (auch wenn flaggen eigentlich recht offensichtlich sein sollten), man sieht seine Aufgabenstellung, welche Sicherheitlücken gerade aktiviert oder deaktiviert sind und man kann sich zu den aktuellen Aufgaben Tipps holen.
Außerdem befinden sich dort 2 weitere buttons, einmal der CTF-Admin bereich und zum anderen der "DB Server Reset".
Der CTF-Admin Bereich leitet einen wie zu erwarten in den Admin bereich weiter. Der DB Server Reset überschreibt die aktuelle Datenbank mit einem backup um den Server wieder zum laufen zu bekommen falls man etwas kaputt gemacht hat.

Im CTF Admin bereich befinden sich 2 Untermenüs mit welchen man zum einen die Aufgaben aktivieren und zum anderen die Nutzerdatenbank bearbeiten kann.
Man kann sich theoretisch dort einen neuen Adminnutzer erstellen welcher die Flaggen abfragen kann aber das würde ja den Sinn eines CTF's verfehlen daher kann ich nur darum bitten dort nicht zu schummeln.
(vielleicht werde ich diese funktion auch einfach später deaktivieren)

Die Logindaten für den CTF-Admin bereich sind ctfadmin/YouShallNotHackThisPassword

Falls es in einer Aufgabe darum geht, sich zugang zu einem administrator nutzer zu verschaffen, kann man die Flagge dann im adminbereich des shops (nicht ctf admin bereich) abrufen.
Dieser ist im Aufklappbaren Menü oben links verlinkt.