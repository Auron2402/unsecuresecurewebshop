4# Original Lösungsweg für das CTF
## Bitte Nur lesen falls schon gelöst

### Itemtype handling
In dieser Aufgabe geht es darum den generischen Shop so zu manipulieren, dass er mehr aus der datenbank anzeigt, als er eigentlich soll.

In der URL sieht man das je nach Produktauswahl sich nur das letzte wort ändert (/shop/phone wird zu /shop/tv). 
Wenn man es auf etwas zufälliges ändert, bekommt man keine Fehlermeldung, sondern einfach kein ergebnis. 
Hierdurch könnte man davon ausgehen dass aus der URL ein SQL statement erzeugt wird, welches dann das ergebnis im richtigen Format im Shop ausgibt.

Man muss also nun die Form des SQL statements erraten um diese zu bearbeiten. 
Ein Anfang wäre, davon auszugehen dass es ungefähr so aussieht "SELECT * FROM 'TABLENAME' WHERE type = '{URLPARAMETER}'". 
Um nun weitere Informationen zu erhalten hat man die Möglichkeit einen UNION Select zu machen. 
Union Select braucht aber eine gültige Zieltabelle auf die es ausgeführt werden kann. 
Entweder Über tools wie sqlmap oder durch ausprobieren kann man herausfinden, dass es sich um eine sqlite datenbank handelt. 
Diese speichert alle Tabellennamen in einer tabelle namens sqlite_master ab.
Wenn man ein Tool wie sqlmap verwendet hat kennt man sowieso den aufbau der datenbank schon aber ich gehe jetzt einfach mal vom ausprobieren aus um auch diesen Weg zu beschreiben.
Nun kann man den Parameter in der URL abändern um ein ergebnis zu bekommen. 
Um die Anzahl der Parameter herauszufinden sollte man mit einem recht simplen select anfangen.
Dazu ändert man den Parameter zu "asdf' UNION SELECT 1 from 'sqlite_master" ab.
Hier bekommt man nun einen Fehler, also kann man davon ausgehen das es einen Fehler im UNION SELECT gibt.
Der Tabellenname kann es nicht sein, aber die Parameter kann gar nicht stimmen, da die Itemboxen ja mehr als eine Information beinhalten. 
Durch weiteres ausprobieren kommt man letztendlich auf den funktionierenden string "asdf' UNION SELECT 1, 2, 3, 4 FROM 'sqlite_master".
Man sieht nun ein Produkt mit dem namen 2 und dem Preis 1 (im quelltext würde man die 2 weiteren parameter auch finden aber uns reicht eigentlich sogar einer).
Nun da man den Grundaufbau eines funktionierenden Aufrufs hat kann man dieses nun abändern um Informationen aus der Datenbank zu ziehen.
"asdf' UNION SELECT 1, name, 3, 4 FROM 'sql_master" liefert die Tabellennamen zurück, dort sieht man eine flag tabelle.
"asdf' UNION SELECT 1, flag, 3 4 FROM 'flag" liefert dann die gewünschte flagge zurück.

### Cart negative quantity handling
In dieser Aufgabe geht es darum, einen negativen Gesamtbetrag mit dem Einkaufswagen zu erreichen.
Durch herumspielen mit den Produkten, während man die cookies eingeblendet hat, findet man heraus dass dynamisch in einen "cart" cookie geschrieben wird.
Dieser Cart-cookie ist codiert aber das ist sehr offensichtlich eine URL-Codierung um zeichenverlust zu vermeiden. 
Mit einem beliebigen onlinetool zum codieren/decodieren von urls kann man herausfinden dass das speicherkonstrukt in etwa so aussieht:

[[1, 1][2, 1][3, 1][5, 1][7, 1]]

Wenn man nun die Zahlen willkürlich abändert und den Warenkorb aktualisiert sieht man dass sich bei der ersten Zahl das produkt verändert und bei der zweiten Zahl die Anzahl.
Durch abändern der Quantität des Produkts im Warenkorb auf einen negativen wert, kommt man so insgesamt auf einen negativen Gesamtbetrag.
Wenn man nun mit einem negativen Gesamtbetrag den Checkout aufruft, bekommt man die Flagge.

### SQL injection login
Ohne Tipps und Ohne google ist dies vermutlich die mit abstand schwerste Aufgabe. Mit google und mit den tipps vermutlich die einfachste.

In dieser Aufgabe geht es darum sich Zugang zum Admin Account zu verschaffen. Wenn man die Admin seite aufruft beschwert sich die seite dass man gar nicht "admin" ist. 
Admin ist hier nicht also rolle gedacht sondern als direktes ansprechen, so kann man darauf kommen, dass der admin account auch wirklich admin heißt.

In der Aufgabenstellung wird gesagt, dass der Shopbesitzer der meinung ist dass ein md5 hash vor jeglicher SQL Injection schützt. 
Wenn man das Googled findet man direkt im ersten link einen Ausnahmefall der beschreibt wann es doch dazu kommen kann, das SQL Injection funktioniert.
Hier steht auch schon direkt die Lösung zu der aufgabe mit einem funktionierenden Lösungsstring, aber ich erkläre hier einfach noch mal wie man selbst darauf kommen könnte.

[Blogpost link](http://cvk.posthaven.com/sql-injection-with-raw-md5-hashes)

Beim generieren eines MD5 Hashes, wird entweder die Hexform oder die Byteform (raw) des Strings erzeugt. 
Ohne zusätlich übergebenen Argumente wird aber das ganze immer in Byteform übergeben, was zu dieser Falle führen kann.
Wenn man dies nicht tut, kann es passiert das der hash auch Steuerzeichen für andere sprachen (wie z. B. SQL enthält).
Man muss also nun einen String generieren der nach einen MD5 hash eine SQL Injection erzeugt welche am ende TRUE erzeugt.
Hierfür kann man zufällige strings in md5 hashen und überprüfen ob sie eine sqlinjection beinhalten.
  
Der string sollte also einen string mit einem Hochkomma beenden, dann or oder || beinhalten, dann einen string wieder beginnt und danach einen Ausdruck der TRUE als wert hat anfügen.
Hier zählen glücklicherweiße alle Zahlen über 0 also kann man das ganze auf entweder:

'or'ZAHL>0

oder 

'||'ZAHL>0

reduzieren.

Hier läuft es dann auf einen brute-force hinaus wenn man selbst auf einen lösungsstring kommen möchte. Oder man verwendet einfach das gegooglete ergebnis.
Ich habe es zwar selbst nicht ausprobiert aber laut dem Blogpost braucht es ca 2 Stunden auf einem Dualcore rechner.

Ein möglicher Angriffsstring lautet dann "129581926211651571912466741651878684928".
Dieser würde in Hexform "06da5430449f8f6f23dfc1276f722738" sein aber im raw byte format "?T0D??o#??'or'8.N=?".
Wie man hier sehen kann befindet sich hier "'or'8" innerhalb des Strings wodurch das Endergebnis des SQL aufrufes immer TRUE ergeben wird.

Wenn man nun als Benutzername admin und das oben herausgefundene passwort verwendet, kommt man in den adminaccount des webshops und kann auf die shopadmin seite zugreifen.
Hier steht dann die Flagge.


### Email template handling
Diese aufgabe ist in der "freien Welt" sehr selten aufzufinden. Entweder braucht man eine sehr alte version von php (+ twig) oder flask (+jinja), oder einen sehr fahrlässigen Webentwickler.
Standardmäßig werden alle Templates escaped außer man lässt es explizit zu. Hierfür verwendet man in php mit twig innerhalb der templatevariable raw als parameter (z. B. {{ var|raw }} ) oder in Flask mit jinja2 render_template_string() anstatt render_template().

In der Aufgabenstellung wird erwähnt, dass die E-Mail Bestätigung temporär deaktiviert ist, dafür aber trotzdem die aktive E-Mail Adresse angezeigt wird.
Wenn man nun in den Profileinstellungen seine E-Mail abändert und diese über das E-Mail bestätigen fenster anzeigt, kann man eine Templateinjection hervorrufen.

Als erstes sollte man die E-mail auf "{{ 7 * '7' }}" ändern um herauszufinden ob die Templatesprache Twig oder Jinja2 ist.
Jinja2 hat intern feste Typen und castet nicht, daher würde es 7777777 zurück geben, twig hingegen castet da es mit php keine richtigen typen hat und dibt 49 zurück.
Da man nun weiß das es sich um Jinja2 handelt und Jinja2 hauptsächlich von Flask verwendet wird kann man sich nun versuchen angriffsvektoren zu suchen.
Mit {{ config }} greift man auf die globale config variable von Flask zu und gibt diese aus. 
Innerhalb dieser konfig sieht man direkt in der Letzten zeile die Flagge. 

Rein theoretisch hat man über eine templateinjection eine komplette shell wenn man weiß wie.
Dies wird aber für diese Aufgabe nicht benötigt.

### Secret key handling (+ user_id_handling)
Diese Aufgabe besteht aus zwei ineinander greifende Sicherheitslücken. 
Beide sind nur im zusammenhang mit der anderen ausnutzbar.
Zum einen sollte der Secret Key einer Flask app NIEMALS an einen Nutzer übergeben werden. 
Dieser dient um den session cookie zu signieren und kann daher von einem böswilligen Nutzer für session manipulation verwendet werden.
Zum anderen sollte die userID niemals nur ein integer wert sein über welchen man iterieren kann. 

Falls man die session manipulieren kann aber die userid ein sehr langer zufälliger string ist, ist es quasi unmöglich die admin ID zu erraten.
Falls die userID ein integer ist, man aber die session nicht bearbeiten kann, kann man sich zwar denken was die Admin ID ist aber dies nicht ausnutzen / überprüfen.

In der Aufgabenstellung wird erwähnt, dass der webentwickler der meinung ist, der Flask session cookie sei verschlüsselt.
Das ist tatsächlich ein recht weit verbreiteter irrglaube, da er nur recht kompliziert codiert und signiert ist.
Man kann sich den quellcode von Flask anschauen und überprüfen was mit dem session cookie gemacht wird, oder man lädt sich einfach eins der fertigen scripte aus dem internet welche den Session cookie codieren/decodieren.
In meinem Beispiel verwende ich  den [Flask Session cookie manager](https://github.com/noraj/flask-session-cookie-manager)

Mit den Tipp aus der Aufgabenstellung sollte man sich nun einloggen und den Session Cookie auslesen und decodieren.
Hier der command zum decodieren meines cookies: 

python session_cookie_manager.py decode -c ".eJxNj7FuwzAMRP9FswdSjE0qPyNQ1AkJErSA7QxB0H-vhg4Fbju8h7tPqmPHcUvXc39hSfXe0zWxmTdkMlqZLspRWAOj2wYHeR6qzpHDOBDUmUx6IZTRxDk3gRBcUbKuBOsiUjiCcCkDxNuEFexUqJHT1ouJgbVrsW6rZqQlxbGPen4_8DX3jLXLCGXLvlLIwKBoHLxNVx9uko3dG03uQOw46wPvyZ23-1FnvO7w5_Nd_7VLeh3Y__6qpJ9fbs5P0Q.XA-nkg.5_eGYu1hL_JqHQZgrG22P2PZO78"

Ergebnis:

{"_fresh":true,"_id":"188abe2080510471c917cefd86eae0a2f77a1c2c81cec0d1083d90e9fb3a12b3e30ea7e92750e8d33391cc0e49fe0167a17e1a090b0a06d9838e17d798d8572e","csrf_token":"f5d3fc7182a50c3fef0cb1c16167dfa83281aab0","secret_key":"this_is_a_really_secret_key","user_id":"173"}

Am ende des ganzen sieht man "secret_key":"this_is_a_really_secret_key" und "user_id":"173".
Der Secret Key ermöglicht es einen nun Cookies zu signieren und die UserID kann abgeändert werden.
Man kann davon ausgehen, dass der AdminAccount der erste erstellte account ist, also entweder 1 oder 0.

Das script verspricht ein besseres Ergebnis wenn man beim decodieren auch den secret key mit angibt. Also erweitere ich den oberen befehl um "-s 'this_is_a_really_secret_key'".
Neues Ergebnis:

{u'csrf_token': u'f5d3fc7182a50c3fef0cb1c16167dfa83281aab0', u'_fresh': True, u'user_id': u'173', u'secret_key': u'this_is_a_really_secret_key', u'_id': u'188abe2080510471c917cefd86eae0a2f77a1c2c81cec0d1083d90e9fb3a12b3e30ea7e92750e8d33391cc0e49fe0167a17e1a090b0a06d9838e17d798d8572e'}

Wie man sieht sind nun die Typen mit übergeben. Diese braucht man vermutlich um den Cookie neu zu signieren, daher werden wir mit diesem neuen Ergebnis weiterarbeiten.
Man kann also nun die UserID auf 1 abändern um die Session dieses nutzers zu übernehmen. "_fresh" sollte man auf True lassen, da man sonst sich möglicherweiße neu einloggen muss.
Commando zum signieren: 

python session_cookie_manager.py encode -s 'this_is_a_really_secret_key' -t "{u'csrf_token': u'f5d3fc7182a50c3fef0cb1c16167dfa83281aab0', u'_fresh': True, u'user_id': u'1', u'secret_key': u'this_is_a_really_secret_key', u'_id': u'188abe2080510471c917cefd86eae0a2f77a1c2c81cec0d1083d90e9fb3a12b3e30ea7e92750e8d33391cc0e49fe0167a17e1a090b0a06d9838e17d798d8572e'}"

Ergebnis: 

.eJxNj7GKAzEMRP_F9RaSHa_k_IyR5TEJCXfg3RQh3L-fiysOphveY-YT6pg4buF6zhe2UO89XAOrWkMkpcx0EfbC4hhddxjI4hAx9ujKDqfOpKkXQhktGceWkAgmKFEyQXtKqbA74VIGiPcFC9ioUCOjvRdNCpYuRbtmiQhb8GOOen4_8LX2jNzTcGGNlsnTwCBv7LwvVx-mKSqbNVrcAZ846wPvxZ23-1FXrE7Y8_mu_9otvA7Mv7_h5xfPuk9n.XA-qZg.yxVEKviunXhRBTOGI2K8xpkof6M

Wenn man alles richtig gemacht hat, sollte man nun mit dem Admin Account eingelogged sein und wieder auf die shopadmin seite zugreifen können.
Dort befindet sich dann wieder die Flagge.


