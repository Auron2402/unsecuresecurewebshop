from flask import Blueprint, json, redirect, url_for, jsonify
from flask_login import login_required, current_user

from app import app, session
from controller.misc import get_admin_cursor, get_cursor

flag_manager = Blueprint('flag_manager', __name__)


@flag_manager.route('/flag_manager/activate_flag/')
def activate_flag(flag):
    pass


def hide_itemtype_flag():
    """
    Verstecke Flagge in shoptabelle um sie für UNION SELECT sichtbar zu machen
    :return: None
    """
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 1')
    hideflag = admincursor.fetchall()[0][0]
    cursor = get_cursor()
    cursor.execute('INSERT INTO flag (flag) VALUES (?)', [hideflag])


def remove_itemtype_flag():
    """
    Entferne Versteckte Flagge aus shoptabelle
    :return: None
    """
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 1')
    hideflag = admincursor.fetchall()[0][0]
    cursor = get_cursor()
    cursor.execute('DELETE FROM flag WHERE flag = ?', [hideflag])


def hide_cart_negative_quantity_flag():
    """
    Speichere Flag in app.config damit das checkout Template diese auslesen kann
    :return: None
    """
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 2')
    hideflag = admincursor.fetchall()[0][0]
    app.config['cart_flag'] = hideflag


def remove_cart_negative_quantity_flag():
    """
    Entferne Flag aus app.config
    :return: None
    """
    app.config['cart_flag'] = 'The flag is in another castle'


def hide_sqli_flag():
    """
    Speichere Flag in active_flags damit das shopadmin panel diese auslesen kann
    :return: None
    """
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 4')
    hideflag = admincursor.fetchall()[0][0]
    active_flags['sqli_flag'] = hideflag


def remove_sqli_flag():
    """
    Entferne die Flagge aus active_flags
    :return: None
    """
    active_flags.pop('sqli_flag')


def hide_email_template_flag():
    """
    Verstecke Flagge in app.config damit emailtemplate mit {{ config }} darauf zugreifen kann
    :return: None
    """
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 5')
    hideflag = admincursor.fetchall()[0][0]
    app.config['EMAIL_TEMPLATE_FLAG'] = hideflag


def remove_email_template_flag():
    """
    Entferne Flagge aus app.config
    :return: None
    """
    app.config['EMAIL_TEMPLATE_FLAG'] = 'The flag is in another castle'


def hide_secret_key_flag():
    """
    Verstecke flagge in active_flags damit admin über shopadmin darauf zugreifen kann
    :return: None
    """
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 6')
    hideflag = admincursor.fetchall()[0][0]
    active_flags['secret_key_flag'] = hideflag


def remove_secret_key_flag():
    """
    Entferne Flagge aus active_flags
    :return:
    """
    active_flags.pop('secret_key_flag')


def hide_flag(mode):
    """
    Verteilungsfunktion je nach übergebenen Modus um jeweils passende Flagge richtig zu verstecken
    :param mode:
    :return: None
    """
    if mode == "itemtype_handling":
        hide_itemtype_flag()
    elif mode == "cart_negative_quantity_handling":
        hide_cart_negative_quantity_flag()
    elif mode == "user_id_handling":
        pass
    elif mode == "sql_injection_login":
        hide_sqli_flag()
    elif mode == "email_template_handling":
        hide_email_template_flag()
    elif mode == "secret_key_handling":
        hide_secret_key_flag()
    else:
        print("DAFQ? Hide_flag_else sollte niemals passieren")


def remove_flag(mode):
    """
    Verteilungsfunktion je nach übergebenen Modus um jeweilg passende Flagge wieder zu entfernen
    :param mode:
    :return: None
    """
    if mode == "itemtype_handling":
        remove_itemtype_flag()
    elif mode == "cart_negative_quantity_handling":
        remove_cart_negative_quantity_flag()
    elif mode == "user_id_handling":
        pass
    elif mode == "sql_injection_login":
        remove_sqli_flag()
    elif mode == "email_template_handling":
        remove_email_template_flag()
    elif mode == "secret_key_handling":
        remove_secret_key_flag()
    else:
        print("DAFQ? remove_flag_else sollte niemals passieren")


def activate_risk(mode):
    """
    Verteilungsfunktion um jeweilige Lücke einzufügen, da nur Modus wechseln nicht reicht
    :param mode:
    :return: None
    """
    if mode == "itemtype_handling":
        pass
    elif mode == "cart_negative_quantity_handling":
        pass
    elif mode == "user_id_handling":
        pass
    elif mode == "sql_injection_login":
        pass
    elif mode == "email_template_handling":
        pass
    elif mode == "secret_key_handling":
        loosen_secret_key()
    else:
        print("DAFQ? activate_risk else sollte niemals passieren")


def deactivate_risk(mode):
    """
    Verteilungsfunktion um jeweilige Lücke wieder zu Stopfen, falls diese nicht mehr benötigt wird
    :param mode:
    :return: None
    """
    if mode == "itemtype_handling":
        pass
    elif mode == "cart_negative_quantity_handling":
        pass
    elif mode == "user_id_handling":
        pass
    elif mode == "sql_injection_login":
        pass
    elif mode == "email_template_handling":
        pass
    elif mode == "secret_key_handling":
        harden_secret_key()
    else:
        print("DAFQ? deactivate_risk else sollte niemals passieren")


def toggle_risks(mode):
    """
    Toggle um eine Lücke hinzuzufügen / zu entfernen
    :param mode:
    :return: None
    """
    if app.config[mode] == "insecure":
        activate_risk(mode)
    elif app.config[mode] == 'secure':
        deactivate_risk(mode)


def toggle_flags(mode):
    """
    Toggle um eine Flagge hinzuzufügen / zu entfernen
    :param mode:
    :return: None
    """
    if app.config[mode] == "insecure":
        hide_flag(mode)
    elif app.config[mode] == 'secure':
        remove_flag(mode)


def toggle_shown_tipps(mode):
    """
    Toggle um Tipps anzuzeigen / zu verstecken
    :param mode:
    :return: None
    """
    if app.config[mode] == "insecure":
        active_tipps[mode] = tipps[mode]
        active_aufgabenstellung[mode] = aufgabenstellung[mode]
    elif app.config[mode] == 'secure':
        active_tipps.pop(mode)
        active_aufgabenstellung.pop(mode)


def toggle_config_variable(mode):
    """
    Toggle um die variablen in app.config zu ändern.
    :param mode:
    :return: None
    """
    if app.config[mode] == "secure":
        app.config[mode] = "insecure"
    elif app.config[mode] == "insecure":
        app.config[mode] = "secure"


# secure / insecure variables
app.config["itemtype_handling"] = "secure"
app.config["cart_negative_quantity_handling"] = "secure"
app.config["user_id_handling"] = "secure"
app.config["sql_injection_login"] = "secure"
app.config["email_template_handling"] = "secure"
app.config["secret_key_handling"] = "secure"
aufgabenstellung = {
    "itemtype_handling": "Ich bin schon überrascht wie dynamisch dieser Shop seine Produktkategorie Seiten generiert, ob man das ausnutzen kann um an andere daten zu kommen?",
    "cart_negative_quantity_handling": "Irgendwie finde ich es unfair das Shops nur Produkte verkaufen. Was wenn ich vielleicht auch ein unglaublich gutes Angebot habe? Verkauf dem Shop doch mal seine eigenen Produkte.",
    "sql_injection_login": "Ab sofort speichern wir alle passwörter als md5 hashes ab. Dadurch kann man die passwörter nicht mehr lesen und man kann uns nicht mehr mit sqlinjections hacken, WIN WIN! Oder etwa nicht?",
    "email_template_handling": "Wir bauen aktuell ziemlich fancy E-Mail Templates. Deshalb wurde vorübergehend die E-Mail bestätigung deaktiviert. Wir zeigen dir trotzdem die verknüpfte E-Mail an.",
    "secret_key_handling": "Zum glück sind Python Sessions verschlüsselt, so kann man auch Kritische informationen an den User senden und damit weiterarbeiten ohne dass er es mitbekommt",
    'user_id_handling': ''
}
tipps = {
    "itemtype_handling": [
        "Könnte die URL einen Teil eines SQL statements beinhalten?",
        "Union select soll praktisch sein um auf tabellen außerhalb der eigentlichen zugreifen zu können",
        "man kann sich bei den meisten datenbanken über einen bestimmten select anzeigen lassen welche tabellen es gibt",
        "vielleicht einen union select auf die flag tabelle falls ich nichts am ablauf geändert habe"
    ],
    "cart_negative_quantity_handling": [
        "manche shops speichern ihre carts in einem cookie ab um rechenleistung vom server zu nehmen und seiten schneller zu generieren",
        "kann man diesen cookie etwa auf eine art decoden? das encoding sieht schon sehr simpel aus",
        "vermutlich besteht es aus einer item id und einer anzahl",
        "vielleicht kann man einfach die anzahl negativ setzten um auf einen negativen gesamtpreis zu kommen"
    ],
    "sql_injection_login": [
        "md5 hashing ist zwar besser als nichts, aber sollte man trotzdem nicht wirklich machen",
        "es besteht die chance das man trotz md5 hash eine sqlinjection machen kann",
        "das gesendete password wird md5 gehashed und in byteform mit dem gespeicherten md5 hash innerhalb der datenbank verglichen",
        "es gibt md5 hashes die in byteform eine sqlinjection wie 'or1 repräsentieren",
        "um genau zu sein könnte es in raw 'or'8 beinhalten"
    ],
    "email_template_handling": [
        "die templates befinden sich nicht nur in der email",
        "es ist ein flask webserver",
        "flask verwendet jinja2 als template renderengine",
        "da die emails noch nicht implementiert sind wurde bei der bestätigung nur ein bedürftig implementiertes fenster erstellt"
    ],
    "secret_key_handling": [
        "Flask webserver verwenden einen secret key der niemals öffentlich freigegeben werden sollte",
        "leichtsinnige programmierer speichern informationen in der flask session, kann man diese auslesen?",
        "wenn man einen secret key von flask hat, kann man jederzeit neue cookies generieren die vom server als vertrauenswürdig akzeptiert werden",
        "vielleicht kann man die userId des aktiven users ändern, den cookie richtig signieren und codieren und wieder zurückschicken?"
    ],
    'user_id_handling': [

    ],
}
active_aufgabenstellung = {}
active_tipps = {}
active_flags = {}

"""DIES SIND SETTINGS DAMIT SIE GEFUNDEN KÖNNEN WERDEN"""
app.config['SECRET_KEY'] = 'this_is_a_really_secret_key'
app.config['EMAIL_TEMPLATE_FLAG'] = "CTF{templateinjection_ist_awesome_aber_selten}"


@app.route('/ctf/admin/changemode/<string:mode>')
@login_required
def ctf_admin_change_mode(mode):
    """
    Für gedrückten Button jeweiligen Modus aktivieren / deaktivieren
    :param mode:
    :return: "secure" || "insecure"
    """
    if current_user.role == 'admin':
        toggle_config_variable(mode)
        toggle_shown_tipps(mode)
        toggle_flags(mode)
        toggle_risks(mode)
        return json.jsonify(app.config[mode])


def loosen_secret_key():
    """
    Secret Key auf Lesbar stellen und in Session übergeben
    :return: None
    """
    app.config['SECRET_KEY'] = 'this_is_a_really_secret_key'
    session['secret_key'] = 'this_is_a_really_secret_key'


def harden_secret_key():
    """
    Secret Key auf Zufällig stellen und in Session überschreiben
    :return: None
    """
    app.config['SECRET_KEY'] = 'oqpi23z9q82z3qr9823zh9oq82zhroq289zhrrrr29r'
    session['secret_key'] = 'the secret key is random and secret this time, sorry'


def get_flag(id):
    cursor = get_admin_cursor()
    cursor.execute('SELECT flag FROM main.flag WHERE id = ?', [id])
    return cursor.fetchone()


def toggle_all_risks():
    toggle_risks("itemtype_handling")
    toggle_risks("cart_negative_quantity_handling")
    toggle_risks("user_id_handling")
    toggle_risks("sql_injection_login")
    toggle_risks("email_template_handling")
    toggle_risks("secret_key_handling")


def toggle_all_flags():
    toggle_flags("itemtype_handling")
    toggle_flags("cart_negative_quantity_handling")
    toggle_flags("user_id_handling")
    toggle_flags("sql_injection_login")
    toggle_flags("email_template_handling")
    toggle_flags("secret_key_handling")


def toggle_all_config_variables():
    toggle_config_variable("itemtype_handling")
    toggle_config_variable("cart_negative_quantity_handling")
    toggle_config_variable("user_id_handling")
    toggle_config_variable("sql_injection_login")
    toggle_config_variable("email_template_handling")
    toggle_config_variable("secret_key_handling")


@flag_manager.route("/restart_everything")
def start_everything():
    import datetime
    timestamp = datetime.datetime.now()
    cursor = get_admin_cursor()
    cursor.execute("INSERT INTO tester_stats (points, timestamp) VALUES (?, ?)", [0, timestamp])
    toggle_all_config_variables()
    toggle_all_risks()
    toggle_all_flags()
    return redirect(url_for('index'))


@flag_manager.route('/ctf/flag/<string:flag>')
def check_flag(flag):
    """
    überprüfe gegebene Flagge mit datenbank und antworte mit json (da ajax aufruf)
    :param flag:
    :return: True || False
    """
    cursor = get_admin_cursor()
    cursor.execute('SELECT id FROM main.flag where flag = ?', [flag])
    result = cursor.fetchall()
    if len(result) > 0:
        return jsonify(True)
    return jsonify(False)
