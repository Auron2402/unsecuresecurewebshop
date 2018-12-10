import hashlib
import os
import shutil
import flask_debugtoolbar
import json
import random
import sqlite3
import string
import urllib
import math
from flask import *
from flask_login import LoginManager, logout_user, login_required, login_user, UserMixin, current_user
from flask_session import Session
from flask_wtf import CSRFProtect
from passlib.hash import sha256_crypt
from wtforms import Form, BooleanField, StringField, PasswordField, validators, IntegerField

# from flask_talisman import Talisman
# from flask_admin import Admin

# flask variables
app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'oqpi23z9q82z3qr9823zh9oq82zhroq289zhrrrr29r'
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
toolbar = flask_debugtoolbar.DebugToolbarExtension(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Nur als registrierter Nutzer möglich.'
SELF = "'self'"
INLINE = "'unsafe-inline'"
EVAL = "'unsafe-eval'"
srcs = [
    SELF,
    INLINE,
    '*.localhost',
    '*.jquery.com',
    '*.googleapis.com',
    '*.getmdl.io',
    '*.cloudflare.com',
    '*.gstatic.com',
    '*.w3.org',
]
csp = {
    'default-src': srcs,
    'style-src': srcs,
    'script-src': srcs
}
# talisman = Talisman(app, content_security_policy=csp)
csrf = CSRFProtect()
app.wtf_csrf_secret_key = 'apow389paw3z5ap385awp35zapwoehpcbykls3478tz'
csrf.init_app(app)
handling = ""


# SESSION_TYPE = 'memcached'
# sess = Session()
# app.config['SESSION_TYPE'] = "filesystem"
# sess.init_app(app)

# user edit functions
def gen_user(name, passwd):
    """
    Generiere einen User in der Datenbank nur mit Name und Passwort
    :param name:
    :param passwd:
    :return: id des generierten nutzers
    """
    chars = string.ascii_letters + string.digits
    size = 16
    salt = ''.join((random.choice(chars)) for x in range(size))
    pw_hash = sha256_crypt.encrypt(passwd + salt)
    pwmd5 = get_md5_bytes(passwd)
    cursor = get_cursor()
    cursor.execute('INSERT INTO user (name, password, salt, secure_id, pw_md5, role) VALUES (?, ?, ?, ?, ?, ?)',
                   [name.lower(), pw_hash, salt, salt, pwmd5, 'user'])
    return cursor.lastrowid


def gen_complete_user(name, password, mail, first_name, last_name, adress, role):
    """
    Generiere einen User in der Datenbank mit allen einfügbaren Daten die es gibt
    :param name:
    :param password:
    :param mail:
    :param first_name:
    :param last_name:
    :param adress:
    :param role:
    :return: id des generierten Nutzers
    """
    chars = string.ascii_letters + string.digits
    size = 16
    salt = ''.join((random.choice(chars)) for x in range(size))
    pw_hash = sha256_crypt.encrypt(password + salt)
    pwmd5 = get_md5_bytes(password)
    cursor = get_cursor()
    cursor.execute(
        'INSERT INTO user (name, password, salt, secure_id, pw_md5, role, mail, first_name, last_name, adress) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [name.lower(), pw_hash, salt, salt, pwmd5, role, mail, first_name, last_name, adress])
    return cursor.lastrowid


def get_md5_bytes(pw):
    """
    Hashe das Passwort in md5 und gebe die repräsentierenden Bytes zurück um es anfällig für md5sqlinject anfällig zu machen
    :param pw:
    :return: md5 bytes
    """
    pwhash = hashlib.md5()
    pwhash.update(pw.encode('utf-8'))
    compare = pwhash.digest()
    compare = str(compare)
    compare = compare[2:-1]
    return compare


def insecure__get_id_for_name(name):
    """
    Hole die unsichere Integer ID für gegebenen namen aus db
    :param name:
    :return: insecure_id
    """
    cursor = get_cursor()
    cursor.execute('SELECT insecure_id FROM user WHERE name = ?', [name.lower()])
    try:
        return cursor.fetchall()[0][0]
    except IndexError as e:
        print(e.__str__())
    return -1


def secure__get_id_for_name(name):
    """
    Hole sichere random ID für gegebenen namen aus db
    :param name:
    :return: secure_id
    """
    cursor = get_cursor()
    cursor.execute('SELECT secure_id FROM user WHERE name = ?', [name.lower()])
    try:
        secureid = cursor.fetchall()[0][0]
    except IndexError as e:
        print(e.__str__())
        return -1
    return secureid


def get_secure_id_for_insecure_id(id):
    """
    Hole für gegebene unsichere User-ID die dazu gehörige sichere User-ID aus DB
    :param id:
    :return: secure_id
    """
    cursor = get_cursor()
    cursor.execute('SELECT secure_id FROM user WHERE insecure_id = ?', [id])
    result = cursor.fetchall()
    try:
        return result[0][0]
    except IndexError as e:
        print(e.with_traceback())
        return -1


def check_pw_secure_id(id, pw):
    """
    Verteilungsfunktion für passwortcheck anhand sicherer UserID
    :param id:
    :param pw:
    :return: True || False
    """
    if app.config["sql_injection_login"] == "secure":
        return secure__check_pw_secure_id(id, pw)
    elif app.config["sql_injection_login"] == "insecure":
        return insecure__check_pw_secure_id(id, pw)
    return False


def insecure__check_pw_secure_id(id, pw):
    """
    Unsicherer md5-byte passwort vergleich aus der DB anhand sicherer ID mit unsicherem Passwort
    :param id:
    :param pw:
    :return: True || False
    """
    cursor = get_cursor()
    compare = get_md5_bytes(pw)
    sqlstring = """SELECT insecure_id from user WHERE secure_id = '""" + id + """' AND pw_md5 = '""" + compare + """'"""
    cursor.execute(sqlstring)
    try:
        cursor.fetchall()[0]
    except IndexError as e:
        return False
    return True


def secure__check_pw_secure_id(id, pw):
    """
    Sicherer SHA256 passwort vergleich aus der DB anhand sicherer ID
    :param id:
    :param pw:
    :return: True || False
    """
    cursor = get_cursor()
    cursor.execute('SELECT password, salt FROM user WHERE secure_id = ?', [id])
    result = cursor.fetchall()
    try:
        pw_hash = result[0][0]
        pw_salt = result[0][1]
    except IndexError as e:
        return False
    return sha256_crypt.verify(pw + pw_salt, pw_hash)


class User(UserMixin):
    @classmethod
    def get_user_instance(cls, id):
        """
        Fülle User Konstruktor aus DB auf anhand gegebener unsicherer oder sicherer ID
        :param id:
        :return: Initialisierter Nutzer
        """
        if app.config['user_id_handling'] == 'insecure':
            cursor = get_cursor()
            cursor.execute(
                'SELECT name, first_name, last_name, adress, mail, role, insecure_id, secure_id FROM user WHERE insecure_id = ?',
                [id])
        else:
            cursor = get_cursor()
            cursor.execute(
                'SELECT name, first_name, last_name, adress, mail, role, insecure_id, secure_id FROM user WHERE secure_id = ?',
                [id])
        result = []
        try:
            result = cursor.fetchall()[0]
        except IndexError as e:
            return None
        name = result[0]
        firstname = result[1]
        lastname = result[2]
        adress = result[3]
        mail = result[4]
        role = result[5]
        insecure_id = result[6]
        secure_id = result[7]
        return User(id=id, name=name, firstname=firstname, lastname=lastname, adress=adress, mail=mail, role=role,
                    insecure_id=insecure_id, secure_id=secure_id)

    def __init__(self, id, name, firstname, lastname, adress, mail, role, insecure_id, secure_id):
        """
        Initialisiere Nutzer
        self.id ist entweder die unsichere Integer ID oder die sichere random ID, je nach aktiviertem Modus
        :param id:
        :param name:
        :param firstname:
        :param lastname:
        :param adress:
        :param mail:
        :param role:
        :param insecure_id:
        :param secure_id:
        """
        self.id = id
        self.name = name
        self.first_name = firstname
        self.last_name = lastname
        self.adress = adress
        self.mail = mail
        self.role = role
        self.insecure_id = insecure_id
        self.secure_id = secure_id

    def __repr__(self):
        return "%d/%s" % (self.id, self.name)


@login_manager.user_loader
def load_user(user_id):
    """
    Benötigte Funktion für flask_login
    :param user_id:
    :return: Initialisierter Nutzer
    """
    return User.get_user_instance(user_id)


# AB HIER SERVERFUNKTIONEN
class LoginForm(Form):
    """
    Minimales Login Formular
    """
    username = StringField('Name', [
        validators.DataRequired(),
        validators.Length(min=4, max=25)
    ], id='username')
    password = PasswordField('Passwort', [
        validators.DataRequired(),
        validators.Length(min=8)
    ], id='password')
    remember = BooleanField('Eingelogged bleiben')


class CompleteUserForm(Form):
    """
    Nutzerformular für alle Fälle außer Login
    """
    username = StringField('Name', [
        validators.DataRequired(),
        validators.Length(min=4, max=25)
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8)
    ])
    first_name = StringField("Vorname")
    last_name = StringField("Nachname")
    mail = StringField('E-Mail Adresse')
    adress = StringField('Adresse')
    insecure_id = IntegerField('insecure_id')
    role = StringField('Rolle')


@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def userprofile():
    """
    Falls Post, Speichere Nutzerprofil mit übergebenen Daten,
    Falls Get, Zeige Nutzerprofil des aktuellen Nutzers
    :return: Profil Template
    """
    form = CompleteUserForm(request.form)
    if request.method == 'POST':
        save_profile(form, current_user.id)
    if app.config["email_template_handling"] == "insecure":
        emailstring = render_template_string("nice email: " + current_user.mail)
    else:
        emailstring = render_template_string("nice email: {{ current_user.mail }}")
    return render_template("user/profile.html", form=form, emailstring=emailstring)


def save_profile(form, id):
    """
    Speichere Nutzerprofil in Datenbank ab
    :param form:
    :param id:
    :return: None
    """

    if app.config['user_id_handling'] == 'insecure':
        columname = 'insecure_id'
    else:
        columname = 'secure_id'

    cursor = get_cursor()
    cursor.execute("UPDATE user SET "
                   "name = ?,"
                   "mail = ?,"
                   "first_name = ?,"
                   "last_name = ?,"
                   "adress = ?"
                   f"WHERE {columname} = ?",
                   [
                       form.username.data,
                       form.mail.data,
                       form.first_name.data,
                       form.last_name.data,
                       form.adress.data,
                       id
                   ])


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Falls Eingelogged, Leite auf Index weiter
    Falls GET Ausgelogged, Zeige loginseite
    Falls POST Ausgelogged, Überprüfe Login Daten je nach Modus
    :return: Login Template
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        if app.config['user_id_handling'] == 'insecure':
            id = insecure__get_id_for_name(form.username.data)
        else:  # user_id_handling == secure
            id = secure__get_id_for_name(form.username.data)
        user = User.get_user_instance(id)
        if user is None or not check_pw_secure_id(id=user.secure_id, pw=form.password.data):
            flash('Name oder Passwort sind falsch.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember.data)
        return redirect(url_for('index'))
    return render_template('user/login.html', title='Anmelden', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Falls GET, Zeige Registrierungsseite an
    Falls POST, Erstelle Nutzer für übergebene Informationen aber immer mit der Rolle "USER"
    :return: Register Template
    """
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = CompleteUserForm(request.form)
    if request.method == "POST" and form.validate():
        insecure_id = gen_complete_user(form.username.data, form.password.data, form.mail.data, form.first_name.data,
                                        form.last_name.data, form.adress.data, "user")
        secure_id = get_secure_id_for_insecure_id(insecure_id)
        user = User.get_user_instance(secure_id)
        login_user(user)
        return redirect(url_for('index'))
    return render_template('user/register.html', title='Registrieren', form=form)


@app.route("/logout")
@login_required
def logout():
    """
    Logout aktuellen Benutzer und redirect nach Index
    :return:
    """
    logout_user()
    return redirect(url_for('index'))


@app.route('/ctf/admin', methods=['GET', "POST"])
@login_required
def ctf_admin_panel():
    """
    Falls GET, Zeige Adminpanel für Modi und Nutzerverwaltung
    Falls POST, Erstelle neuen User für gegebene Informationen (Rolle anpassbar, nicht wie bei Register)
    :return: redirect ctf/admin || redirect index
    """
    if current_user.role == 'admin':
        form = CompleteUserForm(request.form)
        if request.method == 'GET':
            data = get_cursor().execute(
                "select insecure_id, name, mail, first_name, last_name, adress, secure_id, role from user").fetchall()
            return render_template('ctf/admin.html', form=form, data=data)
        if request.method == 'POST':
            gen_complete_user(form.username.data, form.password.data, form.mail.data, form.first_name.data,
                              form.last_name.data, form.adress.data, form.role.data)
            return redirect('/ctf/admin')
    else:
        return redirect(url_for('index'))


@app.route('/ctf/flag/<string:flag>')
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


@app.route('/ctf/admin/<string:secure_id>/delete')
@login_required
def ctf_admin_delete_user(secure_id):
    """
    Lösche user für gegebener sicheren ID (admin delete)
    :param secure_id:
    :return: redirect referrer
    """
    cursor = get_cursor()
    cursor.execute('DELETE FROM user WHERE secure_id = ?', [secure_id])
    return redirect(request.referrer)


@app.route('/ctf/reset')
def ctf_reset_server():
    """
    Sete die Datenbank des Servers auf das backup zurück
    :return: redirect index
    """
    wd = os.getcwd()
    shutil.copy(wd + '/database/backup_shop', wd + '/database/shop')
    return redirect(url_for('index'))


@app.route('/admin/shopadmin')
@login_required
def admin_flag_panel():
    """
    Überprüfe ob Nutzer "Shopadmin" rolle besitzt,
    Falls JA, Zeige aktive Flaggen an die Shopadmin rechte benötigen
    Falls NEIN, Zeige keine Flaggen und gebe Fehler als HTML zurück
    :return: shopadmin Template
    """
    isadmin = False
    if current_user.role == 'shopadmin':
        isadmin = True
    else:
        isadmin = False
    return render_template('admin/shopadmin.html', isadmin=isadmin, flags=active_flags)


@app.route('/index')
def index():
    """
    Zeige Landingpage
    :return: index template
    """
    return render_template('index.html')


@app.route('/')
def hello_world():
    """
    Leite auf Landingpage weiter
    :return: redirect index
    """
    return redirect(url_for("index"))


@app.route('/shop')
def shop():
    """
    Zeige Shop übersicht
    :return: shop template
    """
    return render_template('shop/shop.html')


@app.route('/shop/<string:itemtype>')
def generic_shop(itemtype):
    """
    zeige generische shopseite für übergebenen url an
    :param itemtype:
    :return: generic_shop template
    """
    items = get_item_by_type(itemtype)
    return render_template('shop/generic_shop.html', items=items)


def create_cart_table(dictcart):
    """
    Generiere die Einkaufswagentabelle und füge eine "Gesamt" Zeile am ende ein
    :param dictcart:
    :return: cart_array
    """
    cursor = get_cursor()
    result = []
    i = 1
    gesamtpreis = 0
    for key, value in dictcart.items():
        cursor.execute("SELECT name, price FROM items WHERE id = ?", [key])
        row = cursor.fetchall()
        row[0] = list(row[0])
        row[0].insert(0, i)
        row[0].insert(2, value)
        row[0].insert(4, value * row[0][3])
        result.extend(row)
        i = i + 1
        gesamtpreis += row[0][4]
    row = []
    row.insert(0, [])
    row[0].insert(0, i)
    row[0].insert(1, "GESAMT")
    row[0].insert(2, 1)
    row[0].insert(3, gesamtpreis)
    row[0].insert(4, gesamtpreis)
    result.extend(row)
    return result


@app.route('/user/cart')
def show_cart():
    """
    Zeige den einkaufswagen der aktuellen Session an (aus cookie geholt)
    :return: cart template
    """
    dictcart = reformat_cart()
    result = create_cart_table(dictcart)
    return render_template("user/cart.html", items=result)


def reformat_cart():
    """
    Formatiere Cart das in Cookie als String Mitgegeben wurde in ein Dictionary um
    :return: Cart Dictionary
    """
    cartstring = request.cookies.get('cart')
    cartstring = urllib.parse.unquote(cartstring)
    cart = json.loads(cartstring)
    dictcart = {}
    if cart is None:
        return {}
    for item in cart:
        if item[0] not in dictcart:
            dictcart[item[0]] = item[1]
        else:
            dictcart[item[0]] += item[1]

    return dictcart


def get_cursor():
    """
    Hole Datenbankcursor für shopdatenbank
    :return: shop-db cursor
    """
    a = sqlite3.connect('database/shop', isolation_level=None)
    return a.cursor()


def get_admin_cursor():
    """
    Hole Datenbankcursor für admindatenbank
    :return: admin-db cursor
    """
    a = sqlite3.connect('database/admin', isolation_level=None)
    return a.cursor()


def secure__checkout():
    """
    Checkout des verwendeten einkaufswagen MIT überprüfung ob es Gegenstände mit einer Quantität unter 0 gibt
    :return: checkout template
    """
    dictcart = reformat_cart()
    result = create_cart_table(dictcart)
    scam_noticed = 0
    totalprice = 0
    for item in result:
        # check if itemquantity is negative or if coupon is active more than once
        if item[2] < 0 or (item[3] < 0 and item[2] > 1):
            scam_noticed = 1
        # set last price to totalprice
        totalprice = item[4]
    return render_template("user/checkout.html", totalprice=totalprice, scam_noticed=scam_noticed)


def insecure__checkout():
    """
    Checkout des verwendeten einkaufswagen OHNE überprüfung
    :return: checkout Template
    """
    dictcart = reformat_cart()
    result = create_cart_table(dictcart)
    scam_noticed = 0
    totalprice = 0
    for item in result:
        totalprice = item[4]
    return render_template("user/checkout.html", totalprice=totalprice, scam_noticed=scam_noticed,
                           cart_flag=app.config['cart_flag'])


@app.route('/user/checkout')
@login_required
def checkout():
    """
    Verteilungsfunktion für den Checkout
    :return: checkout template
    """
    if app.config["cart_negative_quantity_handling"] == "secure":
        return secure__checkout()
    elif app.config["cart_negative_quantity_handling"] == "insecure":
        return insecure__checkout()
    return None


@app.route('/user/profile/password-change', methods=['GET', 'POST'])
@login_required
def change_pw():
    """
    Falls GET, zeige Passwort Feld zum ändern
    Falls POST, speichere gesendetes Passwort für aktiven account
    :return: redirect userprofile || changepassword template
    """
    form = CompleteUserForm(request.form)
    if request.method == 'POST':
        newpw = form.password.data
        save_pw(newpw, current_user.id)
        return redirect(url_for('userprofile'))
    return render_template('user/change-password.html', form=form)


def save_pw(pw, id):
    """
    Speichere übergebenes Passwort in allen benötigten Formaten in Datenbank ab
    :param pw:
    :param id:
    :return: None
    """
    chars = string.ascii_letters + string.digits
    size = 16
    salt = ''.join((random.choice(chars)) for x in range(size))
    pw_hash = sha256_crypt.encrypt(pw + salt)
    pwmd5 = get_md5_bytes(pw)
    cursor = get_cursor()
    cursor.execute('UPDATE user SET password = ?, salt = ?, pw_md5 = ? WHERE secure_id = ?', [pw_hash, salt, pwmd5, id])


def get_item_by_type(itemtype):
    """
    Verteilungsfunktion um Shopseiten je nach URL und aktiven Modus anzuzeigen
    :param itemtype:
    :return: generic_shop template
    """
    if app.config["itemtype_handling"] == "secure":
        return secure__get_item_by_type(itemtype)
    elif app.config["itemtype_handling"] == "insecure":
        return insecure__get_item_by_type(itemtype)
    return None


def secure__get_item_by_type(itemtype):
    """
    Hole Waren für übergebenen Typen von Datenbank (sicher)
    :param itemtype:
    :return: [i][id, name, filename, price]
    """
    cursor = get_cursor()
    cursor.execute("SELECT id, name, filename, price FROM items WHERE type = ?;", [itemtype])
    result = cursor.fetchall()
    return result


def insecure__get_item_by_type(itemtype):
    """
    Hole Waren für übergebenen Typen von Datenbank (unsicher)
    :param itemtype:
    :return: [i][id, name, filename, price]
    """
    cursor = get_cursor()
    cursor.execute("SELECT id, name, filename, price FROM items where type = '%s';" % itemtype)
    result = cursor.fetchall()
    return result


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


if __name__ == '__main__':
    app.run()

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


@app.context_processor
def inject_stage_and_region():
    """
    APP CONTEXT PROCESSOR: Funktionen und Variablen die an alle Templates mit übergeben werden.
    Hier: Lückensettings, tipps, aufgabenstellungen und format_price funktion
    :return:
    """
    def format_price(amount):
        """
        Funktion um einen Integer ct betrag zu nehmen und diesen als 00,00 € anzuzeigen um Rundungsfehler von kommazahlen zu vermeiden.
        :param amount:
        :return: 543 -> 5,43 €
        """
        frac, whole = math.modf(amount / 100)
        number_after = str(frac).split(".")[1]
        number_pre = str(whole).split(".")[0]
        return number_pre + "," + number_after + " €"

    return {
        "sec_settings": {
            "itemtype_handling": app.config["itemtype_handling"],
            "cart_negative_quantity_handling": app.config["cart_negative_quantity_handling"],
            "sql_injection_login": app.config["sql_injection_login"],
            "email_template_handling": app.config["email_template_handling"],
            "secret_key_handling": app.config['secret_key_handling'],
            "user_id_handling": app.config['user_id_handling']
        },
        "tips": active_tipps,
        "format_price": format_price,
        "aufgaben": active_aufgabenstellung
    }
