import hashlib
import flask_debugtoolbar
import json
import pylibmc
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

SESSION_TYPE = 'memcached'
sess = Session()
app.config['SESSION_TYPE'] = "filesystem"
sess.init_app(app)
mc = pylibmc.Client(["127.0.0.1"], binary=True, behaviors={"tcp_nodelay": True, "ketama": True})


# app.config['FLASK_ADMIN_SWATCH'] = 'slate'
# admin = Admin(app, name='unsecuresecurewebshop', template_mode='bootstrap3')


# user edit functions
def gen_user(name, passwd):
    chars = string.ascii_letters + string.digits
    size = 16
    salt = ''.join((random.choice(chars)) for x in range(size))
    pw_hash = sha256_crypt.encrypt(passwd + salt)
    pwmd5 = get_md5_bytes(passwd)
    cursor = get_cursor()
    cursor.execute('INSERT INTO user (name, password, salt, secure_id, pw_md5, role) VALUES (?, ?, ?, ?, ?, ?)',
                   [name, pw_hash, salt, salt, pwmd5, 'user'])
    return cursor.lastrowid


def gen_complete_user(name, password, mail, first_name, last_name, adress, role):
    chars = string.ascii_letters + string.digits
    size = 16
    salt = ''.join((random.choice(chars)) for x in range(size))
    pw_hash = sha256_crypt.encrypt(password + salt)
    pwmd5 = get_md5_bytes(password)
    cursor = get_cursor()
    cursor.execute(
        'INSERT INTO user (name, password, salt, secure_id, pw_md5, role, mail, first_name, last_name, adress) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [name, pw_hash, salt, salt, pwmd5, role, mail, first_name, last_name, adress])
    return cursor.lastrowid


def get_md5_bytes(pw):
    pwhash = hashlib.md5()
    pwhash.update(pw.encode('utf-8'))
    compare = pwhash.digest()
    compare = str(compare)
    compare = compare[2:-1]
    return compare


def insecure__get_id_for_name(name):
    cursor = get_cursor()
    cursor.execute('SELECT insecure_id FROM user WHERE name = ?', [name])
    return cursor.fetchall()[0][0]


def secure__get_id_for_name(name):
    cursor = get_cursor()
    cursor.execute('SELECT secure_id FROM user WHERE name like ?', [name])
    try:
        secureid = cursor.fetchall()[0][0]
    except IndexError as e:
        print(e.__str__())
        return -1
    return secureid


def get_secure_id_for_insecure_id(id):
    cursor = get_cursor()
    cursor.execute('SELECT secure_id FROM user WHERE insecure_id = ?', [id])
    result = cursor.fetchall()
    try:
        return result[0][0]
    except IndexError as e:
        print(e.with_traceback())
        return -1


def check_pw_secure_id(id, pw):
    if app.config["sql_injection_login"] == "secure":
        return secure__check_pw_secure_id(id, pw)
    elif app.config["sql_injection_login"] == "insecure":
        return insecure__check_pw_secure_id(id, pw)
    return None


def insecure__check_pw_secure_id(id, pw):
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
    cursor = get_cursor()
    cursor.execute('SELECT password FROM user WHERE secure_id = ?', [id])
    try:
        pw_hash = cursor.fetchall()[0][0]
    except IndexError:
        return False
    return sha256_crypt.verify(pw + id, pw_hash)


# def secure__check_pw_name(name, pw):
#     cursor = get_cursor()
#     cursor.execute('SELECT insecure_id, password FROM user WHERE name = ?', [name])
#     result = cursor.fetchall()
#     try:
#         id = result[0][0]
#         pw_hash = result[0][1]
#     except IndexError:
#         return False
#     return sha256_crypt.verify(pw + id, pw_hash)

class User(UserMixin):
    @classmethod
    def get_user_instance(cls, id):
        cursor = get_cursor()
        cursor.execute('SELECT name, first_name, last_name, adress, mail, role, insecure_id FROM user WHERE secure_id = ?', [id])
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
        return User(id=id, name=name, firstname=firstname, lastname=lastname, adress=adress, mail=mail, role=role, insecure_id=insecure_id)

    def __init__(self, id, name, firstname, lastname, adress, mail, role, insecure_id):
        self.id = id
        self.name = name
        self.first_name = firstname
        self.last_name = lastname
        self.adress = adress
        self.mail = mail
        self.role = role
        self.insecure_id = insecure_id

    def __repr__(self):
        return "%d/%s" % (self.id, self.name)


@login_manager.user_loader
def load_user(user_id):
    return User.get_user_instance(user_id)


# from here server functions
class LoginForm(Form):
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
    form = CompleteUserForm(request.form)
    if request.method == 'POST':
        save_profile(form, current_user.id)
    if app.config["email_template_handling"] == "insecure":
        emailstring = render_template_string("nice email: " + current_user.mail)
    else:
        emailstring = render_template_string("nice email: {{ current_user.mail }}")
    return render_template("user/profile.html", form=form, emailstring=emailstring)


def save_profile(form, id):
    cursor = get_cursor()
    cursor.execute("UPDATE user SET "
                   "name = ?,"
                   "mail = ?,"
                   "first_name = ?,"
                   "last_name = ?,"
                   "adress = ?"
                   "WHERE secure_id = ?",
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
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        id = secure__get_id_for_name(form.username.data)
        user = User.get_user_instance(id)
        if user is None or not check_pw_secure_id(id=id, pw=form.password.data):
            flash('Name oder Passwort sind falsch.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember.data)
        return redirect(url_for('index'))
    return render_template('user/login.html', title='Anmelden', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = CompleteUserForm(request.form)
    if request.method == "POST" and form.validate():
        insecure_id = gen_complete_user(form.username.data, form.password.data, form.mail.data, form.first_name.data, form.last_name.data, form.adress.data, "user")
        secure_id = get_secure_id_for_insecure_id(insecure_id)
        user = User.get_user_instance(secure_id)
        login_user(user)
        return redirect(url_for('index'))
    return render_template('user/register.html', title='Registrieren', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/ctf/admin', methods=['GET', "POST"])
@login_required
def ctf_admin_panel():
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
    cursor = get_admin_cursor()
    cursor.execute('SELECT id FROM main.flag where flag = ?', [flag])
    result = cursor.fetchall()
    if len(result) > 0:
        return jsonify(True)
    return jsonify(False)


@app.route('/ctf/admin/<string:secure_id>/delete')
@login_required
def ctf_admin_delete_user(secure_id):
    cursor = get_cursor()
    cursor.execute('DELETE FROM user WHERE secure_id = ?', [secure_id])
    return redirect(request.referrer)


@app.route('/admin/shopadmin')
@login_required
def admin_flag_panel():
    isadmin = False
    if current_user.role == 'shopadmin':
        isadmin = True
    else:
        isadmin = False
    return render_template('admin/shopadmin.html', isadmin=isadmin, flags=active_flags)


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/')
def hello_world():
    return redirect(url_for("index"))


@app.route('/shop')
def shop():
    return render_template('shop/shop.html')


@app.route('/shop/<string:itemtype>')
def generic_shop(itemtype):
    items = get_item_by_type(itemtype)
    return render_template('shop/generic_shop.html', items=items)


def create_cart_table(dictcart):
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
    dictcart = reformat_cart()
    result = create_cart_table(dictcart)
    return render_template("user/cart.html", items=result)


def reformat_cart():
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
    a = sqlite3.connect('database/shop', isolation_level=None)
    return a.cursor()


def get_admin_cursor():
    a = sqlite3.connect('database/admin', isolation_level=None)
    return a.cursor()


def secure__checkout():
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
    dictcart = reformat_cart()
    result = create_cart_table(dictcart)
    scam_noticed = 0
    totalprice = 0
    for item in result:
        totalprice = item[4]
    return render_template("user/checkout.html", totalprice=totalprice, scam_noticed=scam_noticed, cart_flag=app.config['cart_flag'])


@app.route('/user/checkout')
@login_required
def checkout():
    if app.config["cart_negative_quantity_handling"] == "secure":
        return secure__checkout()
    elif app.config["cart_negative_quantity_handling"] == "insecure":
        return insecure__checkout()
    return None


def get_item_by_type(itemtype):
    if app.config["itemtype_handling"] == "secure":
        return secure__get_item_by_type(itemtype)
    elif app.config["itemtype_handling"] == "insecure":
        return insecure__get_item_by_type(itemtype)
    return None


def secure__get_item_by_type(itemtype):
    cursor = get_cursor()
    cursor.execute("SELECT id, name, filename, price FROM items WHERE type = ?;", [itemtype])
    result = cursor.fetchall()
    return result


def insecure__get_item_by_type(itemtype):
    cursor = get_cursor()
    cursor.execute("SELECT id, name, filename, price FROM items where type = '%s';" % itemtype)
    result = cursor.fetchall()
    return result


def loosen_secret_key():
    app.config['SECRET_KEY'] = 'this_is_a_really_secret_key'
    session['secret_key'] = 'this_is_a_really_secret_key'


def harden_secret_key():
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
    "cart_negative_quantity_handling": "Irgendwie finde ich es unfair das Shops nur Produkte verkaufen. Was wenn ich vielleicht auch ein unglaublich gutes Angebot habe?",
    "sql_injection_login": "Ab sofort speichern wir alle passwörter als md5 hashes ab. Dadurch kann man die passwörter nicht mehr lesen und man kann uns nicht mehr mit sqlinjections hacken, WIN WIN!",
    "email_template_handling": "Wir bauen aktuell ziemlich fancy E-Mail Templates. Deshalb wurde vorübergehend die E-Mail bestätigung deaktiviert. Wir zeigen dir trotzdem die verknüpfte E-Mail an.",
    "secret_key_handling": "Zum glück sind Python Sessions verschlüsselt, so kann man auch Kritische informationen an den User senden und damit weiterarbeiten"
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
    ]
}
active_aufgabenstellung = {}
active_tipps = {}
active_flags = {}


@app.route('/ctf/admin/changemode/<string:mode>')
@login_required
def ctf_admin_change_mode(mode):
    if current_user.role == 'admin':
        toggle_config_variable(mode)
        toggle_shown_tipps(mode)
        toggle_flags(mode)
        toggle_risks(mode)
        return json.jsonify(app.config[mode])


def hide_itemtype_flag():
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 1')
    hideflag = admincursor.fetchall()[0][0]
    cursor = get_cursor()
    cursor.execute('INSERT INTO flag (flag) VALUES (?)', [hideflag])


def remove_itemtype_flag():
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 1')
    hideflag = admincursor.fetchall()[0][0]
    cursor = get_cursor()
    cursor.execute('DELETE FROM flag WHERE flag = ?', [hideflag])


def hide_cart_negative_quantity_flag():
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 2')
    hideflag = admincursor.fetchall()[0][0]
    app.config['cart_flag'] = hideflag


def remove_cart_negative_quantity_flag():
    app.config['cart_flag'] = 'The flag is in another castle'


def hide_sqli_flag():
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 4')
    hideflag = admincursor.fetchall()[0][0]
    active_flags['sqli_flag'] = hideflag


def remove_sqli_flag():
    active_flags.pop('sqli_flag')


def hide_email_template_flag():
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 5')
    hideflag = admincursor.fetchall()[0][0]
    app.config['EMAIL_TEMPLATE_FLAG'] = hideflag


def remove_email_template_flag():
    app.config['EMAIL_TEMPLATE_FLAG'] = 'The flag is in another castle'


def hide_secret_key_flag():
    admincursor = get_admin_cursor()
    admincursor.execute('SELECT flag FROM flag WHERE id = 6')
    hideflag = admincursor.fetchall()[0][0]
    active_flags['secret_key_flag'] = hideflag


def remove_secret_key_flag():
    active_flags.pop('secret_key_flag')


def hide_flag(mode):
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
    if app.config[mode] == "insecure":
        activate_risk(mode)
    elif app.config[mode] == 'secure':
        deactivate_risk(mode)


def toggle_flags(mode):
    if app.config[mode] == "insecure":
        hide_flag(mode)
    elif app.config[mode] == 'secure':
        remove_flag(mode)


def toggle_shown_tipps(mode):
    if app.config[mode] == "insecure":
        active_tipps[mode] = tipps[mode]
        active_aufgabenstellung[mode] = aufgabenstellung[mode]
    elif app.config[mode] == 'secure':
        active_tipps.pop(mode)
        active_aufgabenstellung.pop(mode)


def toggle_config_variable(mode):
    if app.config[mode] == "secure":
        app.config[mode] = "insecure"
    elif app.config[mode] == "insecure":
        app.config[mode] = "secure"


@app.context_processor
def inject_stage_and_region():
    def format_price(amount):
        frac, whole = math.modf(amount / 100)
        number_after = str(frac).split(".")[1]
        number_pre = str(whole).split(".")[0]
        return number_pre + "," + number_after + " €"

    l = "l"
    return {
        "sec_settings": {
            "itemtype_handling": app.config["itemtype_handling"],
            "cart_negative_quantity_handling": app.config["cart_negative_quantity_handling"],
            "sql_injection_login": app.config["sql_injection_login"],
            "email_template_handling": app.config["email_template_handling"],
            "secret_key_handling": app.config['secret_key_handling']
        },
        "tips": active_tipps,
        "format_price": format_price,
        "aufgaben": active_aufgabenstellung
    }
