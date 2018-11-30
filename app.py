import hashlib

from flask import *
from flask_session import Session
import pylibmc
# from flask_talisman import Talisman
from flask_login import LoginManager, logout_user, login_required, login_user, UserMixin, current_user
# from flask_talisman import Talisman
from flask_wtf import CSRFProtect
from passlib.hash import sha256_crypt
from werkzeug.utils import secure_filename
from wtforms import Form, BooleanField, StringField, PasswordField, validators, IntegerField

import flask_debugtoolbar, pytest, pytest_cov, wtforms_components, json, urllib, string, sqlite3, random

# secure / insecure variables
itemtype_handling = "secure"
cart_negative_quantity_handling = "secure"
user_id_handling = "secure"
sql_injection_login = "secure"
email_template_handling = "secure"

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

SESSION_TYPE = 'memcached'
sess = Session()
app.config['SESSION_TYPE'] = "filesystem"
sess.init_app(app)
mc = pylibmc.Client(["127.0.0.1"], binary=True, behaviors={"tcp_nodelay": True, "ketama": True})


def gen_user(name, passwd):
    chars = string.ascii_letters + string.digits
    size = 16
    salt = ''.join((random.choice(chars)) for x in range(size))
    pw_hash = sha256_crypt.encrypt(passwd + salt)
    cursor = get_cursor()
    cursor.execute('INSERT INTO user (name, password, salt, secure_id) VALUES (?, ?, ?, ?)', [name, pw_hash, salt, salt])
    return cursor.lastrowid


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


# def secure__check_pw_insecure_id(id, pw):
#     cursor = get_cursor()
#     cursor.execute('SELECT password FROM user WHERE insecure_id = ?', [id])
#     try:
#         pw_hash = cursor.fetchall()[0][0]
#     except IndexError:
#         return False
#     return sha256_crypt.verify(pw + id, pw_hash)


def check_pw_secure_id(id, pw):
    if sql_injection_login == "secure":
        return secure__check_pw_secure_id(id, pw)
    elif sql_injection_login == "insecure":
        return insecure__check_pw_secure_id(id, pw)
    return None


def insecure__check_pw_secure_id(id, pw):
    cursor = get_cursor()
    pwhash = hashlib.md5()
    pwhash.update(pw.encode('utf-8'))
    compare = pwhash.digest()
    compare = str(compare)
    compare = compare[2:-1]
    # compare = compare[:-1]
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
        cursor.execute('SELECT name, first_name, last_name, adress, mail FROM user WHERE secure_id = ?', [id])
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
        return User(id=id, name=name, firstname=firstname, lastname=lastname, adress=adress, mail=mail)

    def __init__(self, id, name, firstname, lastname, adress, mail):
        self.id = id
        self.name = name
        self.first_name = firstname
        self.last_name = lastname
        self.adress = adress
        self.mail = mail

    def __repr__(self):
        return "%d/%s" % (self.id, self.name)


@login_manager.user_loader
def load_user(user_id):
    return User.get_user_instance(user_id)


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


@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def userprofile():
    form = CompleteUserForm(request.form)
    if request.method == 'POST':
        save_profile(form)
    if email_template_handling == "insecure":
        emailstring = render_template_string("nice email: " + current_user.mail)
    else:
        emailstring = render_template_string("nice email: {{ current_user.mail }}")
    return render_template("user/profile.html", form=form, emailstring=emailstring)


def save_profile(form):
    cursor = get_cursor()
    cursor.execute("UPDATE user SET "
                   "name = ?,"
                   "mail = ?,"
                   "first_name = ?,"
                   "last_name = ?,"
                   "adress = ?"
                   "WHERE insecure_id = ?",
                   [
                       form.username.data,
                       form.mail.data,
                       form.first_name.data,
                       form.last_name.data,
                       form.adress.data,
                       form.insecure_id.data
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
    return render_template('user/login.html', title='Sign In', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


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
    return render_template("user/checkout.html", totalprice=totalprice, scam_noticed=scam_noticed)


@app.route('/user/checkout')
@login_required
def checkout():
    if cart_negative_quantity_handling == "secure":
        return secure__checkout()
    elif cart_negative_quantity_handling == "insecure":
        return insecure__checkout()
    return None


def get_item_by_type(itemtype):
    if itemtype_handling == "secure":
        return secure__get_item_by_type(itemtype)
    elif itemtype_handling == "insecure":
        return insecure__get_item_by_type(itemtype)
    return None


def secure__get_item_by_type(itemtype):
    cursor = get_cursor()
    cursor.execute("SELECT id, name, filename, price FROM items WHERE type = ?;", [itemtype])
    result = cursor.fetchall()
    return result


def insecure__get_item_by_type(itemtype):
    cursor = get_cursor()
    cursor.execute("SELECT id, name filename, price FROM items where type = '%s';" % itemtype)
    result = cursor.fetchall()
    return result


def loosen_secret_key():
    app.config['SECRET_KEY'] = 'this_is_a_really_secret_key'


if __name__ == '__main__':
    app.run()


"Unicode-objects must be encoded before hashing".encode("utf-8")