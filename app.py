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

# secure / unsecure variables
itemtype_handling = "secure"
cart_negative_quantity_handling = "secure"

# flask variables
app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'oqpi23z9q82z3qr9823zh9oq82zhroq289zhrrrr29r'
toolbar = flask_debugtoolbar.DebugToolbarExtension(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Nur als registrierter User möglich.'
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
    cursor.execute('INSERT INTO user (name, password, salt) VALUES (?, ?, ?)', [name, pw_hash, salt])
    return cursor.lastrowid


def insecure__get_id_for_name(name):
    cursor = get_cursor()
    cursor.execute('SELECT insecure_id FROM user WHERE name = ?', [name])
    return cursor.fetchall()[0][0]


def secure__get_id_for_name(name):
    cursor = get_cursor()
    cursor.execute('SELECT secure_id FROM user WHERE name = ?', [name])
    return cursor.fetchall()[0][0]


def scure__check_pw_insecure_id(id, pw):
    cursor = get_cursor()
    cursor.execute('SELECT password FROM user WHERE insecure_id = ?', [id])
    try:
        pw_hash = cursor.fetchall()[0][0]
    except IndexError:
        return False
    return sha256_crypt.verify(pw + id, pw_hash)


def scure__check_pw_secure_id(id, pw):
    cursor = get_cursor()
    cursor.execute('SELECT password FROM user WHERE secure_id = ?', [id])
    try:
        pw_hash = cursor.fetchall()[0][0]
    except IndexError:
        return False
    return sha256_crypt.verify(pw + id, pw_hash)


def scure__check_pw_name(name, pw):
    cursor = get_cursor()
    cursor.execute('SELECT insecure_id, password FROM user WHERE name = ?', [name])
    result = cursor.fetchall()
    try:
        id = result[0][0]
        pw_hash = result[0][1]
    except IndexError:
        return False
    return sha256_crypt.verify(pw + id, pw_hash)


class User(UserMixin):
    @classmethod
    def get_user_instance(cls, id):
        cursor = get_cursor()
        cursor.execute('SELECT name, first_name, last_name, adress, mail FROM user WHERE insecure_id = ?', [id])
        result = cursor.fetchall()[0]
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
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8)
    ])
    remember = BooleanField('Eingelogged bleiben')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        id = secure__get_id_for_name(form.username.data)
        user = User.get_user_instance(id)
        if user is None or not scure__check_pw_secure_id(id=id, pw=form.password.data):
            flash('Name oder Passwort sind falsch.')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', title='Sign In', form=form)


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
def checkout():
    if cart_negative_quantity_handling == "secure":
        return secure__checkout()
    elif cart_negative_quantity_handling == "insecure":
        return insecure__checkout()
    return None


@app.route('/user/profile')
def userprofile():
    cursor = get_cursor()
    cursor.execute("SELECT name, first_name, last_name, mail, adress FROM user where ")


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
