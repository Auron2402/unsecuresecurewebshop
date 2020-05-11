import hashlib
import random
import string

from flask_login import UserMixin, login_required, current_user, login_user, logout_user
from passlib.handlers.sha2_crypt import sha256_crypt

from app import app
from controller.forms import CompleteUserForm, LoginForm
from controller.misc import get_cursor
from flask import Blueprint, render_template_string, render_template, redirect, request, url_for, flash

user_manager = Blueprint('user_manager', __name__)


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
    0 = passwort falsch
    1 = nur 1 check geschafft (sql injection)
    2 = passwort richtig
    :param id:
    :param pw:
    :return: 0 || 1 || 2
    """

    if app.config["sql_injection_login"] == "secure":
        if secure__check_pw_secure_id(id, pw):
            return 2
        return 0
    elif app.config["sql_injection_login"] == "insecure":
        return insecure__check_pw_secure_id(id, pw)
    return 0


def insecure__check_pw_secure_id(id, pw):
    """
    Unsicherer md5-byte passwort vergleich aus der DB anhand sicherer ID mit unsicherem Passwort
    Sicherheitsstufe (security) erhöht sich wenn ein passwordcheck geschafft wird und bleibt gleich sich wenn nicht geschafft werden

    security 0 = kein check geschafft --> falsches passwort
    security 1 = nur weiter check geschafft --> sql injection
    security 2 = beide checks geschafft  --> richtiges passwort

    :param id:
    :param pw:
    :return: 0 || 1 || 2
    """
    security = 0
    cursor = get_cursor()
    compare = get_md5_bytes(pw)
    sqlstring = """SELECT insecure_id from user WHERE secure_id = '""" + id + """' AND pw_md5 = '""" + compare + """'"""
    cursor.execute(sqlstring)
    try:
        cursor.fetchall()[0]
    except IndexError as e:
        security = -1
    security = security + 1
    cursor.execute('SELECT insecure_id from user where secure_id = ? AND pw_md5 = ?', [id, compare])
    try:
        cursor.fetchall()[0]
    except IndexError as e:
        security = security - 1
    return security + 1


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


@app.login_manager.user_loader
def load_user(user_id):
    """
    Benötigte Funktion für flask_login
    :param user_id:
    :return: Initialisierter Nutzer
    """
    return User.get_user_instance(user_id)


@user_manager.route('/user/profile', methods=['GET', 'POST'])
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


@user_manager.route('/login', methods=['GET', 'POST'])
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
        if user is None:
            flash("Benutzername existiert nicht!")
            return redirect(url_for("user_manager.login"))
        else:
            passwordstatus = check_pw_secure_id(id=user.secure_id, pw=form.password.data)
            if passwordstatus == 0:
                flash('Name oder Passwort sind falsch.')
                return redirect(url_for('user_manager.login'))
            elif passwordstatus == 1:
                return redirect(url_for('user_manager.diggydiggyhole'))
            elif passwordstatus == 2:
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))
            else:
                flash('Etwas ist verdammt schief gelaufen. Versuchs nochmal?')
                return redirect(url_for('user_manager.login'))
    return render_template('user/login.html', title='Anmelden', form=form)


@user_manager.route('/register', methods=['GET', 'POST'])
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
        if app.config['user_id_handling'] == 'insecure':
            user = User.get_user_instance(insecure_id)
        else:
            user = User.get_user_instance(secure_id)
        login_user(user)
        return redirect(url_for('index'))
    return render_template('user/register.html', title='Registrieren', form=form)


@user_manager.route("/logout")
@login_required
def logout():
    """
    Logout aktuellen Benutzer und redirect nach Index
    :return:
    """
    logout_user()
    return redirect(url_for('index'))


@user_manager.route('/user/profile/password-change', methods=['GET', 'POST'])
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
        return redirect(url_for('user_manager.userprofile'))
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


@user_manager.route('/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig/dig')
def diggydiggyhole():
    return render_template("/ctf/diggydiggyhole.html")