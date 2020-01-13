import flask_debugtoolbar
import math
from flask import *
from flask_login import LoginManager
from flask_wtf import CSRFProtect

app = Flask(__name__)
app.debug = True
app.config['SECRET_KEY'] = 'oqpi23z9q82z3qr9823zh9oq82zhroq289zhrrrr29r'
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
toolbar = flask_debugtoolbar.DebugToolbarExtension(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'user_manager.login'
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


if __name__ == '__main__':
    app.run()


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
        if number_after == '0':
            number_after = '00'
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


from controller.controller_flag_manager import flag_manager, active_tipps, active_aufgabenstellung, active_flags, \
    get_flag

app.register_blueprint(flag_manager)

from controller.controller_user_manager import user_manager

app.register_blueprint(user_manager)

from controller.controller_scoreboard import scoreboard

app.register_blueprint(scoreboard)

from controller.controller_admin import admin

app.register_blueprint(admin)

from controller.controller_cart import cart

app.register_blueprint(cart)

from controller.controller_shop import shopctrl

app.register_blueprint(shopctrl)
