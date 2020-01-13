from flask import Blueprint, render_template
from flask_login import login_required, current_user

from app import app
from controller.controller_flag_manager import get_flag
from controller.misc import get_cursor

shopctrl = Blueprint('shopctrl', __name__)


@shopctrl.route('/shop')
def shop():
    """
    Zeige Shop übersicht
    :return: shop template
    """
    return render_template('shop/shop.html')


@shopctrl.route('/shop/<string:itemtype>')
def generic_shop(itemtype):
    """
    zeige generische shopseite für übergebenen url an
    :param itemtype:
    :return: generic_shop template
    """
    items = get_item_by_type(itemtype)
    return render_template('shop/generic_shop.html', items=items)


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
    cursor.execute("SELECT id, name, filename, price FROM items where type like '" + itemtype + "';")
    result = cursor.fetchall()
    return result


@shopctrl.route('/admin/shopadmin')
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
    flag = get_flag(6)
    return render_template('admin/shopadmin.html', isadmin=isadmin, flags={'admin sitzung': flag})
