from flask import Blueprint, render_template

from app import app
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

