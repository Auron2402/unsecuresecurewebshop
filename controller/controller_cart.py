import urllib

from flask import Blueprint, render_template, request, json, Flask, current_app
from flask_login import login_required

#from app import app
from controller.controller_flag_manager import get_flag
from controller.misc import get_cursor

app = current_app
cart = Blueprint('cart', __name__)


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


@cart.route('/user/cart')
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
    cartflag= get_flag(2)
    return render_template("user/checkout.html", totalprice=totalprice, scam_noticed=scam_noticed,
                           cart_flag="CTF{das_ver_ist_optional}")


@cart.route('/user/checkout')
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
