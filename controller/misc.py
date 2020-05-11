import sqlite3


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