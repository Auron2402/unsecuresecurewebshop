import sqlite3
import pyppeteer
import asyncio
from multiprocessing import Process
from functools import wraps

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


def sync_simulate_read_message_for_xss():
    # async read_message in sync umwandeln
    return asyncio.run(async_simulate_read_message_for_xss())





# class message_reader:
#     def __init__(self):
#         self.loop = asyncio.get_event_loop()
#
#     def try_read_message(self):
#         async def run():
#             # headless browser starten und seite aufrufen
#             browser = await pyppeteer.launch()
#             page = await browser.newPage()
#             await page.goto('localhost:5000/user/profile/tickets')
#             await page.screenshot({'path': 'test.png'})
#             await browser.close()
#         return self.loop.run_until_complete(run())



async def async_simulate_read_message_for_xss():
    # headless browser starten und seite aufrufen

    await page.goto('localhost:5000/user/profile/tickets')
    await page.screenshot({'path': 'test.png'})
    await browser.close()
    return 'done'

