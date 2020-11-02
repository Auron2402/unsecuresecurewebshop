import asyncio

import pyppeteer
from pyppeteer import errors
import controller.misc


async def check_page(page):
    try:
        # go to page
        await page.setJavaScriptEnabled(True)
        await page.goto('http://127.0.0.1:5000/user/profile/tickets')

        # check if last message is new or old
        div = await page.querySelector('div.last_message_sent_by')
        sender = await page.evaluate('''(element) => element.dataset.user''', div)
        if sender == 'support':
            # do nothing because we sent last message
            pass
        elif sender == 'user':
            # say that you have read all messages
            await page.evaluate('''send_message('Hi ich bin die Support Susi, ich habe deine Nachricht gelesen, werde sie aber einfach ignorieren. Schönen tag noch ;)')''')
    except errors.TimeoutError:
        # catch timeout error
        print('timeouterror')
        page = await setup_browser()
    return page


async def setup_browser():
    # launch chromium
    browser = await pyppeteer.launch()
    page = await browser.newPage()
    # set logged in and flag cookie
    session_cookie = {
        'name': 'session',
        'value': '.eJwljkFqBDEMBP_icw6WZMvSfmYYyy0SAgnM7J5C_h5DLn2oppv6KUdeuN_L43m98FaOj1UeRTlkiLI5SELMm9cQXbTEW-7syyYZTanSCbkw4kySam6sc1h6MKFnD9BE8JnchN05R-z5Kbr7Fuqhoo7OVJ0nC9L3B8oWed24_m3I2gZxX3k8vz_xtZGjjYpMlkocUzVtSQNmqCJOYFVbmlp-_wDGQj-j.X5bNmg.6dZ8UspGGmP_b51oNyugOCvWp-c',
        'domain': '127.0.0.1',
    }
    flag_cookie = {
        'name': 'flag',
        'value': 'CTF{cookie_monster_wants_more_cookies}',
        'domain': '127.0.0.1',
    }
    await page.setCookie(session_cookie, flag_cookie)
    await page.setViewport({'width': 1920, 'height': 1080})
    return page


async def check_page_every_x_sec(timeout):
    page = await setup_browser()
    while True:
        await asyncio.sleep(timeout)
        page = await check_page(page)


async def check_max_message_every_x_sec(timeout):
    while True:
        # check messages
        cursor = controller.misc.get_cursor()
        cursor.execute('SELECT id FROM tickets')
        messages = cursor.fetchall()
        # remove if there are more than 5
        if len(messages) > 5:
            cursor.execute('DELETE FROM tickets WHERE id = ?', [messages[0][0]])
            print('message id deleted: ' + str(messages[0][0]))
        await asyncio.sleep(timeout)


async def main():
    # start event loop
    loop = asyncio.new_event_loop()
    # create xss checker task and start it
    task_1 = asyncio.create_task(check_page_every_x_sec(10))
    # create db cleanup for messages and start it
    task_2 = asyncio.create_task(check_max_message_every_x_sec(1))
    # await so python does not cry that they are not awaited (script will never really reach this point)
    await task_1
    await task_2


if __name__ == '__main__':
    # using asyncio to run multiple scripts parallel in one script
    asyncio.run(main())
