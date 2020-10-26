import asyncio

import pyppeteer
import sched, time
from pyppeteer import errors

s = sched.scheduler(time.time, time.sleep)


async def check_page(page):
    try:
        await page.goto('http://127.0.0.1:5000/user/profile/tickets')
        await page.screenshot({'path': 'test.png'})
    except errors.TimeoutError:
        print('timeouterror')
        page = await setup_browser()
    print('sved')
    return page


async def setup_browser():
    browser = await pyppeteer.launch()
    page = await browser.newPage()
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
    return page


async def check_page_every_x_sec(timeout):
    page = await setup_browser()
    while True:
        await asyncio.sleep(timeout)
        page = await check_page(page)


if __name__ == '__main__':
    # eventloop = asyncio.get_event_loop()
    # eventloop.run_until_complete(do_stuff_every_x_seconds(10, check_page))
    asyncio.run(check_page_every_x_sec(5))
