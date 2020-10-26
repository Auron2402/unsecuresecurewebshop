from flask import Blueprint, jsonify, request, current_app
from flask_login import current_user
from functools import wraps
import asyncio
from controller.misc import get_cursor, sync_simulate_read_message_for_xss, async_simulate_read_message_for_xss
from flask_socketio import SocketIO


def async_action(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        return asyncio.run(f(*args, **kwargs))
    return wrapped


api = Blueprint('api', __name__)


@api.route('/api/get_message_after')
def get_message_after():
    last_message_id = request.args.get('last_message_id', 0, type=int)
    cursor = get_cursor()
    cursor.execute('SELECT id, text, sender_id FROM tickets WHERE id > ?', [last_message_id])
    result = cursor.fetchall()
    return jsonify(result)


@api.route('/api/send_message')
# @async_action
def send_message():
    # insert message into DB
    message_text = request.args.get('message_text', '', type=str)
    sender_id = current_user.id
    cursor = get_cursor()
    cursor.execute('INSERT INTO tickets (text, sender_id) VALUES (?, ?);', [message_text, sender_id])

    # invoke message "check" for XSS
    # reader = message_reader()
    # reader.try_read_message()
    done = sync_simulate_read_message_for_xss()
    # await async_simulate_read_message_for_xss()


    # return something so there is no error
    return jsonify(done)
