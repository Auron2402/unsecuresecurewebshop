from flask import Blueprint, jsonify, request
from flask_login import current_user

from controller.misc import get_cursor

api = Blueprint('api', __name__)


@api.route('/api/get_message_after')
def get_message_after():
    last_message_id = request.args.get('last_message_id', 0, type=int)
    cursor = get_cursor()
    cursor.execute('SELECT id, text, sender_id FROM tickets WHERE id > ?', [last_message_id])
    result = cursor.fetchall()
    return jsonify(result)


@api.route('/api/send_message')
def send_message():
    message_text = request.args.get('message_text', '', type=str)
    sender_id = current_user.id
    cursor = get_cursor()
    cursor.execute('INSERT INTO tickets (text, sender_id) VALUES (?, ?);', [message_text, sender_id])
    return jsonify(True)
