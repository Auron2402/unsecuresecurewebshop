from flask import Blueprint, jsonify, request

from controller.misc import get_cursor

api = Blueprint('api', __name__)


@api.route('/api/ajax_test')
def ajax_test():
    a = request.args.get('a', 0, type=int)
    return jsonify(test='good', variable=a)


@api.route('/api/get_message_after')
def get_message_after():
    last_message_id = request.args.get('last_message_id', 0, type=int)
    cursor = get_cursor()
    cursor.execute('SELECT id, text, sender_id FROM tickets WHERE id > ?', [last_message_id])
    result = cursor.fetchall()
    return jsonify(result)