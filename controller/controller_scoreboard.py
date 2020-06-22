from flask import Blueprint, render_template, jsonify

from controller.misc import get_admin_cursor

scoreboard = Blueprint('scoreboard', __name__)


def get_scoreboard():
    cursor = get_admin_cursor()
    cursor.execute('SELECT id, name, description, status FROM scoreboard')
    return cursor.fetchall()


def get_tips():
    cursor = get_admin_cursor()
    cursor.execute('SELECT tips.id, scoreboard.name, tips.cost, tips.text, bought '
                   'FROM tips, scoreboard '
                   'WHERE tips.achievement_id = scoreboard.id')
    return cursor.fetchall()


def get_tester_data():
    cursor = get_admin_cursor()
    cursor.execute("SELECT id, points, timestamp FROM tester_stats ORDER BY id DESC LIMIT 1")
    return cursor.fetchone()


def get_resets():
    cursor = get_admin_cursor()
    cursor.execute('SELECT count(*) FROM tester_stats')
    result = cursor.fetchone()
    if result is not None:
        return result[0] - 1
    return "ERROR"


# @scoreboard.route('/scoreboard')
# def render_scoreboard():
#     achievements = get_scoreboard()
#     helping = get_tips()
#     testerdata = get_tester_data()
#     if testerdata is not None:
#         points = testerdata[1]
#         timestamp = testerdata[2]
#     else:
#         points = 0
#         timestamp = None
#     resets = get_resets()
#     return render_template('scoreboard/scoreboard.html', achievements=achievements, helping=helping, points=points,
#                            timestamp=timestamp, resets=resets)
#
#
# @scoreboard.route('/ctf/buy-help/<int:help_id>')
# def buy_help(help_id):
#     # get cost for achievement
#     cursor = get_admin_cursor()
#     cursor.execute('SELECT cost FROM tips WHERE id = ?', [help_id])
#     result = cursor.fetchone()
#     if result is None:
#         return jsonify('Cant fetch Price'), 500
#     price = result[0]
#
#     # get points of player
#     cursor.execute('SELECT points FROM tester_stats ORDER BY id DESC LIMIT 1')
#     result = cursor.fetchone()
#     if result is None:
#         return jsonify('Cant fetch Points'), 500
#     oldpoints = result[0]
#
#     # get current player id
#     cursor.execute('SELECT MAX(id) FROM tester_stats')
#     result = cursor.fetchone()
#     if result is None:
#         return jsonify('Cant fetch PlayerID'), 500
#     player_id = result[0]
#
#     # buy help for points (save the transaction in database)
#     new_points = oldpoints - price
#     cursor.execute('UPDATE tester_stats SET points = ? WHERE id = ?', [new_points, player_id])
#     cursor.execute('UPDATE tips SET bought = true WHERE id = ?', [help_id])
#     return jsonify(True), 200
