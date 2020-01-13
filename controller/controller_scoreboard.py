from flask import Blueprint, render_template
from flask_login import login_required

from controller.misc import get_admin_cursor

scoreboard = Blueprint('scoreboard', __name__)


def get_scoreboard():
    cursor = get_admin_cursor()
    cursor.execute('SELECT id, name, description, status FROM scoreboard')
    return cursor.fetchall()


def get_tips():
    cursor = get_admin_cursor()
    cursor.execute('SELECT id, text, achievement_id, bought FROM tips')
    return cursor.fetchall()


def get_tester_data():
    cursor = get_admin_cursor()
    cursor.execute("SELECT id, points, timestamp FROM tester_stats ORDER BY id DESC LIMIT 1")
    return cursor.fetchone()


@scoreboard.route('/scoreboard')
def render_scoreboard():
    achievements = get_scoreboard()
    helping = get_tips()
    testerdata = get_tester_data()
    points = testerdata[1]
    timestamp = testerdata[2]
    return render_template('scoreboard/scoreboard.html', achievements=achievements, helping=helping, points=points, timestamp=timestamp)
