from flask import Blueprint

flag_manager = Blueprint('flag_manager', __name__)


@flag_manager.route('/activate_flag/')
def activate_flag(flag):
    pass
