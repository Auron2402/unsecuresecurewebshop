from flask import Blueprint, request, render_template, redirect, url_for
from flask_login import login_required, current_user

from controller.controller_user_manager import gen_complete_user
from controller.forms import CompleteUserForm
from controller.misc import get_cursor

admin = Blueprint('admin', __name__)


@admin.route('/ctf/admin', methods=['GET', "POST"])
@login_required
def ctf_admin_panel():
    """
    Falls GET, Zeige Adminpanel für Modi und Nutzerverwaltung
    Falls POST, Erstelle neuen User für gegebene Informationen (Rolle anpassbar, nicht wie bei Register)
    :return: redirect ctf/admin || redirect index
    """
    if current_user.role == 'admin':
        form = CompleteUserForm(request.form)
        if request.method == 'GET':
            data = get_cursor().execute(
                "select insecure_id, name, mail, first_name, last_name, adress, secure_id, role from user").fetchall()
            return render_template('ctf/admin.html', form=form, data=data)
        if request.method == 'POST':
            gen_complete_user(form.username.data, form.password.data, form.mail.data, form.first_name.data,
                              form.last_name.data, form.adress.data, form.role.data)
            return redirect('/ctf/admin')
    else:
        return redirect(url_for('index'))


@admin.route('/ctf/admin/<string:secure_id>/delete')
@login_required
def ctf_admin_delete_user(secure_id):
    """
    Lösche user für gegebener sicheren ID (admin delete)
    :param secure_id:
    :return: redirect referrer
    """
    cursor = get_cursor()
    cursor.execute('DELETE FROM user WHERE secure_id = ?', [secure_id])
    return redirect(request.referrer)
