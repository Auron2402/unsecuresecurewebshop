from wtforms import Form, StringField, validators, PasswordField, BooleanField, IntegerField


class LoginForm(Form):
    """
    Minimales Login Formular
    """
    username = StringField('Name', [
        validators.DataRequired(),
        validators.Length(min=4, max=25)
    ], id='username')
    password = PasswordField('Passwort', [
        validators.DataRequired(),
        validators.Length(min=8)
    ], id='password')
    remember = BooleanField('Eingelogged bleiben')


class CompleteUserForm(Form):
    """
    Nutzerformular für alle Fälle außer Login
    """
    username = StringField('Name', [
        validators.DataRequired(),
        validators.Length(min=4, max=25)
    ])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8)
    ])
    first_name = StringField("Vorname")
    last_name = StringField("Nachname")
    mail = StringField('E-Mail Adresse')
    adress = StringField('Adresse')
    insecure_id = IntegerField('insecure_id')
    role = StringField('Rolle')