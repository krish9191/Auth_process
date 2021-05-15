from password_validator import PasswordValidation
from extensions.extensions import db
from model.user import User
from auth.manager import password_verify, password_hashing
from password_generator import password_generator
from flask_mail import Message
from extensions.extensions import mail
from auth.mail_manager import mail_username


def password_manager(old_password, new_password, email):
    user = db.session.query(User.username).filter_by(email=email).first()
    if user is None:
        return {"error": '404 Not Found', 'message': 'please enter a valid email'}, 404
    if password_verify(user.password, old_password):

        if (PasswordValidation.is_check_none_space_length(new_password) and PasswordValidation.is_check_char(
                new_password)
                and PasswordValidation.is_check_special_char(new_password)):
            user.password = password_hashing(new_password)
            db.session.commit()
            return {'password': new_password}

    return {'error': '400 Bad Request', 'message': 'please enter a valid password'}, 400


def password_forgot(email):

    user = db.session.query(User.username).filter_by(email=email).first()
    if not user:
        return {'error': 'Not found, 404', 'message': 'email is not valid'}, 404
    password = password_generator()
    msg = Message(subject="Reset Password", sender=mail_username, recipients=[email])
    msg.html = "<body><h1>"f"New password is {password}</h1>""</body>"
    mail.send(msg)
    user.password = password_hashing(password)
    db.session.commit()
    return {'password': password}
