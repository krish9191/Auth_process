import os
from password_validator import PasswordValidation
from extensions.extensions import db, mail
from auth.model.user import User
from auth.manager import password_verify, password_hashing
from password_generator import generate_password
from flask_mail import Message


def change_password(email, old_password, new_password):
    user = User.find_user_by_email(email)
    if user is None:
        return {"error": '404 Not Found', 'message': 'please enter a valid email'}, 404
    if password_verify(user.password, old_password):
        if (PasswordValidation.is_check_none_space_length(new_password) and PasswordValidation.is_check_char(
                new_password) and PasswordValidation.is_check_special_char(new_password)):
            user.password = password_hashing(new_password)
            db.session.commit()
            return {'changed_password': new_password}
    return {'error': '400 Bad Request', 'message': 'please enter a valid password'}, 400


def forgot_password(email):
    user = User.find_user_by_email(email)
    if not user:
        return {'error': 'Not found, 404', 'message': 'email is not valid'}, 404
    password = generate_password()
    try:
        msg = Message(subject="Reset Password", sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[os.environ.get('MAIL_RECIPIENTS')])
        msg.html = "<body><h1>"f"New password is {password}</h1>""</body>"
        mail.send(msg)

    except Exception:
        print('message:- this are test email address, you can also use genuine email in a sender and recipients')
    finally:
        user.password = password_hashing(password)
        db.session.commit()
        return {'password': password}
