import os
from auth.model.user import User
from flask_mail import Message
from exception import MyException
from extensions.extensions import mail, db
from flask_jwt_extended import create_access_token, decode_token, get_jwt
from datetime import timedelta
from flask import jsonify


def generate_email_token(email):
    """return email verify token and send it to the user email address"""

    user = User.find_user_by_email(email)
    if not user:
        raise MyException('could not find this email', status_code=404)
    email_verify_token = create_access_token(
        identity=user.user_id, fresh=True, expires_delta=timedelta(hours=1),
        additional_claims={'email': user.email, 'username': user.username})
    try:
        msg = Message(subject="email verification", sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[email])
        msg.body = 'click the link below to verify email'
        msg.html = "<href>" f"{email_verify_token}" "</href>"
        mail.send(msg)
    except Exception:
        print('message:- this are test email, you can use real email in a sender and recipients')
    finally:
        return email_verify_token


def email_verify(token):
    """ verify user email and update email_status to active """

    try:
        token_data = decode_token(token)
        email = token_data['email']
    except Exception:
        raise MyException('please click the link to verify your email', status_code=404)
    user = User.find_user_by_email(email)
    if not user:
        return {'message': 'invalid email, 404'}, 404
    user.email_status = True
    db.session.commit()
    return jsonify(
        email=user.email,
        email_status=user.email_status,

    )


def generate_update_email_token(email):
    """return email update token and send it to the user email address"""

    user = User.query.filter(User.username == get_jwt()['sub']).first()
    if not user:
        raise MyException('invalid user', status_code=404)
    email_verify_token = create_access_token(
        identity=user.user_id, fresh=True, expires_delta=timedelta(hours=1),
        additional_claims={'email': email, 'username': user.username})
    try:
        msg = Message(subject="email verification", sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[email])
        msg.body = 'click the link below to verify email'
        msg.html = "<href>" f"{email_verify_token}" "</href>"
        mail.send(msg)
    except Exception:
        print('message:- this are test email, you can use real email in a sender and recipients')
    finally:
        return email_verify_token
