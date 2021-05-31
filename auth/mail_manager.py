import os
from auth.model.user import User
from flask_mail import Message
from extensions.extensions import mail, db
from flask_jwt_extended import create_access_token, decode_token
from datetime import timedelta
from flask import jsonify


def generate_email_token(email):
    user = User.find_user_by_email(email)
    if not user:
        return {'error': 'not valid email, 404'}, 404
    email_verify_token = create_access_token(
        identity=user.user_id, fresh=True, expires_delta=timedelta(hours=1),
        additional_claims={'email': user.email})
    try:
        msg = Message(subject="email verification", sender=os.environ.get('MAIL_USERNAME'),
                      recipients=[os.environ.get('MAIL_RECIPIENTS')])
        msg.body = 'click the link below to verify email'
        msg.html = "<href>" f"{email_verify_token}" "</href>"
        mail.send(msg)
    except Exception:
        print('message:- this are test email address, you can also use genuine email in a sender and recipients')
    finally:
        return email_verify_token


def email_verify(token):
    data = decode_token(token)
    email = data['email']
    user = User.find_user_by_email(email)
    if user:
        user.email_status = True
        db.session.commit()
    else:
        return {'message': 'email not found, 404'}, 404
    return jsonify(
        username=user.username,
        password=user.password,
        firstname=user.firstname,
        lastname=user.lastname,
        email=user.email,
        email_status=user.email_status,
        email_created_at=user.email_created_at
    )
