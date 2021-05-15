from model.user import User
from flask_mail import Message
from extensions.extensions import mail, db
from flask_jwt_extended import create_access_token, decode_token
from datetime import timedelta
from dotenv import load_dotenv
import os
from flask import jsonify

load_dotenv('.env')
mail_username = os.environ.get('MAIL_USERNAME')
mail_password = os.environ.get('MAIL_PASSWORD')
mail_recipients = os.environ.get('MAIL_RECIPIENTS')


def email_token(email):
    user = User.query.filter_by(email=email).first()
    if not user:
        return {'error': 'not valid email, 404'}, 404
    email_verify_token = create_access_token(
        identity=user.user_id, fresh=True, expires_delta=timedelta(hours=1),
        additional_claims={'email': user.email})
    msg = Message(subject="email verification", sender=mail_username, recipients=[email])
    msg.body = 'click the link below to verify email'
    msg.html = "<href>" f"{email_verify_token}" "</href>"
    mail.send(msg)
    return email_verify_token


def email_verify(token):
    data = decode_token(token)
    email = data['email']
    user = User.query.filter_by(email=email).first()
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
