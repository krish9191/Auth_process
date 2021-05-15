from flask import request, jsonify
from model.user import User
from werkzeug.security import generate_password_hash, check_password_hash
from extensions.extensions import db, jwt, mail
from model.token_revoked import TokenRevoked
from flask_jwt_extended import create_access_token, create_refresh_token, current_user, get_jwt, get_jwt_identity
from flask_jwt_extended import decode_token
from password_validator import PasswordValidation
from email_validator import validate_email, EmailNotValidError
from flask_mail import Message
from datetime import timedelta




def add_user(firstname, lastname, username, email, role, password):
    first_name = firstname
    if first_name == '':
        return {'message': 'firstname is not valid', 'error': 'bad request, 404'}, 400
    else:
        firstname = first_name.strip()

    last_name = lastname
    if last_name == '':
        return {'message': 'lastname is not valid', 'error': 'bad request, 404'}, 400
    else:
        lastname = last_name.strip()

    user_name = username
    if user_name == '' or User.query.filter_by(username=user_name).first():
        return {'message': 'username is not valid', 'error': 'bad request, 404'}, 400
    else:
        username = user_name.strip()

    email = email
    if User.query.filter_by(email=email).first():
        return {'message': 'email is not valid', 'error': 400}, 400

    try:
        valid = validate_email(email, allow_smtputf8=False)
        email = valid.email
    except EmailNotValidError as err:
        return str(err)

    role = role
    if role != 'admin' and role != 'user':
        return {'message': 'role is not valid', 'error': 'bad request, 404'}, 400

    password = password

    if (PasswordValidation.is_check_none_space_length(password) and PasswordValidation.is_check_char(password)
            and PasswordValidation.is_check_special_char(password)):
        pwd = password_hashing(password)
        user = User(username=username, password=pwd, email=email, firstname=firstname, lastname=lastname, role=role)

        db.session.add(user)
        db.session.commit()
        return {'users': {
            'username': username,
            'password': password,
            'firstname': firstname,
            'lastname': lastname,
            'email': email,
            'role': role,
            'email_status': user.email_status
        }
        }
    return {'error': '400 Bad Request', 'message': 'Enter a valid Password'}, 400


def list_users():  # List Users
    users = User.query.all()
    results = []
    for user in users:
        data_user = dict()
        data_user['username'] = user.username
        data_user['password'] = user.password
        data_user['email'] = user.email
        data_user['firstname'] = user.firstname
        data_user['lastname'] = user.lastname
        data_user['role'] = user.role
        data_user['email_status'] = user.email_status

        results.append(data_user)

    return {'users': results}


def list_user(id):
    user = User.query.get(id)
    if user is None:
        return {"error": '404 Not Found', 'message': 'please enter a valid id'}, 404
    user_data = dict()
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['email'] = user.email
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['role'] = user.role
    user_data['email_status'] = user.email_status
    user_data['email_created_at'] = user.email_created_at
    return {'user': user_data}


def update_user(id):
    user = User.query.get(id)
    user_data = {}
    if user is None:
        return {"error": 'Not Found', 'message': 'please enter a valid id'}, 404
    if request.json == {}:
        return {'message': 'enter valid field to update'}, 200

    username = request.json.get('username', None)
    if username is not None:
        user.username = username

    firstname = request.json.get('firstname', None)
    if firstname is not None:
        user.firstname = firstname

    lastname = request.json.get('lastname', None)
    if lastname is not None:
        user.lastname = lastname

    email = request.json.get('email', None)
    if email is not None:
        user.email = email

    db.session.commit()
    user_data['username'] = user.username
    user_data['password'] = user.password
    user_data['email'] = user.email
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['role'] = user.role
    user_data['email_status'] = user.email_status
    return user_data


def delete_user(id):
    user = User.query.get(id)
    if user is None:
        return {"error": '404 Not Found', 'message': 'please enter a valid id'}, 404
    db.session.delete(user)
    db.session.commit()
    return {'deleted': user.user_id}


def user_login(username, password):
    user = User.query.filter_by(username=username).first()
    if not user:
        return {'error': '400 Bad Request', 'message': 'you need to enter valid Username and password'}, 400
    if password_verify(user.password, password):
        access_token, refresh_token = generate_token(user.username, user.role)
        return jsonify(
            username=user.username,
            access_token=access_token,
            refresh_token=refresh_token,
            role=user.role
        )

    return {'error': '400 Bad Request', 'message': 'you need to enter valid Username and password'}, 400



def refresh_access_token():
    jti = get_jwt()['jti']
    if db.session.query(TokenRevoked.id).filter_by(refresh_jti=jti):
        return {'msg': 'refresh token is expired'}, 404
    identity = get_jwt_identity()
    token = create_access_token(identity=identity, fresh=True)
    return {'token': token}


def generate_token(identity, role):
    access_token = create_access_token(identity=identity, fresh=True, additional_claims={role: True})
    refresh_token = create_refresh_token(identity=identity)
    return access_token, refresh_token


def user_identity():
    return jsonify(
        id=current_user.user_id,
        username=current_user.username,
        password=current_user.password
    )


def password_hashing(pwd):
    password = generate_password_hash(pwd)
    return password


def password_verify(password, pwd):
    return check_password_hash(password, pwd)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(username=identity).first()


@jwt.expired_token_loader
def revoked_token_callback(_jwt_header, _jwt_payload):
    return {'error': '403, forbidden', 'message': 'this token has been expired'}, 403


@jwt.token_in_blocklist_loader
def check_if_token_revoked(_jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = db.session.query(TokenRevoked.id).filter_by(access_jti=jti).scalar()
    return token is not None
