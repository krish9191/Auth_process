from flask import request, jsonify
from model.user import User
from werkzeug.security import generate_password_hash, check_password_hash
from extensions.extensions import db, jwt
from model.token_revoked import RevokedToken
from flask_jwt_extended import create_access_token, create_refresh_token, current_user, get_jwt, get_jwt_identity
from flask_jwt_extended import decode_token
from password_validator import PasswordValidation
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timezone


def add_user(firstname, lastname, username, email, password):
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
    if user_name == '' or User.find_user_by_username(user_name):
        return {'message': 'username is not valid', 'error': 'bad request, 404'}, 400
    else:
        username = user_name.strip()

    email = email
    if User.find_user_by_email(email):
        return {'message': 'email is not valid', 'error': 'bad request, 404'}, 400

    try:
        valid = validate_email(email, allow_smtputf8=False)
        email = valid.email
    except EmailNotValidError as err:
        return str(err)

    password = password

    if not (PasswordValidation.is_check_none_space_length(password) and PasswordValidation.is_check_char(
            password) and PasswordValidation.is_check_special_char(password)):
        return {'error': '400 Bad Request', 'message': 'Enter a valid Password'}, 400

    pwd = password_hashing(password)
    user = User(username=username, password=pwd, email=email, firstname=firstname, lastname=lastname)

    db.session.add(user)
    db.session.commit()
    return {'users': {
        'username': username,
        'password': password,
        'firstname': firstname,
        'lastname': lastname,
        'email': email,
    }
    }


def list_users():  # List Users
    users = User.find_all_user()
    results = []
    for user in users:
        data_user = dict()
        data_user['id'] = user.user_id
        data_user['username'] = user.username
        data_user['password'] = user.password
        data_user['email'] = user.email
        data_user['firstname'] = user.firstname
        data_user['lastname'] = user.lastname
        data_user['role'] = user.role
        data_user['email_status'] = user.email_status
        data_user['email_created_at'] = user.to_str_date()
        results.append(data_user)

    return {'users': results}


def list_user(id):
    user = User.find_user_by_id(id)
    if user is None:
        return {"error": '404 Not Found', 'message': 'please enter a valid id'}, 404
    return user.write_to_dict()


def update_user(id):
    user = User.find_user_by_id(id)
    user_data = {}
    if user is None:
        return {"error": 'Not Found', 'message': 'please enter a valid id'}, 404
    if request.json == {}:
        return {'message': 'enter valid field to update'}, 400

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
    user_data['email'] = user.email
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    return user_data


def update_role(username, role):
    user = User.find_user_by_username(username)
    if not user:
        return {"error": '404 Not Found', 'message': 'please enter a valid username'}, 404
    user.role = role
    db.session.commit()
    return user.write_to_dict()


def delete_user(id):
    user = User.find_user_by_id(id)
    if user is None:
        return {"error": '404 Not Found', 'message': 'please enter a valid id'}, 404
    db.session.delete(user)
    db.session.commit()
    return {'deleted': user.user_id}


def user_login(username, password):
    user = User.find_user_by_username(username)
    if not user:
        return {'error': '404 Not Found', 'message': 'you need to enter valid Username and password'}, 404
    if not password_verify(user.password, password):
        return {'error': '400 Bad Request', 'message': 'you need to enter valid Username and password'}, 400
    access_token, refresh_token = generate_token(user.username, user.role)
    return jsonify(
        username=user.username,
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role
    )


def refresh_access_token():
    jti = get_jwt()['jti']
    if db.session.query(RevokedToken.id).filter_by(refresh_jti=jti).first():
        return {'msg': 'refresh token is expired'}, 403
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
    return User.find_user_by_username(identity)


@jwt.expired_token_loader
def revoked_token_callback(_jwt_header, _jwt_payload):
    return {'error': '403, forbidden', 'message': 'this token has been expired'}, 403


@jwt.token_in_blocklist_loader
def check_if_token_revoked(_jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = db.session.query(RevokedToken.id).filter_by(access_jti=jti).scalar()
    return token is not None


def user_logout():
    refresh_token = request.json.get('refresh_token', None)
    if refresh_token is None:
        return {'require refresh token'}
    data = decode_token(refresh_token)
    refresh_jti = data['jti']
    access_jti = get_jwt()['jti']
    revoked_at = datetime.now(timezone.utc)
    revoked_token = RevokedToken(access_jti=access_jti, refresh_jti=refresh_jti, created_at=revoked_at)
    db.session.add(revoked_token)
    db.session.commit()

    return jsonify(
        access_jti=access_jti,
        refresh_jti=refresh_jti
    )
