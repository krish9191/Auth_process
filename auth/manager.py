from flask import request, jsonify
from auth.model.user import User
from werkzeug.security import generate_password_hash, check_password_hash
from exception import MyException
from extensions.extensions import db, jwt
from auth.model.token_revoked import RevokedToken
from flask_jwt_extended import create_access_token, create_refresh_token, current_user, get_jwt, get_jwt_identity
from flask_jwt_extended import decode_token
from password_validator import PasswordValidation
from email_validator import validate_email, EmailNotValidError
from datetime import datetime, timezone


def add_user(firstname, lastname, username, email, password):
    """add user into the users table"""

    if firstname == '':
        return {'message': 'firstname is not valid', 'error': 'bad request, 404'}, 400
    else:
        firstname = firstname.strip()

    if lastname == '':
        return {'message': 'lastname is not valid', 'error': 'bad request, 404'}, 400
    else:
        lastname = lastname.strip()

    if username == '':
        return {'message': 'username is not valid', 'error': 'bad request, 404'}, 400
    else:
        username = username.strip()

    try:
        valid = validate_email(email, allow_smtputf8=False)
        email = valid.email
    except EmailNotValidError as err:
        return str(err)

    if not (PasswordValidation.is_check_none_space_length(password) and PasswordValidation.is_check_char(
            password) and PasswordValidation.is_check_special_char(password)):
        return {'error': '400 Bad Request', 'message': 'Enter a valid Password'}, 400

    pwd = password_hashing(password)
    user = User(username=username, password=pwd, email=email, firstname=firstname, lastname=lastname)

    db.session.add(user)
    db.session.commit()
    return {
        'username': username,
        'password': password,
        'firstname': firstname,
        'lastname': lastname,
        'email': email,
    }


def list_users():
    """return list of users"""

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
    """return user by id"""

    user = User.find_user_by_id(id)
    if user is None:
        raise MyException('could not find this id', status_code=404)
    return user.write_to_dict()


def update_user():
    """update specific or collection of field in a row of users table """
    user = User.query.filter(User.user_id == current_user.user_id).one()
    if user is None:
        raise MyException('need user login', status_code=401)

    if request.json == {}:
        raise MyException('update field cannot be empty', status_code=400)

    username = request.json.get('username', None)
    if username is not None:
        user.username = username

    firstname = request.json.get('firstname', None)
    if firstname is not None:
        user.firstname = firstname

    lastname = request.json.get('lastname', None)
    if lastname is not None:
        user.lastname = lastname

    db.session.commit()
    user_data = dict()
    user_data['username'] = user.username
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    return user_data


def update_email(token):
    """ update email verifying it and set status to true"""
    try:
        token_data = decode_token(token)
        email = token_data['email']
        username = token_data['username']
    except Exception:
        raise MyException('please click the link to verify your email', status_code=404)
    user = User.query.filter(User.username == username).first()
    if user is None:
        raise MyException('invalid user', status_code=404)
    user.email = email
    db.session.commit()
    user.email_status = True
    return {"updated_email": email}


def update_role(username, role):
    """update user's role"""

    user = User.find_user_by_username(username)
    if user is None:
        raise MyException('could not find this username', status_code=404)
    user.role = role
    db.session.commit()
    return user.write_to_dict()


def delete_user(id):
    """ delete row in a user table"""

    user = User.find_user_by_id(id)
    if user is None:
        raise MyException('could not find this id', status_code=404)
    db.session.delete(user)
    db.session.commit()
    return {'deleted': user.user_id}


def user_login(username, password):
    """authenticate user and assign access and refresh tokens to that user """

    user = User.find_user_by_username(username)
    if not user:
        raise MyException('could not find this username', status_code=404)
    if not password_verify(user.password, password):
        raise MyException('invalid password', status_code=400)
    if user.email_status is False:
        raise MyException('please verify your email', status_code=401)
    access_token, refresh_token = generate_token(user.username, user.role)
    return jsonify(
        username=user.username,
        access_token=access_token,
        refresh_token=refresh_token,
        role=user.role
    )


def refresh_access_token():
    """ refresh access token by checking refresh token has been revoked or not """

    jti = get_jwt()['jti']
    if db.session.query(RevokedToken.id).filter_by(refresh_jti=jti).first():
        return {'msg': 'refresh token is expired'}, 403
    identity = get_jwt_identity()
    token = create_access_token(identity=identity, fresh=True)
    return {'token': token}


def generate_token(identity, role):
    """create access and refresh token"""

    access_token = create_access_token(identity=identity, fresh=True, additional_claims={role: True})
    refresh_token = create_refresh_token(identity=identity)
    return access_token, refresh_token


def user_identity():
    """ return login user identity"""

    return jsonify(

        firstname=current_user.firstname,
        lastname=current_user.lastname,
        username=current_user.username,
        email=current_user.email,
        role=current_user.role

    )


def password_hashing(pwd):
    """ return password hash"""

    password = generate_password_hash(pwd)
    return password


def password_verify(password, pwd):
    """ return true if string password match password hash else false  """

    return check_password_hash(password, pwd)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    """ callback function to return user identity"""

    identity = jwt_data["sub"]
    return User.find_user_by_username(identity)


@jwt.expired_token_loader
def revoked_token_callback(_jwt_header, _jwt_payload):
    """callback function that gives error message when expired tokens encounter"""

    return {'error': '401, Unauthorized', 'message': 'this token has been expired'}, 401


@jwt.token_in_blocklist_loader
def check_if_token_revoked(_jwt_header, jwt_payload):
    """return true if token has been revoked else false"""

    jti = jwt_payload['jti']
    token = db.session.query(RevokedToken.id).filter_by(access_jti=jti).scalar()
    return token is not None


def user_logout():
    """logout user revoking fresh tokens """

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
        message="successfully revoked tokens",
        access_jti=access_jti,
        refresh_jti=refresh_jti
    )
