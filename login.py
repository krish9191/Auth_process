from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from flask_jwt_extended import create_access_token
from flask_jwt_extended import create_refresh_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import get_jwt
from flask_jwt_extended import jwt_required
from flask_jwt_extended import verify_jwt_in_request
from flask_jwt_extended import decode_token
from flask_jwt_extended import current_user
from flask_jwt_extended import JWTManager
from email_validator import validate_email, EmailNotValidError
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from dotenv import load_dotenv
from functools import wraps
from flask_mail import Message, Mail
import os
import string
import secrets

app = Flask(__name__)
api = Api(app)
load_dotenv(".env")
database_password = os.environ.get('PASSWORD')
host = os.environ.get('HOST')
database = os.environ.get('DATABASE')
SECRET_KEY = os.environ.get("TOKEN_KEY")
mail_username = os.environ.get('MAIL_USERNAME')
mail_password = os.environ.get('MAIL_PASSWORD')
mail_recipients = os.environ.get('MAIL_RECIPIENTS')
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://postgres:{database_password}@{host}/{database}"
db = SQLAlchemy(app)
app.config["JWT_SECRET_KEY"] = SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=3)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = mail_username
app.config['MAIL_PASSWORD'] = mail_password
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    email_status = db.Column(db.Boolean, default=False)
    email_created_at = db.Column(db.DateTime(timezone=True))
    role = db.Column(db.String(255), default=None)

    def __init__(self, username, password, firstname, lastname, email, role):
        self.username = username
        self.password = password
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.role = role
        self.email_status = False
        self.email_created_at = datetime.utcnow()


class RevokedToken(db.Model):
    __tablename__ = 'revoke_jwt'
    id = db.Column(db.Integer, primary_key=True)
    access_jti = db.Column(db.String, unique=True, nullable=False)
    refresh_jti = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)


db.create_all()


class UserInfo(Resource):

    def get(self):  # List Users
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

    def post(self):  # user registration
        if request.json is None:
            return {'error': 'bad request', 'message': 'invalid input'}
        if request.json == {}:
            return {'message': 'it is required to enter all the fields', 'error': 'bad request, 404'}, 400

        first_name = request.json.get('firstname')
        if first_name is None or first_name == '':
            return {'message': 'firstname is not valid', 'error': 'bad request, 404'}, 400
        else:
            firstname = first_name.strip()

        last_name = request.json.get('lastname')
        if last_name is None or last_name == '':
            return {'message': 'lastname is not valid', 'error': 'bad request, 404'}, 400
        else:
            lastname = last_name.strip()

        email = request.json.get('email')
        # if email is None or email == '':
        #     return {'message': 'email is not valid', 'error': 400}, 400
        # else:
        try:
            valid = validate_email(email, allow_smtputf8=False)
            email = valid.email
        except EmailNotValidError as err:
            return str(err)

        user_name = request.json.get('username')
        if user_name is None or user_name == '':
            return {'message': 'username is not valid', 'error': 'bad request, 404'}, 400
        else:
            username = user_name.strip()

        role = request.json.get('role')
        if role is not None:
            if role != 'admin' and role != 'user':
                return {'message': 'role is not valid', 'error': 'bad request, 404'}, 400

        password = request.json.get('password')

        if is_check_none_space_length(password) and is_check_char(password) and is_check_special_char(password):
            pwd = password_hashing(password)
            user = User(username=username, password=pwd, email=email, firstname=firstname, lastname=lastname, role=role)

            db.session.add(user)
            db.session.commit()
            return {'users': {
                'username': user_name,
                'password': password,
                'firstname': first_name,
                'lastname': last_name,
                'email': email,
                'role': role,
                'email_status': user.email_status
            }
            }
        return {'error': '400 Bad Request', 'message': 'Enter a valid Password'}, 400


def admin_required(func):  # decorator which checks claims(type of user) in token payload
    @wraps(func)
    def is_check_admin(*args, **kwargs):
        verify_jwt_in_request()
        claim = get_jwt()
        try:
            if claim['is_administrator']:
                return func(*args, **kwargs)
        except KeyError:
            return {"error": '403, forbidden', 'message': 'you are not authorize to perform this operation '}, 403

    return is_check_admin


class UserOperation(Resource):

    @admin_required
    def get(self, id):  # list user by a specified user_id
        user = User.query.get(id)
        if user is None:
            return {"error": '404 Not Found', 'message': 'please enter a valid id'}, 404
        data_user = dict()
        data_user['username'] = user.username
        data_user['password'] = user.password
        data_user['email'] = user.email
        data_user['firstname'] = user.firstname
        data_user['lastname'] = user.lastname
        return {'user': data_user}

    @admin_required
    def delete(self, id):  # delete user using user_id
        user = User.query.get(id)
        if user is None:
            return {"error": '404 Not Found', 'message': 'please enter a valid id'}, 404
        db.session.delete(user)
        db.session.commit()
        return {'deleted': user.user_id}

    @jwt_required(fresh=True)
    def put(self, id):  # update user using user_id, can update single field or multiple field
        user = User.query.get(id)
        if user is None:
            return {"error": 'Not Found', 'message': 'please enter a valid id', 'field': 'id'}, 404

        if request.json == {}:
            return {'error': 'bad request', 'message': 'invalid input'}, 400

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

        user_data = jsonify(
            firstname=user.firstname,
            lastname=user.lastname,
            email=user.email,
            username=user.username,
            password=user.password,
            role=user.role,
            email_status=user.email_status,
            email_created_at=user.email_created_at
        )
        return user_data


class PasswordManager(Resource):  # create new password verifying user email and old password
    @jwt_required(fresh=True)
    def put(self):
        data = request.get_json()
        user = db.session.query(User.username).filter_by(email=data['email']).first()
        if user is None:
            return {"error": '404 Not Found', 'message': 'please enter a valid email or password'}, 404
        old_password = data['old_password']
        if password_verify(user.password, old_password):
            new_password = data['new_password']
            if is_check_none_space_length(new_password) and is_check_char(new_password) and is_check_special_char(
                    new_password):
                user.password = password_hashing(new_password)
                db.session.commit()
                return {'password': data['new_password']}

        return {'error': '400 Bad Request', 'message': 'please enter a valid password'}, 400


class EmailToken(Resource):   # create access token, send to the user in a link to verify the user email
    def post(self):
        email = request.json['email']
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


class EmailVerify(Resource):  # verify email from the payload of token
    def patch(self):
        token = request.json['token']
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


def password_generator():  # generate 8 character password randomly with each upper, lower, digit, special character
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits
    special_char = ['@', '*', '#']
    password = ''.join(
        secrets.choice(upper) + secrets.choice(lower) + secrets.choice(digits) + secrets.choice(special_char)
        for i in range(2))

    return password


class PasswordForgot(Resource):  # create and add new password in the database
    def post(self):
        email = request.json['email']
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


class Login(Resource):  # user authentication, creation of access and refresh token
    def post(self):
        username = request.json['username']
        password = request.json['password']
        user = User.query.filter_by(username=username).first()
        if not user:
            return {'error': '400 Bad Request', 'message': 'you need to enter valid Username and password'}, 400
        if password_verify(user.password, password):
            if user.role == 'admin':
                token = create_access_token(identity=user.email, fresh=True,
                                            additional_claims={'is_administrator': True})
                refresh_token = create_refresh_token(identity=user.email)
                return jsonify(token=token, refresh_token=refresh_token)

            else:
                token = create_access_token(identity=user.email, fresh=True)
                refresh_token = create_refresh_token(identity=user.email)
                return jsonify(token=token, refresh_token=refresh_token)

        return {'error': '400 Bad Request', 'message': 'you need to enter valid Username and password'}, 400


class UserIdentity(Resource):  # give information of current user(logged in user)

    @jwt_required(fresh=True)
    def get(self):
        return jsonify(
            id=current_user.user_id,
            username=current_user.username,
            password=current_user.password

        )


class RefreshAccessToken(Resource):  # refresh access token if refresh token is not expired
    @jwt_required(refresh=True)
    def post(self):
        jti = get_jwt()['jti']
        if db.session.query(RevokedToken.id).filter_by(refresh_jti=jti):
            return {'msg': 'refresh token is expired'}, 404
        identity = get_jwt_identity()
        token = create_access_token(identity=identity, fresh=True)
        return {'token': token}


class Logout(Resource):  # logout user
    @jwt_required()
    def post(self):
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


def password_hashing(pwd):
    password = generate_password_hash(pwd)
    return password


def password_verify(password, pwd):
    return check_password_hash(password, pwd)


def is_check_none_space_length(pwd):
    return pwd is not None and ' ' not in pwd and 8 <= len(pwd) <= 16


def is_check_char(pwd):
    str_func = [str.isalpha, str.islower, str.isupper]
    result = []
    for item in str_func:
        if any(item(char) for char in pwd):
            result.append(True)
        else:
            result.append(False)
    return all(result)


def is_check_special_char(pwd):
    special_char = ['*', '.', '@', '!']
    return any(char for char in pwd if char in special_char)


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(email=identity).first()


@jwt.expired_token_loader
def revoked_token_callback(_jwt_header, _jwt_payload):
    return {'error': '403, forbidden', 'message': 'this token has been expired'}, 403


@jwt.token_in_blocklist_loader
def check_if_token_revoked(_jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    token = db.session.query(RevokedToken.id).filter_by(access_jti=jti).scalar()
    return token is not None


api.add_resource(UserInfo, '/auth/signup')
api.add_resource(EmailToken, '/auth/signup/email_token')
api.add_resource(EmailVerify, '/auth/signup/verify_email')
api.add_resource(UserOperation, '/auth/login/user/<int:id>')
api.add_resource(PasswordManager, '/auth/login/user/change_password')
api.add_resource(PasswordForgot, '/auth/forgot_password')
api.add_resource(Login, '/auth/login')
api.add_resource(UserIdentity, '/auth/login/current_user')
api.add_resource(RefreshAccessToken, '/refresh_access_token')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(debug=True)
