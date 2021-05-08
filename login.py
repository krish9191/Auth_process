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
from flask_jwt_extended import current_user
from flask_jwt_extended import JWTManager
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from dotenv import load_dotenv
from functools import wraps
import os

app = Flask(__name__)
api = Api(app)
load_dotenv(".env")
database_password = os.environ.get('PASSWORD')
host = os.environ.get('HOST')
database = os.environ.get('DATABASE')
SECRET_KEY = os.environ.get("TOKEN_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://postgres:{database_password}@{host}/{database}"
db = SQLAlchemy(app)
app.config["JWT_SECRET_KEY"] = SECRET_KEY
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=3)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)
print(app.config)


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(255), default=None)


class RevokedToken(db.Model):
    __tablename__ = 'revoke_jwt'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)


db.create_all()


class UserInfo(Resource):

    def get(self):
        users = User.query.all()
        results = []
        for user in users:
            data_user = dict()
            data_user['username'] = user.username
            data_user['password'] = user.password
            data_user['email'] = user.email
            data_user['firstname'] = user.firstname
            data_user['lastname'] = user.lastname
            results.append(data_user)

        return {'users': results}

    def post(self):
        if request.json == {}:
            return {'message': 'it is required to enter all the fields', 'error': 400}, 400

        first_name = request.json.get('firstname')
        if first_name is None or first_name == '':
            return {'message': 'firstname is not valid', 'error': 400}, 400
        else:
            firstname = first_name.strip()

        last_name = request.json.get('lastname')
        if last_name is None or last_name == '':
            return {'message': 'lastname is not valid', 'error': 400}, 400
        else:
            lastname = last_name.strip()

        email = request.json.get('email')
        if email is None or email == '':
            return {'message': 'email is not valid', 'error': 400}, 400
        else:
            u_email = email.strip()

        user_name = request.json.get('username')
        if user_name is None or user_name == '':
            return {'message': 'username is not valid', 'error': 400}, 400
        else:
            username = user_name.strip()

        role = request.json.get('role')
        if role is not None:
            if role != 'admin' and role != 'user':
                return {'message': 'role is not valid', 'error': 400}, 400

        password = request.json.get('password')

        if is_check_none_space_length(password) and is_check_char(password) and is_check_special_char(password):
            pwd = password_hashing(password)
            user = User(username=username, password=pwd, email=u_email, firstname=firstname, lastname=lastname,
                        role=role)
            db.session.add(user)
            db.session.commit()
            return {'users': {
                'username': user_name,
                'password': password,
                'firstname': first_name,
                'lastname': last_name,
                'email': email,
                'role': role
            }
            }
        return {'error': '400 Bad Request', 'message': 'Enter a valid Password'}, 400


def admin_required(func):
    @wraps(func)
    def is_check_admin(*args, **kwargs):
        verify_jwt_in_request()
        claim = get_jwt()
        try:
            if claim['is_administrator']:
                return func(*args, **kwargs)
        except KeyError as err:
            return {"error": '403, forbidden', 'message': 'you are not authorize to perform this operation '}, 403
    return is_check_admin


class UserOperation(Resource):
    @jwt_required(fresh=True)
    def get(self, id):
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
    def delete(self, id):
        user = User.query.get(id)
        if user is None:
            return {"error": '404 Not Found', 'message': 'please enter a valid id', 'field': 'id'}, 404
        db.session.delete(user)
        db.session.commit()
        return {'deleted': user.user_id}

    @jwt_required(fresh=True)
    def put(self, id):
        user = User.query.get(id)
        if user is None:
            return {"error": '404 Not Found', 'message': 'please enter a valid id', 'field': 'id'}, 404
        username = request.json.get('username', 'none')
        if username != 'none':
            user.username = username
        firstname = request.json.get('firstname', 'none')
        if firstname != 'none':
            user.firstname = firstname
        lastname = request.json.get('lastname', 'none')
        if lastname != 'none':
            user.lastname = lastname
        email = request.json.get('email', 'none')
        if email != 'none':
            user.email = email

        db.session.commit()
        return 'successfully updated'


class PasswordManager(Resource):
    @jwt_required(fresh=True)
    def put(self):
        data = request.get_json()
        user = User.query.filter_by(email=data['email']).first()
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

        return {'error': '400 Bad Request', 'message': 'please enter a valid new password'}, 400


class Login(Resource):
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


class Identity(Resource):

    @jwt_required(fresh=True)
    def get(self):
        return jsonify(
            id=current_user.user_id,
            username=current_user.username,
            password=current_user.password

        )


class RefreshAccessToken(Resource):
    @jwt_required(refresh=True)
    def post(self):
        identity = get_jwt_identity()
        token = create_access_token(identity=identity, fresh=True)
        return {'token': token}


class Logout(Resource):
    @jwt_required()
    def delete(self):
        jti = get_jwt()['jti']
        deleted_at = datetime.now(timezone.utc)
        revoked_token = RevokedToken(jti=jti, created_at=deleted_at)
        db.session.add(revoked_token)
        db.session.commit()
        return {'deleted': jti}


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
    token = db.session.query(RevokedToken.id).filter_by(jti=jti).scalar()
    return token is not None


api.add_resource(UserInfo, '/auth/signup')
api.add_resource(UserOperation, '/user/<int:id>')
api.add_resource(PasswordManager, '/user/change_password')
api.add_resource(Login, '/login')
api.add_resource(Identity, '/user_logged_in')
api.add_resource(RefreshAccessToken, '/refresh_access_token')
api.add_resource(Logout, '/logout')

if __name__ == '__main__':
    app.run(debug=True)
