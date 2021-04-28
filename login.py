from flask import Flask, request, jsonify,make_response
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from marshmallow import Schema, fields

app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:1234@localhost/lottery"
db = SQLAlchemy(app)


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)


class UserSchema(Schema):
    username = fields.Str()
    password = fields.Str()
    email = fields.Email()
    firstname = fields.Str()
    lastname = fields.Str()


user = UserSchema()
users = UserSchema(many=True)


def login_decorator(func):
    @wraps(func)
    def check_login(*args, **kwargs):
        auth = request.authorization
        if auth.username == User.username and auth.password == User.password:
           return func(*args, **kwargs)
        else:
            return make_response('you are not allowed to visit this page',401)
    return check_login


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

        return jsonify({'users': results})

    def post(self):
        first_name = request.json['Firstname']
        last_name = request.json['Lastname']
        email = request.json['Email']
        user_name = request.json['Username']
        password = request.json['Password']
        user = User(username=user_name, password=password, email=email, firstname=first_name, lastname=last_name)
        db.session.add(user)
        db.session.commit()
        return 'Successfully inserted'


class UserOperation(Resource):

    def get(self, id):
        user = User.query.get(id)
        data_user = dict()
        data_user['username'] = user.username
        data_user['password'] = user.password
        data_user['email'] = user.email
        data_user['firstname'] = user.firstname
        data_user['lastname'] = user.lastname
        return jsonify({'user': data_user})

    def delete(self, id):
        user = User.query.get(id)
        db.session.delete(user)
        db.session.commit()
        return 'Successfully deleted'

    def put(self, id):
        user = User.query.get(id)
        username = request.json.get('Username', 'None')
        if username != 'None':
            user.username = username
        firstname = request.json.get('Firstname', 'None')
        if firstname != 'None':
            user.firstname = firstname
        lastname = request.json.get('Lastname', 'None')
        if lastname != 'None':
            user.lastname = lastname
        email = request.json.get('Email', 'None')
        if email != 'None':
            user.email = email

        db.session.commit()
        return 'successfully updated'



@app.route('/change_password/<email>', methods=['PUT'])
def changing_password(email):
    user = User.query.filter_by(email=email).first()
    password = request.json['Password']
    user.password = password
    db.session.commit()
    return 'password changed '


@app.route('/login')
def check_login():
    users = User.query.all()
    auth = request.authorization
    for user in users:
        if auth and auth.username == user.username and auth.password == user.password:
            return 'login successful'
        else:
            return 'login failed'


api.add_resource(UserInfo, '/user')
api.add_resource(UserOperation, '/user/<int:id>')


if __name__ == '__main__':
    app.run(debug=True)
