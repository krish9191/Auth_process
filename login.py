
from flask import Flask, request, jsonify
from flask_restful import Api, Resource
from flask_sqlalchemy import SQLAlchemy
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


class UserInfo(Resource):

    def get(self):
        users = User.query.all()
        schema = UserSchema(many=True)
        output = schema.dump(users)
        return output

    def post(self):
        first_name = request.json['Firstname']
        last_name = request.json['Lastname']
        email = request.json['Email']
        user_name = request.json['Username']
        password = request.json['Password']
        user = User(username=user_name,password=password,email=email,firstname=first_name,lastname=last_name)
        db.session.add(user)
        db.session.commit()
        return 'Successfully inserted'

class UserOperation(Resource):

    def get(self, id):
        user = User.query.get(id)
        schema = UserSchema()
        output = schema.dump(user)
        return output


    def delete(self, id):
        user = User.query.get(id)
        db.session.delete(user)
        db.session.commit()
        return 'Successfully deleted'


api.add_resource(UserInfo, '/user')
api.add_resource(UserOperation,'/user/<int:id>')

if __name__ == '__main__':
    app.run(debug=True)