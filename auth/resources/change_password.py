from flask_restful import Resource
from flask import request
from auth.password_manager import change_password, forgot_password


class PasswordChange(Resource):
    @classmethod
    def put(cls):
        data = request.get_json()
        return change_password(data['email'], data['old_password'], data['new_password'])


class PasswordForgot(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        return forgot_password(data['email'])

