from flask_restful import Resource
from flask import request
from auth.password_manager import password_manager, password_forgot


class PasswordChange(Resource):
    @classmethod
    def put(cls):
        data = request.get_json()
        return password_manager(data['old_password'], data['new_password'], data['email'])


class PasswordForgot(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        return password_forgot(data['email'])

