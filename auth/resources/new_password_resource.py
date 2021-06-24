from flask_restful import Resource
from flask import request
from flask_jwt_extended import jwt_required
from auth.password_manager import change_password, forgot_password
from exception import MyException


class PasswordChange(Resource):
    @classmethod
    @jwt_required()
    def put(cls):
        data = request.get_json()
        if not data:
            raise MyException('fields cannot be empty', status_code=400)
        return change_password(data['email'], data['old_password'], data['new_password'])


class PasswordForgot(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        if not data:
            raise MyException('fields cannot be empty', status_code=400)
        return forgot_password(data['email'])
