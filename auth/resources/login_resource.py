from flask_restful import Resource
from flask import request
from auth.manager import user_login
from exception import MyException


class Login(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        if not data:
            raise MyException('username and password field cannot be empty', status_code=400)
        return user_login(data['username'], data['password'])
