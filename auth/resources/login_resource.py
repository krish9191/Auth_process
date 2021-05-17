from flask_restful import Resource
from flask import request
from auth.manager import user_login


class Login(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        return user_login(data['username'], data['password'])
