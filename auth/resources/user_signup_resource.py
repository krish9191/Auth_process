from flask_restful import Resource
from flask import request
from auth.manager import add_user
from exception import MyException


class UserInfo(Resource):
    @classmethod
    def post(cls):  # user registration
        try:
            data = request.get_json()
            if not data:
                return {'message': 'required to enter all the fields', 'error': 'bad request, 400'}, 400
            return add_user(
                data['firstname'], data['lastname'], data['username'], data['email'], data['password'])
        except Exception as err:
            if "username" in err.args[0]:
                raise MyException('this username is already taken try next', status_code=406)
            else:
                raise MyException('email must be unique', status_code=406)

