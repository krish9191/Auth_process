from flask_restful import Resource
from flask import request
from auth.manager import add_user
from auth.manager import list_users


class UserInfo(Resource):
    @classmethod
    def post(cls):  # user registration
        data = request.get_json()
        if request.json == {}:
            return {'message': 'it is required to enter all the fields', 'error': 'bad request, 404'}, 400

        return add_user(
            data['firstname'], data['lastname'], data['username'], data['email'], data['role'], data['password'])

    @classmethod
    def get(cls):
        return list_users()




