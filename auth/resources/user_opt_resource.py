from flask_restful import Resource
from flask_jwt_extended import jwt_required
from decorators import admin_required
from auth.manager import list_user
from auth.manager import delete_user
from auth.manager import update_user
from exception import MyException


class UserOperation(Resource):

    @classmethod
    @admin_required
    def get(cls, id):
        return list_user(id)

    @classmethod
    @admin_required
    def delete(cls, id):
        return delete_user(id)


class UserUpdate(Resource):
    @classmethod
    @jwt_required()
    def put(cls):
        try:
            return update_user()
        except Exception as err:
            raise MyException('this username is taken try next', status_code=406)
