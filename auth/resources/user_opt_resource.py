from flask_restful import Resource
from flask_jwt_extended import jwt_required
from decorators import admin_required
from auth.manager import list_user
from auth.manager import delete_user
from auth.manager import update_user


class UserOperation(Resource):

    @classmethod
    @admin_required
    def get(cls, id):  # list user by a specified user_id
        return list_user(id)

    @classmethod
    @admin_required
    def delete(cls, id):  # delete user using user_id
        return delete_user(id)

    @classmethod
    @jwt_required()
    def put(cls, id):  # update user using user_id, can update single field or multiple field
        return update_user(id)
