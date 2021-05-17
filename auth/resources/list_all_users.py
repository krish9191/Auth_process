from auth.manager import list_users
from flask_restful import Resource
from decorators import admin_required


class UsersList(Resource):
    @classmethod
    @admin_required
    def get(cls):
        return list_users()