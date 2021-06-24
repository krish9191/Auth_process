from flask_restful import Resource
from flask import request
from auth.manager import update_role
from decorators import admin_required
from exception import MyException


class RoleUpdate(Resource):
    @classmethod
    @admin_required
    def patch(cls):
        data = request.get_json()
        if not data:
            raise MyException('fields cannot be empty', status_code=400)
        return update_role(data['username'], data['role'])
