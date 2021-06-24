from flask import request
from flask_jwt_extended import current_user
from flask_restful import Resource
from auth.manager import update_email
from auth.model.user import User
from exception import MyException


class EmailUpdate(Resource):
    def patch(self):
        data = request.get_json()
        if not data:
            raise MyException('something is wrong, please try again later', status_code=500)
        return update_email(data["token"])

