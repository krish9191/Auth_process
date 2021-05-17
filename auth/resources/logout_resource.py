from flask_restful import Resource
from auth.manager import user_logout
from flask_jwt_extended import jwt_required


class Logout(Resource):
    @classmethod
    @jwt_required()
    def post(cls):
        return user_logout()
