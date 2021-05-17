from flask_restful import Resource
from auth.manager import user_identity
from decorators import admin_required
from flask_jwt_extended import jwt_required


class UserIdentity(Resource):
    @classmethod
    @jwt_required()
    def get(cls):
        return user_identity()
