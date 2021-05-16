from flask import request
from flask_restful import Resource
from auth.manager import refresh_access_token
from flask_jwt_extended import jwt_required


class RefreshAccessToken(Resource):
    @jwt_required(refresh=True)
    def post(self):
        return refresh_access_token()
