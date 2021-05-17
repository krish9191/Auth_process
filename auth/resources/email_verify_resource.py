from flask_restful import Resource
from flask import request
from decorators import admin_required
from auth.mail_manager import email_token, email_verify


class EmailToken(Resource):
    @classmethod
    @admin_required
    def post(cls):
        data = request.get_json()
        return email_token(data['email'])


class EmailVerify(Resource):
    @classmethod
    @admin_required
    def patch(cls):
        data = request.get_json()
        return email_verify(data['token'])
