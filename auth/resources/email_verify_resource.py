from flask_restful import Resource
from flask import request
from auth.mail_manager import generate_email_token, email_verify
from exception import MyException


class EmailToken(Resource):
    @classmethod
    def post(cls):
        data = request.get_json()
        if not data:
            raise MyException('field cannot be empty', status_code=400)
        return generate_email_token(data['email'])


class EmailVerify(Resource):
    @classmethod
    def patch(cls):
        data = request.get_json()
        if not data:
            raise MyException('field cannot be empty', status_code=400)
        return email_verify(data['token'])
