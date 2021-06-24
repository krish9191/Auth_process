from flask import request
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from auth.mail_manager import generate_update_email_token
from exception import MyException


class EmailUpdateToken(Resource):
    @jwt_required()
    def post(self):
        data = request.get_json()
        if not data:
            raise MyException('enter new email', status_code=404)
        return generate_update_email_token(data["email"])
