from flask import Flask
from flask_restful import Api
from extensions.extensions import db, jwt, mail
from datetime import timedelta
from resources.login_resource import Login
from resources.user_identity_resource import UserIdentity
from resources.user_info_resource import UserInfo
from resources.user_opt_resource import UserOperation
from resources.refresh_access_token_resource import RefreshAccessToken
from resources.email_verify_resource import EmailToken, EmailVerify
from dotenv import load_dotenv
import os

app = Flask(__name__)
api = Api(app)

load_dotenv(".env")
database_password = os.environ.get('PASSWORD')
host = os.environ.get('HOST')
database = os.environ.get('DATABASE')
SECRET_KEY = os.environ.get('TOKEN_KEY')

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://postgres:{database_password}@{host}/{database}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=3)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


api.add_resource(Login, '/auth/login')
api.add_resource(UserInfo, '/auth/signup')
api.add_resource(UserIdentity, '/auth/login/current_user')
api.add_resource(UserOperation, '/auth/login/user/<int:id>')
api.add_resource(PasswordManager, '/auth/login/user/change_password')
api.add_resource(PasswordForgot, '/auth/forgot_password')
api.add_resource(RefreshAccessToken, '/refresh_access_token')
api.add_resource(EmailToken, '/auth/signup/email_token')
api.add_resource(EmailVerify, '/auth/signup/verify_email')

if __name__ == '__main__':
    db.init_app(app)
    jwt.init_app(app)
    mail.init_app(app)
    app.run(debug=True)
