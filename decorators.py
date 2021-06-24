from flask_jwt_extended import verify_jwt_in_request
from flask_jwt_extended import get_jwt
from functools import wraps

from auth.model.user import User
from exception import MyException


def admin_required(func):

    """ decorator that checks designated role to the users"""

    @wraps(func)
    def is_check_admin(*args, **kwargs):
        try:
            verify_jwt_in_request()
            role = get_jwt()
            if role['admin']:
                return func(*args, **kwargs)
        except Exception:
            raise MyException('you are not authorised for this operation', status_code=401)

    return is_check_admin


def login_required(func):
    @wraps(func)
    def is_user_login(*args, **kwargs):
        verify_jwt_in_request()
        username = get_jwt()
        user = User.query.filter(User.username == username).first()
        if user is None:
            raise MyException('login required', status_code=401)
        return func(*args, **kwargs)

    return is_user_login
