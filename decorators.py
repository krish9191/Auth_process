from flask_jwt_extended import verify_jwt_in_request
from flask_jwt_extended import get_jwt
from functools import wraps


def admin_required(func):  # decorator which checks claims(type of user) in token payload
    @wraps(func)
    def is_check_admin(*args, **kwargs):
        verify_jwt_in_request()
        claim = get_jwt()
        try:
            if claim['is_administrator']:
                return func(*args, **kwargs)
        except KeyError:
            return {"error": '403, forbidden', 'message': 'you are not authorize to perform this operation '}, 403

    return is_check_admin
