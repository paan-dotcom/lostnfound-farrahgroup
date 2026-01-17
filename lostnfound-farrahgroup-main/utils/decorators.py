from flask_login import current_user
from flask import abort
from functools import wraps

def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)
            if current_user.role != role:
                abort(403)
            return f(*args, **kwargs)
        return decorated_view
    return wrapper
