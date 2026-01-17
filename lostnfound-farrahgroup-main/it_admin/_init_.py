from flask import Blueprint

it_admin_bp = Blueprint(
    'it_admin',
    __name__,
    url_prefix='/it-admin'
)

from . import routes
