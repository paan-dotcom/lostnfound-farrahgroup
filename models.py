from flask_login import UserMixin
from app import db

class User(UserMixin, db.Model):
    __table_args__ = {'extend_existing': True}  # <--- Add this line here
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), default='user')
