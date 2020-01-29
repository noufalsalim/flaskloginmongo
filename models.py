from flask_login import UserMixin
from app import db

class User(UserMixin, db.Document):
    email = db.StringField(required=True)
    password = db.StringField(required=True)
    name = db.StringField(max_length=50)