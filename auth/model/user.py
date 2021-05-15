from datetime import datetime
from extensions.extensions import db


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(255), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    email_status = db.Column(db.Boolean, default=False)
    email_created_at = db.Column(db.DateTime(timezone=True))
    role = db.Column(db.String(255), default=None)

    def __init__(self, username, password, firstname, lastname, email, role):
        self.username = username
        self.password = password
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.role = role
        self.email_status = False
        self.email_created_at = datetime.utcnow()



