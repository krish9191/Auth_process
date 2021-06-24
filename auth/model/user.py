from datetime import datetime
from extensions.extensions import db


class User(db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    lastname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    email_status = db.Column(db.Boolean, default=False)
    email_created_at = db.Column(db.DateTime(timezone=True))
    role = db.Column(db.String(255), default='user')

    def __init__(self, username, password, firstname, lastname, email):
        self.username = username
        self.password = password
        self.email = email
        self.firstname = firstname
        self.lastname = lastname
        self.role = 'user'
        self.email_status = False
        self.email_created_at = datetime.utcnow()

    def to_str_date(self):
        normal_date = self.email_created_at
        str_date = normal_date.strftime("%Y/%m/%d,%H:%M:%S")
        return str_date

    def write_to_dict(self):
        return {
            'id': self.user_id,
            'user': {
                'username': self.username,
                'email': self.email,
                'firstname': self.firstname,
                'lastname': self.lastname,
                'role': self.role,
                'email_status': self.email_status,
                'email_created_at': self.to_str_date()
            }
        }

    @classmethod
    def find_user_by_id(cls, id):
        return User.query.filter(User.user_id == id).first()

    @classmethod
    def find_user_by_email(cls, email):
        return User.query.filter(User.email == email).first()

    @classmethod
    def find_user_by_username(cls, username):
        return User.query.filter(User.username == username).first()

    @classmethod
    def find_all_user(cls):
        return User.query.all()
