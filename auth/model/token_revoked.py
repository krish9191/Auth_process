from extensions.extensions import db


class TokenRevoked(db.Model):
    __tablename__ = 'revoke_jwt'
    id = db.Column(db.Integer, primary_key=True)
    access_jti = db.Column(db.String, unique=True, nullable=False)
    refresh_jti = db.Column(db.String, unique=True, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)
