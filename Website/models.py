from flask_sqlalchemy import SQLAlchemy
import shared

# Initialize database
db = SQLAlchemy()


# Create database models
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(60), nullable=False, unique=True)
    passwordSalt = db.Column(db.String(32), nullable=False)
    passwordHash = db.Column(db.String(128), nullable=False)
    passwordNonce = db.Column(db.String(32), nullable=False)
    passwordTag = db.Column(db.String(32), nullable=False)
    isAdmin = db.Column(db.BOOLEAN, nullable=False, default=False)

    def __init__(self, name, email, password, is_admin=False):
        self.userName = name
        self.email = email
        self.passwordSalt = shared.gen_user_salt()
        self.passwordHash, self.passwordNonce, self.passwordTag = shared.hashing_process(
            password, self.passwordSalt),
        self.isAdmin = is_admin
