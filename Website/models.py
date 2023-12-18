from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
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
    isConfirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmedOn = db.Column(db.DateTime, nullable=True)

    def __init__(self, name, email, password, is_admin=False, isConfirmed=False, confirmedOn=None):
        self.userName = name
        self.email = email
        self.passwordSalt = shared.gen_user_salt()
        self.passwordHash, self.passwordNonce, self.passwordTag = shared.hashing_process(
            password, self.passwordSalt)
        self.isAdmin = is_admin
        self.isConfirmed = isConfirmed
        self.confirmedOn = confirmedOn

    def update_password(self, password):
        self.passwordHash, self.passwordNonce, self.passwordTag = shared.hashing_process(
            password, self.passwordSalt)


class Jokes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.TEXT(100), nullable=False)
    content = db.Column(db.TEXT(600), nullable=False)
    author = db.Column(db.String(30), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __init__(self, title, content, author):
        self.title = title
        self.content = content
        self.author = author


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jokeId = db.Column(db.Integer, nullable=False)
    content = db.Column(db.TEXT(600), nullable=False)
    author = db.Column(db.String(30), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def __init__(self, joke_id, content, author):
        self.jokeId = joke_id
        self.content = content
        self.author = author
