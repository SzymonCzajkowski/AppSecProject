from flask_sqlalchemy import SQLAlchemy
import shared
import string
import random

# Initialize database
db = SQLAlchemy()


# Create database models
class Users(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	userName = db.Column(db.String(30), nullable=False)
	email = db.Column(db.String(60), nullable=False, unique=True)
	passwordSalt = db.Column(db.String(10), nullable=False)
	passwordHash = db.Column(db.String(128), nullable=False)
	isAdmin = db.Column(db.BOOLEAN, nullable=False, default=False)

	def __init__(self, name, email, password, is_admin=False):
		self.userName = name
		self.email = email
		self.passwordSalt = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(10))
		self.passwordHash = shared.calculate_hash(password, self.passwordSalt)
		self.isAdmin = is_admin
