import hashlib
import re


def calculate_hash(password, password_salt):
	sha = m = hashlib.sha512(password.encode('UTF-8') + password_salt.encode('UTF-8'))
	return m.hexdigest()


def check_strong_password(password):
	password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
	return re.match(password_pattern, password)


def check_email(email):
	email_pattern = "([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
	return re.fullmatch(email_pattern, email)
