import hashlib
import re
import bcrypt
from Cryptodome.Cipher import AES


def passwd_validate(hash_input, encrypted_hash, nonce, tag, pepper=b'0\xeb\xa2\x8fl\xc1%\xe3\xbe\x80$\xd4\x15\x043\xe9\xdeGf\xbb\x96\x9a\xd4XQ5\xc8\xb4\xe9\x83\xcb7'):
    return ''


def hashing_process(input, user_salt, pepper=b'0\xeb\xa2\x8fl\xc1%\xe3\xbe\x80$\xd4\x15\x043\xe9\xdeGf\xbb\x96\x9a\xd4XQ5\xc8\xb4\xe9\x83\xcb7'):
    hash = sha512hashing(input)
    hash = bcrypthashing(hash, user_salt.encode('UTF-8'))
    hash, nonce, tag = encryptAES256(hash, pepper)
    print(hash.hex())
    print(nonce.hex())
    print(tag.hex())
    return hash, nonce, tag


def encryptAES256(input, pepper):
    cipher = AES.new(pepper, AES.MODE_EAX)
    cipherinput, tag = cipher.encrypt_and_digest(input.encode('UTF-8'))
    return cipherinput, cipher.nonce, tag


def bcrypthashing(input, user_salt):

    return bcrypt.hashpw(input.encode('UTF-8'), user_salt).decode('UTF-8')


def sha512hashing(input, rounds=653526):
    hash = calculate_hash(input)
    i = rounds
    while i > 1:
        hash = calculate_hash(hash)
        i -= 1
    return hash


def gen_user_salt():
    return bcrypt.gensalt(rounds=15).decode('UTF-8')


def calculate_hash(password):
    m = hashlib.sha512(password.encode('UTF-8'))
    return m.hexdigest()


def check_strong_password(password):
    password_pattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$"
    return re.match(password_pattern, password)


def check_email(email):
    email_pattern = "([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+"
    return re.fullmatch(email_pattern, email)


salt = '$2b$15$VZRHxC8mz66qv80l/AdoH.'
hashing_process('admin',  salt)
