from itsdangerous import URLSafeTimedSerializer


def generate_token(email):
    serializer = URLSafeTimedSerializer('eorigekfeorgjieofksdoffm')
    return serializer.dumps(email, salt='frkeorkfeo43jo3forfe')


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer('eorigekfeorgjieofksdoffm')
    try:
        email = serializer.loads(
            token, salt='frkeorkfeo43jo3forfe', max_age=expiration
        )
        return email
    except Exception:
        return False
