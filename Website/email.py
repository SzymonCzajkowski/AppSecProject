from flask_mail import Message


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender='filipk0@op.pl'
    )
    Message.send(msg)
