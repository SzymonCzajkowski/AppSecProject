from flask import Flask
from flask_mail import Mail


def create_app():
    # Setting Flask

    # Add database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///appSec.db'
    app.config['SECRET_KEY'] = '0gZ2Rmcw7-$t'

    # Register database
    from .models import db
    db.init_app(app)
    with app.app_context():
        db.create_all()

    # Registering views
    from .views import views
    app.register_blueprint(views, url_prefix='/')

    return app


def setup_mail_config():
    # Mail config
    app.config['MAIL_DEFAULT_SENDER'] = "sanderka12pl@gmail.com"
    app.config['MAIL_SERVER'] = "smtp.gmail.com"
    app.config['MAIL_PORT'] = 465
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = True
    app.config['MAIL_DEBUG'] = False
    app.config['MAIL_USERNAME'] = "sanderka12pl"
    app.config['MAIL_PASSWORD'] = "zpls diud jqbi qgwj"


app = Flask(__name__)
setup_mail_config()
mail = Mail(app)
