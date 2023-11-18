from flask import Flask


def create_app():
	# Setting Flask
	app = Flask(__name__)
	# Add database
	app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
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
