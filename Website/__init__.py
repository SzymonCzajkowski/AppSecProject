from flask import Flask


def create_app():
	# Setting Flask
	app = Flask(__name__)
	app.config['SECRET_KEY'] = '0gZ2Rmcw7-$t'

	# Registering views
	from .views import views

	app.register_blueprint(views, url_prefix='/')

	return app