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

	# To delete later
	with app.app_context():
		from .models import Users
		username = 'admin'
		found_user = Users.query.filter_by(userName=username).first()
		if not found_user:
			user = Users(username, 'admin@email.com', 'admin', True)
			db.session.add(user)
			db.session.commit()

	# Registering views
	from .views import views
	app.register_blueprint(views, url_prefix='/')

	return app
