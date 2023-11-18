from flask import Blueprint, redirect, url_for, render_template, session, request

views = Blueprint('views', __name__)

@views.route('/')
def home():
	if "isGuest" not in session:
		session["isGuest"] = True

	return render_template("index.html", session=session)


@views.route('/logIn', methods=["POST", "GET"])
def log_in():
	if "isGuest" not in session:
		session["isGuest"] = True

	if request.method == "POST":
		username = request.form["username"]
		password = request.form["password"]
		session["isGuest"] = False
		session["username"] = username
		# checking hash
		print(username, password)
		return redirect(url_for("views.home"))
	else:
		return render_template("login.html", session=session)


@views.route('/logOut')
def log_out():
	session["isGuest"] = True
	session["username"] = ""
	return redirect(url_for("views.home"))
