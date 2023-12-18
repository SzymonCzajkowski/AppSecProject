from flask import Blueprint, redirect, url_for, render_template, session, flash, request
from .models import db
from .models import Users
from .models import Jokes
from .token import generate_token, confirm_token
from .email import send_email
import shared
import datetime

views = Blueprint('views', __name__)


@views.route('/', methods=["POST", "GET"])
def home():
    if "isGuest" not in session:
        session["isGuest"] = True

    title = ""

    if request.method == "POST":
        title = request.form["title"]
        jokes = Jokes.query.filter(Jokes.title.contains(title))
    else:
        jokes = Jokes.query.all()
    return render_template("index.html", session=session, jokes=jokes, title=title)


@views.route('/login', methods=["POST", "GET"])
def log_in():
    if "isGuest" not in session:
        session["isGuest"] = True

    # If user is logged in redirect to home
    if not session["isGuest"]:
        return redirect(url_for("views.home"))

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check credentials
        error = False
        found_user = Users.query.filter_by(userName=username).first()
        if not found_user or not shared.validation_process(password, found_user.passwordHash, found_user.passwordSalt,
                                                           found_user.passwordNonce, found_user.passwordTag):
            flash("Wrong username or password!")
            error = True

        if error:
            return render_template("login.html", session=session, username=username)

        session["isGuest"] = False
        session["username"] = username
        return redirect(url_for("views.home"))
    else:
        return render_template("login.html", session=session)


@views.route('/forgot', methods=["POST", "GET"])
def forgot():
    if request.method == "POST":
        email = request.form["email"]

        # Check email
        error = False
        if not shared.check_email(email):
            flash("Wrong Email format")
            error = True

        if error:
            return render_template("forgot.html", session=session, email=email)
    else:
        return render_template("forgot.html", session=session)


@views.route('/register', methods=["POST", "GET"])
def register():
    if "isGuest" not in session:
        session["isGuest"] = True

    # If user is logged in redirect to home
    if not session["isGuest"]:
        return redirect(url_for("views.home"))

    if request.method == "POST":
        user_name = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Check if everything is ok
        error = False
        found_user = Users.query.filter_by(userName=user_name).first()
        if found_user:
            flash("Username must be unique!")
            error = True
        found_user = Users.query.filter_by(email=email).first()
        if len(user_name) < 3:
            flash("Username must be longer!")
            error = True
        if found_user:
            flash("Email already registered")
            error = True
        if not shared.check_email(email):
            flash("Wrong Email format")
            error = True
        if not shared.check_strong_password(password):
            flash("Password must be 8 characters long with at least one uppercase, lowercase and special character!")
            error = True

        # if something is wrong return registration page
        if error:
            return render_template("register.html", session=session, username=user_name, email=email)

        # If everything is fine add new user
        user = Users(user_name, email, password)
        db.session.add(user)
        db.session.commit()

        # Generating verification token
        token = generate_token(user.email)
        confirm_url = url_for('views.confirm_email',
                              token=token, _external=True)
        html = render_template('activate.html',
                               confirm_url=confirm_url)
        subject = "Please confirm your email."
        send_email(user.email, subject, html)

        session["isGuest"] = False
        session["username"] = user_name
        flash('A confirmation email has been sent via email.', 'success')
        return redirect(url_for("views.home"))
    else:
        return render_template("register.html", session=session)


@views.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
    user = Users.query.filter_by(email=email).first_or_404()
    if user.isConfirmed:
        flash('Account is already confirmed. Please login.', 'success')
    else:
        user.isConfirmed = True
        user.confirmedOn = datetime.datetime.now()
        db.session.add(user)
        db.session.commit()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('views.home'))


@views.route('/logOut')
def log_out():
    if "isGuest" not in session:
        session["isGuest"] = True
    # If user is logged in redirect to home
    if session["isGuest"]:
        return redirect(url_for("views.home"))

    session["isGuest"] = True
    session.pop("username", None)
    flash("Successfully logged out")
    return redirect(url_for("views.home"))


@views.route('/addJoke', methods=["POST", "GET"])
def add_joke():
    if "isGuest" not in session:
        session["isGuest"] = True
    # If user is not logged in redirect to home
    if session["isGuest"]:
        return redirect(url_for("views.home"))

    if request.method == "POST":
        title = request.form["jokeTitle"]
        content = request.form["jokeContent"]
        joke = Jokes(title, content, session["username"])
        db.session.add(joke)
        db.session.commit()
        flash("Joke Added successfully!")
        return redirect(url_for("views.home"))
    else:
        return render_template("addJoke.html", session=session)
