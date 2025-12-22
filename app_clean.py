from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from datetime import timedelta

app = Flask(__name__, template_folder="templates", static_folder="static")

app.secret_key = "secret-key"

# Database
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound_clean.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False)   # "lost" or "found"
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    contact_info = db.Column(db.String(100))
    image_path = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime)


# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ---------------- MODELS ----------------

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

# ---------------- LOGIN ----------------

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ---------------- ROUTES ----------------

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(
            username=request.form["username"],
            password=request.form["password"]
        ).first()

        if user:
            login_user(user)
            return redirect(url_for("home"))

        flash("Invalid credentials")

    return render_template("login_custom.html")


@app.route("/continue_without_login")

def continue_without_login():
    return redirect(url_for("login"))


@app.route("/create", methods=["GET", "POST"])
def create():
    if request.method == "POST":
        if request.form["password"] != request.form["confirm_password"]:
            flash("Passwords do not match")
            return redirect(url_for("create"))

        if User.query.filter_by(username=request.form["username"]).first():
            flash("Username already exists")
            return redirect(url_for("create"))

        user = User(
            username=request.form["username"],
            password=request.form["password"]
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created. Please login.")
        return redirect(url_for("login"))

    return render_template("create.html")

@app.route("/home")
@login_required
def home():
    return render_template("home.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------------- MAIN ----------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
