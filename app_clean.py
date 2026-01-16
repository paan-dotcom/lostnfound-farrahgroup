import os
import time
import requests
from datetime import datetime, timedelta
from collections import defaultdict

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# =====================================================
# ENV + APP SETUP
# =====================================================
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound_clean.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Security config
MAX_FAILED_ATTEMPTS = 5
LOCK_TIME_MINUTES = 15
RATE_LIMIT = 5          # requests
RATE_WINDOW = 60        # seconds

# hCaptcha
HCAPTCHA_SITEKEY = os.getenv("HCAPTCHA_SITEKEY")
HCAPTCHA_SECRET = os.getenv("HCAPTCHA_SECRET")

# =====================================================
# EXTENSIONS
# =====================================================
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# =====================================================
# RATE LIMITING (in-memory)
# =====================================================
rate_limit_store = defaultdict(list)

def is_rate_limited(ip):
    now = time.time()
    rate_limit_store[ip] = [
        t for t in rate_limit_store[ip] if now - t < RATE_WINDOW
    ]
    if len(rate_limit_store[ip]) >= RATE_LIMIT:
        return True
    rate_limit_store[ip].append(now)
    return False

# =====================================================
# CAPTCHA VERIFY
# =====================================================
def verify_hcaptcha(token, remoteip):
    if app.debug:
        return True

    if not token:
        return False

    try:
        r = requests.post(
            "https://hcaptcha.com/siteverify",
            data={
                "secret": HCAPTCHA_SECRET,
                "response": token,
                "remoteip": remoteip
            },
            timeout=5
        )
        return r.json().get("success", False)
    except Exception:
        return False

# =====================================================
# DATABASE MODELS
# =====================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False) # ADDED THIS
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    owner_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=True)
    action = db.Column(db.String(255), nullable=False)
    ip_address = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# =====================================================
# HELPERS
# =====================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def log_event(action):
    db.session.add(
        AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            ip_address=request.remote_addr
        )
    )
    db.session.commit()

def is_locked(user):
    if user.locked_until and user.locked_until > datetime.utcnow():
        return True
    return False

# =====================================================
# ROUTES
# =====================================================
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    ip = request.remote_addr

    if is_rate_limited(ip):
        flash("Too many requests. Slow down.", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        token = request.form.get("h-captcha-response")

        if not verify_hcaptcha(token, ip):
            log_event("Captcha failure on login")
            flash("Captcha verification failed", "danger")
            return redirect(url_for("login"))

        user = User.query.filter_by(username=request.form["username"]).first()

        if not user:
            flash("Invalid credentials", "danger")
            return redirect(url_for("login"))

        if is_locked(user):
            flash("Account locked. Try again later.", "danger")
            return redirect(url_for("login"))

        if check_password_hash(user.password, request.form["password"]):
            user.failed_attempts = 0
            user.locked_until = None
            db.session.commit()

            login_user(user)
            log_event(f"Login success: {user.username}")
            return redirect(url_for("home"))

        # failed password
        user.failed_attempts += 1
        log_event(f"Login failure: {user.username}")

        if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCK_TIME_MINUTES)
            log_event(f"Account locked: {user.username}")

        db.session.commit()
        flash("Invalid credentials", "danger")

    return render_template(
        "login.html",
        hcaptcha_sitekey=os.getenv("HCAPTCHA_SITEKEY")
    )

# -----------------------------------------------------
@app.route("/create", methods=["GET", "POST"])
def create():
    ip = request.remote_addr

    if is_rate_limited(ip):
        flash("Too many requests. Slow down.", "danger")
        return redirect(url_for("create"))

    if request.method == "POST":
        token = request.form.get("h-captcha-response")

        if not verify_hcaptcha(token, ip):
            log_event("Captcha failure on register")
            flash("Captcha verification failed", "danger")
            return redirect(url_for("create"))

        username = request.form["username"]
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return redirect(url_for("create"))

        user = User(
            username=username,
            password=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()
        log_event(f"Account created: {username}")

        flash("Account created successfully", "success")
        return redirect(url_for("login"))

    return render_template(
        "create.html",
        hcaptcha_sitekey=os.getenv("HCAPTCHA_SITEKEY")
    )

# -----------------------------------------------------
@app.route("/home")
@login_required
def home():
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template("home.html", items=items)

# -----------------------------------------------------
@app.route("/logout")
@login_required
def logout():
    log_event(f"Logout: {current_user.username}")
    logout_user()
    return redirect(url_for("login"))

# =====================================================
# MAIN
# =====================================================
# Look for this at the bottom of your app_clean.py
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                email="admin@example.com",  # <--- ADD THIS LINE HERE
                password=generate_password_hash("admin123"),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin created: admin / admin123")

    app.run(debug=True)
