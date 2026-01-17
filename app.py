from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import logging

# =====================================================
# App & Config
# =====================================================
app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# File Upload Setup
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config["UPLOAD_FOLDER"] = os.path.join(BASE_DIR, "static", "images")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Helper for allowed files
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# =====================================================
# Models
# =====================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=True) # Added from v2
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user") # Restored from v1
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    items = db.relationship('Item', backref='author', lazy=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="lost")
    category = db.Column(db.String(50))
    location = db.Column(db.String(100))
    image = db.Column(db.String(255))
    contact_info = db.Column(db.String(100))
    priority = db.Column(db.Integer, default=1) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =====================================================
# Routes
# =====================================================

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == "it_admin": return redirect(url_for("it_dashboard"))
            if user.role == "admin": return redirect(url_for("admin_dashboard"))
            return redirect(url_for("dashboard"))
        flash("Invalid credentials")
    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template("dashboard.html", items=items)

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        image_file = request.files.get("image")
        image_path = None

        if image_file and image_file.filename and allowed_file(image_file.filename):
            filename = secure_filename(image_file.filename)
            image_file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
            image_path = f"images/{filename}"

        item = Item(
            title=request.form.get("title"),
            description=request.form.get("description"),
            status=request.form.get("status", "lost"),
            category=request.form.get("category"),
            location=request.form.get("location"),
            contact_info=request.form.get("contact_info"),
            image=image_path,
            user_id=current_user.id
        )
        db.session.add(item)
        db.session.commit()
        flash("Item reported!")
        return redirect(url_for("dashboard"))
    return render_template("report.html")

# Admin and IT Routes
@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin": return redirect(url_for("dashboard"))
    items = Item.query.all()
    return render_template("admin_dashboard.html", items=items)

@app.route("/it-dashboard")
@login_required
def it_dashboard():
    if current_user.role != "it_admin": return redirect(url_for("dashboard"))
    return render_template("it_dashboard.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)