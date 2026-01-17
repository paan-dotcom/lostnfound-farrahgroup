from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import re

app = Flask(__name__)
app.secret_key = "super_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

# --------------------------------------------------
# Models
# --------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")
    failed_attempts = db.Column(db.Integer, default=0)
    blocked = db.Column(db.Boolean, default=False)
    items = db.relationship('Item', backref='author', lazy=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="lost")
    priority = db.Column(db.Integer, default=1) # 0 = Solved, 1 = Pending
    location = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --------------------------------------------------
# Auth Routes
# --------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
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
    items = Item.query.all()
    return render_template("dashboard.html", items=items)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------- ADMIN DASHBOARD & ACTIONS ----------
@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin": 
        flash("Unauthorized!")
        return redirect(url_for("dashboard"))
    items = Item.query.all() # Fetch reports for the admin table
    return render_template("admin_dashboard.html", items=items)

@app.route("/admin/update/<int:item_id>", methods=["POST"])
@login_required
def update_report(item_id):
    item = Item.query.get_or_404(item_id)
    item.priority = 0 
    db.session.commit()
    flash("Report marked as solved.")
    return redirect(url_for("admin_dashboard"))

@app.route("/admin/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_report(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash("Report deleted.")
    return redirect(url_for("admin_dashboard"))

# ---------- IT ADMIN DASHBOARD & TOOLS ----------
@app.route("/it-dashboard")
@login_required
def it_dashboard():
    if current_user.role != "it_admin": 
        return redirect(url_for("dashboard"))
    return render_template("it_dashboard.html")

@app.route("/it-admin/logs")
@login_required
def view_logs():
    logs = ["System Initialized", "User Login Detected", "Database Checkpoint Reached"]
    return render_template("it_logs.html", logs=logs)

@app.route("/it-admin/backup")
@login_required
def backup_db():
    flash("Database Backup Created Successfully!")
    return redirect(url_for("it_dashboard"))

@app.route("/it-admin/permissions")
@login_required
def manage_permissions():
    users = User.query.all()
    return render_template("it_permissions.html", users=users)

# --------------------------------------------------
# Start Server
# --------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)