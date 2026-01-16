from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
import re

# --------------------------------------------------
# App setup
# --------------------------------------------------
app = Flask(__name__)
app.secret_key = "super_secret_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)

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
    # Relationship to items
    items = db.relationship('Item', backref='author', lazy=True)

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="lost") # 'lost' or 'found'
    priority = db.Column(db.Integer, default=1)      # 1=Low, 2=Med, 3=High
    image_file = db.Column(db.String(100), default='default.jpg')
    location = db.Column(db.String(100))
    contact = db.Column(db.String(100))
    date_posted = db.Column(db.DateTime, default=db.func.current_timestamp())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --------------------------------------------------
# Login loader
# --------------------------------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --------------------------------------------------
# Password policy
# --------------------------------------------------
def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[!@#$%^&*()_+=\-]", password)
    )

# --------------------------------------------------
# Routes
# --------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("register"))

        if not is_strong_password(password):
            flash("Password must be strong (8 chars, upper, lower, number, symbol)")
            return redirect(url_for("register"))

        user = User(username=username, role="user")
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Invalid username or password")
            return redirect(url_for("login"))

        if user.blocked:
            flash("Account blocked after 3 failed attempts")
            return redirect(url_for("login"))

        if user.check_password(password):
            user.failed_attempts = 0
            db.session.commit()
            login_user(user)
            
            # ROLE-BASED REDIRECT
            if user.role == "it_admin":
                return redirect(url_for("it_dashboard"))
            elif user.role == "admin":
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))
        else:
            user.failed_attempts += 1
            if user.failed_attempts >= 3:
                user.blocked = True
            db.session.commit()
            flash("Invalid username or password")

    return render_template("login.html")

# ---------- DASHBOARDS ----------

@app.route("/dashboard")
@login_required
def dashboard():
    # Pull data from database for the HTML
    items = Item.query.order_by(Item.date_posted.desc()).all()
    total_items = Item.query.count()
    total_lost = Item.query.filter_by(status='lost').count()
    total_found = Item.query.filter_by(status='found').count()
    recent_items = Item.query.order_by(Item.date_posted.desc()).limit(5).all()

    return render_template("dashboard.html", 
                           items=items, 
                           total_items=total_items, 
                           total_lost=total_lost, 
                           total_found=total_found, 
                           recent_items=recent_items)

@app.route("/it-dashboard")
@login_required
def it_dashboard():
    if current_user.role != "it_admin":
        flash("Unauthorized access!")
        return redirect(url_for("dashboard"))
    return render_template("it_dashboard.html")

@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("dashboard"))
    return render_template("admin_dashboard.html")

# ---------- PROFILE & LOGOUT ----------

@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        flash("Report submitted successfully!")
        return redirect(url_for("profile"))
    return render_template("profile.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/report")
@login_required
def report():
    return "<h1>Report Page</h1><p>This page is under construction.</p><a href='/dashboard'>Back</a>"

@app.route("/locations")
@login_required
def show_locations():
    return "<h1>Locations Page</h1><p>This page is under construction.</p><a href='/dashboard'>Back</a>"

# --------------------------------------------------
# Database init
# --------------------------------------------------
with app.app_context():
    db.create_all()

    # Create default Admin
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", role="admin")
        admin.set_password("Admin@123!")
        db.session.add(admin)

    # Create default IT Admin
    if not User.query.filter_by(username="itadmin").first():
        it_admin = User(username="itadmin", role="it_admin")
        it_admin.set_password("StrongPass123!")
        db.session.add(it_admin)

    db.session.commit()

# ---------- IT ADMIN TOOLS ----------

@app.route("/it-admin/logs")
@login_required
def view_logs():
    if current_user.role != "it_admin":
        return redirect(url_for("dashboard"))
    # In a real app, you'd read a log file here
    logs = ["User 'admin' logged in", "Database backed up", "New item reported"]
    return render_template("it_logs.html", logs=logs)

@app.route("/it-admin/backup")
@login_required
def backup_db():
    if current_user.role != "it_admin":
        return redirect(url_for("dashboard"))
    # Logic for backup would go here
    flash("Database backup initiated successfully!")
    return redirect(url_for("it_dashboard"))

@app.route("/it-admin/permissions")
@login_required
def manage_permissions():
    if current_user.role != "it_admin":
        return redirect(url_for("dashboard"))
    users = User.query.all()
    return render_template("it_permissions.html", users=users)

# 1. Update the existing admin_dashboard route to fetch reports
@app.route("/admin-dashboard")
@login_required
def admin_dashboard():
    if current_user.role != "admin":
        flash("Unauthorized access!")
        return redirect(url_for("dashboard"))
    # Fetch all items to display in the admin table
    items = Item.query.all()
    return render_template("admin_dashboard.html", items=items)

# 2. Route to Mark a Report as Solved
@app.route("/admin/update/<int:item_id>", methods=["POST"])
@login_required
def update_report(item_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))
    
    item = Item.query.get_or_404(item_id)
    item.priority = 0  # We use 0 to represent 'Solved' in this logic
    db.session.commit()
    flash(f"Report '{item.title}' marked as solved.")
    return redirect(url_for("admin_dashboard"))

# 3. Route to Delete a Report
@app.route("/admin/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_report(item_id):
    if current_user.role != "admin":
        return redirect(url_for("dashboard"))
    
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    flash("Report deleted successfully.")
    return redirect(url_for("admin_dashboard"))

if __name__ == "__main__":
    app.run(debug=True)