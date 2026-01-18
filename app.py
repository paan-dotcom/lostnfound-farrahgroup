from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import re

app = Flask(__name__)

app.secret_key = "super_secret_key"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = "static/images"



os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)



db = SQLAlchemy(app)

login_manager = LoginManager(app)

login_manager.login_view = "login"



# --- Models ---

class User(db.Model, UserMixin):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(50), unique=True, nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user") 

    failed_attempts = db.Column(db.Integer, default=0)

    is_blocked = db.Column(db.Boolean, default=False)



class Item(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    type = db.Column(db.String(10)) 

    title = db.Column(db.String(100), nullable=False)

    category = db.Column(db.String(50))

    location = db.Column(db.String(100))

    description = db.Column(db.Text, nullable=False)

    contact = db.Column(db.String(100))

    image = db.Column(db.String(255))

    status = db.Column(db.String(20), default="Pending")

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))



class AuditLog(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    action = db.Column(db.String(255), nullable=False)

    ip_address = db.Column(db.String(50))

    user = db.relationship('User', backref='logs')



@login_manager.user_loader

def load_user(user_id):

    return User.query.get(int(user_id))



def log_event(action, user_id=None):

    new_log = AuditLog(action=action, user_id=user_id, ip_address=request.remote_addr)

    db.session.add(new_log)

    db.session.commit()



# --- Auth Routes ---



@app.route("/")

def home():

    return redirect(url_for('login'))



@app.route("/login", methods=["GET", "POST"])

def login():

    if request.method == "POST":

        user = User.query.filter_by(username=request.form.get("username")).first()

        if user:

            if user.is_blocked:

                log_event(f"Blocked User Login Attempt: {user.username}")

                flash("Account blocked. Please contact IT.")

                return render_template("login.html")

            

            if check_password_hash(user.password, request.form.get("password")):

                user.failed_attempts = 0

                db.session.commit()

                login_user(user)

                log_event("Login Success", user.id)

                if user.role == 'it_admin': return redirect(url_for('it_dashboard'))

                if user.role == 'admin': return redirect(url_for('admin_dashboard'))

                return redirect(url_for("user_dashboard"))

            else:

                user.failed_attempts += 1

                if user.failed_attempts >= 3: 

                    user.is_blocked = True

                    log_event(f"Account Locked (Brute Force): {user.username}")

                else:

                    log_event(f"Login Fail: {user.username}")

                db.session.commit()

        else:

            log_event(f"Unknown User Login Attempt: {request.form.get('username')}")

        

        flash("Invalid login credentials.")

    return render_template("login.html")



@app.route("/logout")
@login_required
def logout():
    log_event("User Logout", current_user.id)
    logout_user()
    return redirect(url_for('login'))

@app.route("/create", methods=["GET", "POST"])
def create_user():
    if request.method == "POST":

        # CAPTCHA CHECK (FIRST)
        captcha_token = request.form.get("h-captcha-response")
        if not captcha_token or not verify_hcaptcha(
            captcha_token,
            request.remote_addr
        ):
            log_event("Captcha Failed Registration Attempt")
            flash("Captcha verification failed. Please try again.")
            return render_template("create.html")

        # FORM DATA
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        # PASSWORD POLICY
        password_regex = r"^(?=.*[0-9])(?=.*[@#$%^&+=!]).{8,}$"
        if not re.match(password_regex, password):
            flash(
                "Password must be at least 8 characters long, include a number, and a special character (@#$%^&+=!).",
                "danger"
            )
            return render_template("create.html")

        # USER EXISTS CHECK
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("create.html")

        # CREATE USER
        hashed_pwd = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password=hashed_pwd
        )
        db.session.add(new_user)
        db.session.commit()

        log_event(f"New User Registered: {new_user.username}")
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("create.html")


# --- User Routes ---



@app.route("/dashboard")

@login_required

def user_dashboard():

    q = request.args.get('q')

    items = Item.query.filter(Item.user_id == current_user.id).all()

    if q:

        items = [i for i in items if q.lower() in i.title.lower()]

    return render_template("user_dashboard.html", items=items)



@app.route("/submit-report", methods=["GET", "POST"])

@login_required

def submit_report():

    if request.method == "POST":

        file = request.files.get("item_image")

        filename = secure_filename(file.filename) if file and file.filename != '' else None

        if filename:

            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        

        new_report = Item(

            type=request.form.get("type"), title=request.form.get("title"),

            category=request.form.get("category"), location=request.form.get("location"),

            description=request.form.get("description"), contact=request.form.get("contact"),

            image=filename, user_id=current_user.id

        )

        db.session.add(new_report)

        db.session.commit()

        log_event(f"New Report Submitted: {new_report.title}", current_user.id)

        return redirect(url_for("user_dashboard"))

    return render_template("report.html")



# --- Admin Routes ---



@app.route("/admin-dashboard")

@login_required

def admin_dashboard():

    if current_user.role != 'admin': return redirect(url_for('login'))

    items = Item.query.all()

    return render_template("admin_dashboard.html", items=items)



@app.route("/admin/solve/<int:item_id>")

@login_required

def solve_item(item_id):

    item = Item.query.get(item_id)

    if item:

        item.status = "Solved"

        db.session.commit()

        log_event(f"Item Mark Solved: {item.title}", current_user.id)

    return redirect(url_for('admin_dashboard'))



@app.route("/admin/delete/<int:item_id>")

@login_required

def delete_item(item_id):

    item = Item.query.get(item_id)

    if item:

        title = item.title

        db.session.delete(item)

        db.session.commit()

        log_event(f"Item Deleted: {title}", current_user.id)

    return redirect(url_for('admin_dashboard'))



# --- IT Admin Dashboard (Enhanced Monitoring) ---



@app.route("/it-dashboard")

@login_required

def it_dashboard():

    if current_user.role != 'it_admin': 

        return redirect(url_for('login'))

    

    # 1. Fetch Blocked Users

    blocked = User.query.filter_by(is_blocked=True).all()

    

    # 2. Get Activity Statistics

    login_count = AuditLog.query.filter(AuditLog.action.like('%Login Success%')).count()

    report_count = AuditLog.query.filter(AuditLog.action.like('%New Report%')).count()

    

    # 3. Detect Potential Attacks (e.g., any failed login attempts)

    attack_alerts = AuditLog.query.filter(AuditLog.action.like('%Login Fail%')).order_by(AuditLog.timestamp.desc()).limit(5).all()

    attack_count = AuditLog.query.filter(AuditLog.action.like('%Login Fail%')).count()



    # 4. Get Latest 10 General Logs for the "Live Feed"

    recent_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()



    return render_template("it_dashboard.html", 

                           users=blocked, 

                           login_count=login_count, 

                           report_count=report_count,

                           attack_count=attack_count,

                           attack_alerts=attack_alerts,

                           recent_logs=recent_logs)



@app.route("/it/unblock/<int:user_id>")

@login_required

def unblock_user(user_id):

    if current_user.role != 'it_admin': return redirect(url_for('login'))

    user = User.query.get(user_id)

    if user:

        user.is_blocked = False

        user.failed_attempts = 0

        db.session.commit()

        log_event(f"IT Admin unblocked user: {user.username}", current_user.id)

    return redirect(url_for('it_dashboard'))



@app.route("/it-logs")

@login_required

def it_logs():

    if current_user.role != 'it_admin': return redirect(url_for('login'))

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()

    return render_template("it_logs.html", logs=logs)



if __name__ == "__main__":

    with app.app_context():

        db.create_all()

    app.run(debug=True)

