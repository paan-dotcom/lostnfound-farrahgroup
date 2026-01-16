from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, current_app, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import requests
import logging
import secrets
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# =====================================================
# Load Environment Variables
# =====================================================
load_dotenv()

# =====================================================
# App & Config
# =====================================================
app = Flask(__name__)

# ---------------- Core Configuration ----------------
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-secret-key-change-this"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ---------------- File Uploads ----------------
# Absolute path is safer than relative
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app.config["UPLOAD_FOLDER"] = os.path.join(
    BASE_DIR, "static", "images"
)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB

# Ensure upload directory exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

# ---------------- Session Configuration ----------------
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["SESSION_COOKIE_SECURE"] = False  # True in production (HTTPS)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_REFRESH_EACH_REQUEST"] = True
app.config["SESSION_COOKIE_NAME"] = "lostnfound_session"

# ---------------- Flask-Login Configuration ----------------
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)
app.config["REMEMBER_COOKIE_SECURE"] = False
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
app.config["REMEMBER_COOKIE_NAME"] = "lostnfound_remember"

# ---------------- Security Configuration ----------------
app.config["MAX_FAILED_LOGINS"] = 5
app.config["LOCK_TIME"] = timedelta(minutes=15)
app.config["EMAIL_TOKEN_EXPIRY"] = timedelta(hours=24)

# ---------------- Email Configuration ----------------
app.config["EMAIL_USER"] = os.environ.get("EMAIL_USER", "")
app.config["EMAIL_PASS"] = os.environ.get("EMAIL_PASS", "")
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

# ---------------- Constants ----------------
MAX_FAILED_LOGINS = app.config["MAX_FAILED_LOGINS"]
LOCK_TIME = app.config["LOCK_TIME"]
EMAIL_TOKEN_EXPIRY = app.config["EMAIL_TOKEN_EXPIRY"]

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------- Database ----------------
db = SQLAlchemy(app)


# =====================================================
# Login Manager
# =====================================================
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."
login_manager.refresh_view = "login"
login_manager.needs_refresh_message = "Please re-authenticate to access this page."
login_manager.session_protection = "strong"

# =====================================================
# hCaptcha
# =====================================================
HCAPTCHA_SITEKEY = "-"
HCAPTCHA_SECRET = "-"

def verify_hcaptcha(token):
    """Verify hCaptcha token"""
    if app.debug:
        logger.debug("Skipping captcha in debug mode")
        return True
    
    try:
        response = requests.post(
            "https://hcaptcha.com/siteverify",
            data={
                "secret": HCAPTCHA_SECRET,
                "response": token
            },
            timeout=5
        )
        result = response.json()
        return result.get("success", False)
    except requests.RequestException as e:
        logger.error(f"Captcha verification failed: {e}")
        return False

# =====================================================
# Models
# =====================================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    email_verified = db.Column(db.Boolean, default=False)
    email_token = db.Column(db.String(100))
    email_token_created = db.Column(db.DateTime)

    failed_logins = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.username}>"
    
    # Flask-Login required methods
    def get_id(self):
        return str(self.id)
    
    def is_active(self):
        return self.email_verified or True  # Change to just self.email_verified in production
    
    # Helper methods
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def lock_account(self, minutes=15):
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)
        db.session.commit()
    
    def unlock_account(self):
        self.locked_until = None
        self.failed_logins = 0
        db.session.commit()
    
    def is_locked(self):
        if self.locked_until:
            return datetime.utcnow() < self.locked_until
        return False
    
    def increment_failed_login(self):
        self.failed_logins += 1
        if self.failed_logins >= MAX_FAILED_LOGINS:
            self.lock_account()
        db.session.commit()
    
    def reset_failed_logins(self):
        self.failed_logins = 0
        self.locked_until = None
        db.session.commit()
    
    def verify_email(self):
        self.email_verified = True
        self.email_token = None
        self.email_token_created = None
        db.session.commit()
    
    # Class methods
    @classmethod
    def create_user(cls, username, email, password, email_verified=False):
        user = cls(
            username=username,
            email=email,
            password=generate_password_hash(password),
            email_verified=email_verified,
            created_at=datetime.utcnow()
        )
        db.session.add(user)
        db.session.commit()
        return user
    
    @classmethod
    def find_by_username(cls, username):
        return cls.query.filter_by(username=username).first()
    
    @classmethod
    def find_by_email(cls, email):
        return cls.query.filter_by(email=email).first()
    
    @classmethod
    def authenticate(cls, username_or_email, password):
        user = cls.find_by_username(username_or_email)
        if not user:
            user = cls.find_by_email(username_or_email)
        
        if user and user.check_password(password) and not user.is_locked():
            user.reset_failed_logins()
            return user
        elif user:
            user.increment_failed_login()
        
        return None


class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255))
    category = db.Column(db.String(50))
    location = db.Column(db.String(100))
    contact_info = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Item {self.title}>"

# =====================================================
# Helpers
# =====================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def send_verification_email(email, token):
    """Send verification email to user"""
    verify_url = url_for("verify_email", token=token, _external=True)
    
    msg = EmailMessage()
    msg["Subject"] = "Verify Your UniKL Lost & Found Account"
    msg["From"] = app.config["EMAIL_USER"]
    msg["To"] = email
    
    # Plain text version
    msg.set_content(f"""
Welcome to UniKL Lost & Found!

Please verify your email address by clicking the link below:
{verify_url}

This link will expire in 24 hours.

If you did not create this account, please ignore this email.

Best regards,
UniKL Lost & Found Team
""")
    
    # HTML version
    msg.add_alternative(f"""\
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
        .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
        .header {{ background-color: #0077b6; color: white; padding: 20px; text-align: center; }}
        .button {{ 
            display: inline-block; 
            background-color: #00b4d8; 
            color: white; 
            padding: 12px 24px; 
            text-decoration: none; 
            border-radius: 5px; 
            font-weight: bold;
            margin: 20px 0;
        }}
        .footer {{ 
            margin-top: 30px; 
            padding-top: 20px; 
            border-top: 1px solid #eee; 
            color: #666; 
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>UniKL Lost & Found</h1>
        </div>
        <h2>Welcome!</h2>
        <p>Please verify your email address to complete your account registration.</p>
        
        <a href="{verify_url}" class="button">Verify Email Address</a>
        
        <p>Or copy and paste this link into your browser:<br>
        <code>{verify_url}</code></p>
        
        <p>This verification link will expire in 24 hours.</p>
        
        <div class="footer">
            <p>If you did not create this account, please ignore this email.</p>
            <p>Best regards,<br>UniKL Lost & Found Team</p>
        </div>
    </div>
</body>
</html>
""", subtype='html')
    
    try:
        with smtplib.SMTP(app.config["MAIL_SERVER"], app.config["MAIL_PORT"]) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(app.config["EMAIL_USER"], app.config["EMAIL_PASS"])
            server.send_message(msg)
            logger.info(f"Verification email sent to {email} via port 587")
            
    except Exception as e:
        logger.error(f"Port 587 failed: {e}. Trying port 465...")
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(app.config["EMAIL_USER"], app.config["EMAIL_PASS"])
                server.send_message(msg)
                logger.info(f"Verification email sent to {email} via port 465")
        except Exception as e2:
            logger.error(f"Port 465 also failed: {e2}")
            raise Exception(f"Failed to send verification email: {e2}")

# =====================================================
# Routes
# =====================================================
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# ---------------- Login ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        logger.debug("User already authenticated, redirecting to dashboard")
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        captcha_token = request.form.get("h-captcha-response")
        
        logger.debug(f"Attempting login for: '{username}'")
        
        # Validate inputs
        if not username or not password:
            flash("Please fill in all fields")
            return redirect(url_for("login"))
        
        # Verify captcha
        if not verify_hcaptcha(captcha_token):
            flash("Captcha verification failed. Please try again.")
            return redirect(url_for("login"))
        
        # Authenticate user
        user = User.authenticate(username, password)
        
        if user:
            # Auto-verify for testing (remove in production)
            if not user.email_verified:
                logger.debug("Auto-verifying user for testing")
                user.verify_email()
            
            # Login user
            login_user(user, remember=True)
            
            # Force session save
            session.modified = True
            session.permanent = True
            
            logger.debug(f"Login successful for user ID: {user.id}")
            logger.debug(f"Session contents: {dict(session)}")
            
            flash("Login successful!")
            
            # Check for next parameter
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password")
            return redirect(url_for("login"))
    
    return render_template("login.html", hcaptcha_sitekey=HCAPTCHA_SITEKEY)

# ---------------- Register ----------------
@app.route("/create", methods=["GET", "POST"])
def create():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        captcha_token = request.form.get("h-captcha-response")
        
        logger.debug(f"Registration attempt - Username: '{username}', Email: '{email}'")
        
        # Validate inputs
        if not all([username, email, password, confirm]):
            flash("Please fill in all fields")
            return redirect(url_for("create"))
        
        # Verify captcha
        if not verify_hcaptcha(captcha_token):
            flash("Captcha verification failed")
            return redirect(url_for("create"))
        
        # Validate email format
        if "@" not in email or "." not in email:
            flash("Please enter a valid email address")
            return redirect(url_for("create"))
        
        # Check password match
        if password != confirm:
            flash("Passwords do not match")
            return redirect(url_for("create"))
        
        # Check password strength
        if len(password) < 8:
            flash("Password must be at least 8 characters long")
            return redirect(url_for("create"))
        
        # Check if username/email already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if existing_user:
            flash("Username or email already exists")
            return redirect(url_for("create"))
        
        # Create verification token
        verify_token = secrets.token_urlsafe(32)
        
        # Create new user
        try:
            user = User.create_user(
                username=username,
                email=email,
                password=password,
                email_verified=True  # Auto-verify for testing
            )
            
            # Set email token for verification
            user.email_token = verify_token
            user.email_token_created = datetime.utcnow()
            db.session.commit()
            
            logger.debug(f"User created with ID: {user.id}")
            logger.debug(f"Password hash: {user.password[:50]}...")
            
            # Skip email for testing
            # send_verification_email(email, verify_token)
            
            flash("Account created! You can now login.")
            return redirect(url_for("login"))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating user: {e}")
            flash("An error occurred. Please try again.")
            return redirect(url_for("create"))
    
    return render_template("create.html", hcaptcha_sitekey=HCAPTCHA_SITEKEY)

# ---------------- Email Verify ----------------
@app.route("/verify/<token>")
def verify_email(token):
    user = User.query.filter_by(email_token=token).first()
    
    if not user:
        flash("Invalid or expired verification link")
        return redirect(url_for("login"))
    
    # Check if token is expired
    if datetime.utcnow() - user.email_token_created > EMAIL_TOKEN_EXPIRY:
        flash("Verification link has expired. Please request a new one.")
        return redirect(url_for("resend_verification"))
    
    # Verify user
    user.verify_email()
    
    flash("Email verified successfully! You may now log in.")
    return redirect(url_for("login"))

# ---------------- Resend Verification ----------------
@app.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        
        if not email:
            flash("Please enter your email address")
            return redirect(url_for("resend_verification"))
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash("Email not found")
            return redirect(url_for("resend_verification"))
        
        if user.email_verified:
            flash("Email is already verified")
            return redirect(url_for("login"))
        
        # Create new token
        user.email_token = secrets.token_urlsafe(32)
        user.email_token_created = datetime.utcnow()
        db.session.commit()
        
        # Send new verification email
        send_verification_email(user.email, user.email_token)
        
        flash("Verification email has been resent. Please check your inbox.")
        return redirect(url_for("login"))
    
    return render_template("resend_verification.html")

# ---------------- Dashboard ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    logger.debug(f"Dashboard accessed by user ID: {current_user.id}")
    logger.debug(f"User authenticated: {current_user.is_authenticated}")
    
    items = Item.query.order_by(Item.created_at.desc()).all()
    logger.debug(f"Found {len(items)} items")
    return render_template("dashboard.html", items=items)
    
 # ---------------- Show Locations ----------------
@app.route("/locations")
@login_required
def show_locations():
    return render_template("locations.html")

@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        try:
            image_file = request.files.get("image")
            image_path = None

            # ---------- IMAGE UPLOAD ----------
            if image_file and image_file.filename:
                if not allowed_file(image_file.filename):
                    flash("Only JPG and PNG images are allowed")
                    return redirect(url_for("report"))

                filename = secure_filename(image_file.filename)

                # ensure upload folder exists
                os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                image_file.save(save_path)

                # store relative path for /static
                image_path = f"images/{filename}"

            # ---------- SAVE ITEM ----------
            item = Item(
                type=request.form.get("type"),
                title=request.form.get("title"),
                description=request.form.get("description"),
                category=request.form.get("category"),
                location=request.form.get("location"),
                contact_info=request.form.get("contact_info"),
                image=image_path,
                owner_id=current_user.id
            )

            db.session.add(item)
            db.session.commit()

            flash("Item reported successfully!")
            return redirect(url_for("dashboard"))

        except Exception:
            db.session.rollback()
            logger.exception("Error reporting item")
            flash("Error reporting item. Please try again.")
            return redirect(url_for("report"))

    return render_template("report.html")

# ---------------- Edit Item ----------------
@app.route("/edit/<int:item_id>", methods=["GET", "POST"])
@login_required
def edit_item(item_id):
    item = Item.query.filter_by(id=item_id, owner_id=current_user.id).first()
    
    if not item:
        flash("Item not found or you don't have permission to edit it")
        return redirect(url_for("profile"))
    
    if request.method == "POST":
        item.title = request.form.get("title", "")
        item.description = request.form.get("description", "")
        item.location = request.form.get("location", "")
        item.contact_info = request.form.get("contact_info", "")
        db.session.commit()
        flash("Item updated successfully")
        return redirect(url_for("profile"))
    
    return render_template("edit_item.html", item=item)

# ---------------- Profile ----------------
@app.route("/profile")
@login_required
def profile():
    posts = Item.query.filter_by(owner_id=current_user.id).order_by(Item.created_at.desc()).all()
    return render_template("profile.html", posts=posts)

# ---------------- Delete Post ----------------
@app.route("/delete-post/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):
    post = Item.query.filter_by(id=post_id, owner_id=current_user.id).first()
    
    if not post:
        flash("Post not found or you don't have permission to delete it")
        return redirect(url_for("profile"))
    
    try:
        db.session.delete(post)
        db.session.commit()
        flash("Post deleted successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting post: {e}")
        flash("Error deleting post")
    
    return redirect(url_for("profile"))

# ---------------- Logout ----------------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out")
    return redirect(url_for("login"))

# ---------------- Debug Routes ----------------
@app.route("/test-email")
def test_email():
    """Test email sending"""
    try:
        test_token = secrets.token_urlsafe(32)
        send_verification_email("test@example.com", test_token)
        return "Email function ran successfully. Check server logs."
    except Exception as e:
        return f"Email error: {str(e)}"

@app.route("/test-auth")
def test_auth():
    """Test authentication status"""
    return {
        'is_authenticated': current_user.is_authenticated,
        'user_id': current_user.id if current_user.is_authenticated else None,
        'username': current_user.username if current_user.is_authenticated else None,
        'email': current_user.email if current_user.is_authenticated else None,
        'session': dict(session)
    }

@app.route("/debug/users")
def debug_users():
    """Debug: Show all users"""
    if not app.debug:
        return "Debug route only available in debug mode", 403
    
    users = User.query.all()
    result = "<h1>Users in Database:</h1><ul>"
    for user in users:
        result += f"<li>ID: {user.id}, Username: {user.username}, Email: {user.email}, Verified: {user.email_verified}</li>"
    result += f"</ul><p>Total: {len(users)} users</p>"
    return result

# =====================================================
# Error Handlers
# =====================================================
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# =====================================================
# Run
# =====================================================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        logger.info("Database tables created/verified")
        logger.info(f"App running in debug mode: {app.debug}")
        logger.info(f"Session cookie secure: {app.config['SESSION_COOKIE_SECURE']}")
    
    app.run(debug=True, host="0.0.0.0", port=5000)
