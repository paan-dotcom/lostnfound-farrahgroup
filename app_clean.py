import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

# 1. Load the variables from your .env file
load_dotenv()

# 2. Create the Flask app instance
app = Flask(__name__)

# 3. Configure the app
# Change these lines to use a simpler path
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lostnfound_clean.db' # Use this simple path
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 4. Initialize the extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False) 
    items = db.relationship('Item', backref='owner', lazy=True)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False) # lost or found
    title = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    contact_info = db.Column(db.String(100))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    user = db.relationship('User', backref='logs')

# --- HELPER FUNCTIONS ---

def log_event(action):
    u_id = current_user.id if current_user.is_authenticated else None
    new_log = AuditLog(
        user_id=u_id,
        action=action,
        ip_address=request.remote_addr
    )
    db.session.add(new_log)
    db.session.commit()

# --- ROUTES ---

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            log_event(f"User {user.username} logged in successfully")
            return redirect(url_for('home'))
        flash('Login failed. Check username and password.', 'danger')
    return render_template('login.html')

@app.route("/create", methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        username = request.form['username']
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        try:
            db.session.add(new_user)
            db.session.commit()
            log_event(f"New account created: {username}")
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Username already exists or error occurred.', 'danger')
    return render_template('create.html')

@app.route("/home")
@login_required
def home():
    search_txt = request.args.get('q', '').strip()
    status_val = request.args.get('status', '').lower()
    cat_val = request.args.get('category', '')

    query = Item.query

    if search_txt:
        query = query.filter(Item.title.ilike(f"%{search_txt}%") | Item.description.ilike(f"%{search_txt}%"))
    
    if status_val and status_val != 'all':
        query = query.filter(Item.type.ilike(f"%{status_val}%"))
        
    if cat_val and cat_val != 'all':
        query = query.filter(Item.category.ilike(f"%{cat_val.split(' / ')[0]}%"))

    items = query.order_by(Item.id.desc()).all()
    
    total_items_count = Item.query.count()
    lost_count = Item.query.filter_by(type='lost').count()
    found_count = Item.query.filter_by(type='found').count()

    return render_template('home.html', 
                           items=items, 
                           total=total_items_count, 
                           lost=lost_count, 
                           found=found_count)

@app.route("/report", methods=['GET', 'POST'])
@login_required 
def report():
    if request.method == 'POST':
        new_item = Item(
            type=request.form['type'],
            title=request.form['title'],
            category=request.form['category'],
            description=request.form['description'],
            location=request.form['location'],
            contact_info=request.form['contact'],
            owner_id=current_user.id
        )
        db.session.add(new_item)
        db.session.commit()
        log_event(f"Item Reported: {new_item.title} ({new_item.type}) by {current_user.username}")
        flash('Report submitted successfully!')
        return redirect(url_for('home'))
    return render_template('report.html')

@app.route("/admin/logs")
@login_required
def view_logs():
    if not current_user.is_admin:
        flash("Access Denied: Admins Only!")
        return redirect(url_for('home'))
    all_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template("admin_logs.html", logs=all_logs)

@app.route("/logout")
def logout():
    log_event(f"User {current_user.username} logged out")
    logout_user()
    return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(403)
def access_denied(e):
    return render_template('403.html'), 403

# --- MAIN BLOCK ---

if __name__ == "__main__":
    with app.app_context():
        if not os.path.exists('instance'):
            os.makedirs('instance')
        db.create_all()
        
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            hashed_pw = generate_password_hash('admin123', method='pbkdf2:sha256')
            new_admin = User(username='admin', password=hashed_pw, is_admin=True)
            db.session.add(new_admin)
            db.session.commit()
            print("Admin account created: User: admin | Pass: admin123")
            
    app.run(debug=True)