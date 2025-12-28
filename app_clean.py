import os
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///lostnfound_clean.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# DATABASE MODELS
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ROUTES
@app.route("/")
@app.route("/login", methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('home'))
        flash('Login failed. Check username and password.', 'danger')
    return render_template('login.html')

@app.route("/create", methods=['GET', 'POST'])
def create():
    if request.method == 'POST':
        hashed_pw = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=request.form['username'], password=hashed_pw)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created! Please login.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Username already exists.', 'danger')
    return render_template('create.html')

@app.route("/home")
@login_required
def home():
    query = Item.query
    search_txt = request.args.get('search', '').strip()
    status_val = request.args.get('status', 'all')
    cat_val = request.args.get('category', 'all')

    if search_txt:
        query = query.filter(Item.title.ilike(f"%{search_txt}%") | Item.description.ilike(f"%{search_txt}%"))
    if status_val != 'all':
        query = query.filter(Item.type == status_val)
    if cat_val != 'all':
        query = query.filter(Item.category == cat_val)

    items = query.order_by(Item.id.desc()).all()
    
    # Stats
    total_items = Item.query.count()
    total_lost = Item.query.filter_by(type='lost').count()
    total_found = Item.query.filter_by(type='found').count()

    return render_template('home.html', user=current_user, items=items, 
                           total_items=total_items, total_lost=total_lost, total_found=total_found)

@app.route("/report", methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        new_item = Item(
            type=request.form['type'],
            title=request.form['title'],
            category=request.form['category'],
            location=request.form['location'],
            description=request.form['description'],
            contact_info=request.form['contact'],
            owner_id=current_user.id
        )
        db.session.add(new_item)
        db.session.commit()
        flash('Report submitted!', 'success')
        return redirect(url_for('home'))
    return render_template('report.html')

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        # This line ensures the folder and database are created automatically
        if not os.path.exists('instance'):
            os.makedirs('instance')
        db.create_all()
    app.run(debug=True)