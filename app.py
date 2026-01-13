from flask_sqlalchemy import SQLAlchemy
from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify, current_app, make_response
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_login import current_user
from datetime import timedelta
import os
from werkzeug.utils import secure_filename
from PIL import Image, ImageOps
import os
from werkzeug.utils import secure_filename
from io import BytesIO
from datetime import datetime, timedelta
import logging
logging.basicConfig(level=logging.DEBUG)

# Set a maximum image size and quality level for compression
MAX_IMAGE_SIZE = (800, 600)  # Max dimensions (width, height)
QUALITY = 85  # Image quality (0-100)

#'LostNFound.mysql.pythonanywhere-services.com', database='LostNFound$default', user='LostNFound', password='"*********"'

sql_host = "**.***.(ythonanywhere-services.com"
sql_user = "LostNFound"
sql_password = "*********"
sql_database = "LostNFound$default"

app = Flask(__name__)
from flask_sqlalchemy import SQLAlchemy

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lostnfound.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(10), nullable=False)  # lost or found
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = '/home/LostNFound/mysite/static/images'  
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg','webp'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)




def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@login_manager.user_loader
def load_user(user_id):
        return User.query.get(int(user_id))

    
# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        
         if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))

        flash('Invalid credentials!')
    return render_template('login.html')

@app.route('/continue_without_login', methods=['GET'])
def continue_without_login():
    user = User.query.filter_by(username='temp').first()
    if user:
        login_user(user)
        return redirect(url_for('dashboard'))

    flash('Temporary user does not exist!')
    return redirect(url_for('login'))

def get_items_from_db():
    return Item.query.order_by(Item.created_at.desc()).all()

def get_items_from_db_prior():
    return Item.query.order_by(Item.priority.desc()).all()


def is_admin(user_id):
    user = User.query.get(int(user_id))
    return user is not None and user.role == 'admin'


@app.route('/dashboard')
@login_required
def dashboard():
    items = get_items_from_db()
    items_prior = get_items_from_db_prior()
    total_lost = 0
    total_found = 0
    total_items = len(items)
    admin_status = is_admin(current_user.id)

    for i, item in enumerate(items):
        try:
            priority = int(item[5])
        except ValueError:
            priority = 0

        items[i] = list(item) 
        items[i][5] = priority


        if item[4] == 'lost':
            total_lost += 1
        elif item[4] == 'found':
            total_found += 1
    for i, item in enumerate(items_prior):
        try:
            priority = int(item[5])
        except ValueError:
            priority = 0

        items_prior[i] = list(item)  
        items_prior[i][5] = priority


    recent_items = items_prior[:10]

    return render_template('dashboard.html',
                           user=get_user_info(),
                           items=items,
                           total_items=total_items,
                           total_lost=total_lost,
                           total_found=total_found,
                           recent_items=recent_items,
                           admin_status=admin_status)

@app.route('/admin_dashboard')
def admin_dashboard():
    items = Item.query.order_by(Item.created_at.desc()).all()
    return render_template('admin_dashboard.html', items=items)

@app.route('/view_items')
def view_items():
    items = Item.query.order_by(Item.created_at.desc()).all()

    items_list = []

    for item in items:
        formatted_item = f'item name: *{item.title}*\n'
        formatted_item += f'desc: {item.description}\n'
        formatted_item += f'status: *{item.status}*\n'
        formatted_item += f'location: {item.location}\n'
        formatted_item += f'contact: {item.contact_info}\n'
        formatted_item += '------' * 10 + '\n'
        items_list.append(formatted_item)

    items_list.append("View all at website: http://127.0.0.1:5000/login")

    formatted_data = ''.join(items_list)

    return render_template('view_items.html', items=formatted_data)

@app.route('/modify_item/<int:item_id>', methods=['GET', 'POST'])
def modify_item(item_id):
    item = Item.query.get_or_404(item_id)

    if request.method == 'POST':
        item.title = request.form['name']
        item.description = request.form['description']
        item.priority = request.form['priority']
        item.category = request.form['category']
        item.status = request.form['status']
        item.location = request.form['location']
        item.contact_info = request.form['contact_info']

        image_file = request.files.get('image_path')
        if image_file and image_file.filename:
            image_filename = secure_filename(image_file.filename)
            upload_path = os.path.join('static/uploads', image_filename)
            image_file.save(upload_path)
            item.image = upload_path

        db.session.commit()

        flash("Item updated successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('modify_item.html', item=item)


@app.route('/delete_item/<int:item_id>', methods=['POST'])
def delete_item(item_id):
    item = Item.query.get_or_404(item_id)

    if item.image:
        image_path = os.path.join(item.image)
        if os.path.exists(image_path):
            os.remove(image_path)

    db.session.delete(item)
    db.session.commit()

    return redirect(url_for('admin_dashboard'))


@app.route('/fetch_items', methods=['GET'])
@login_required
def fetch_items():
    search = request.args.get('search', '').lower()
    category = request.args.get('category', 'all')
    status = request.args.get('status', 'all')
    sort_by = request.args.get('sort', 'priority')

    query = Item.query

    if category != 'all':
        query = query.filter(Item.category == category)

    if status != 'all':
        query = query.filter(Item.status == status)

    if search:
        query = query.filter(
            (Item.title.ilike(f"%{search}%")) |
            (Item.description.ilike(f"%{search}%"))
        )

    if sort_by == 'priority':
        query = query.order_by(Item.priority.desc())
    else:
        query = query.order_by(Item.created_at.desc())

    items = query.all()

    return jsonify([
        {
            "id": item.id,
            "title": item.title,
            "description": item.description,
            "category": item.category,
            "status": item.status,
            "priority": item.priority,
            "location": item.location,
            "contact_info": item.contact_info,
            "image": item.image
        }
        for item in items
    ])

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    # block temp user
    if current_user.username == 'temp':
        return render_template('create.html', temp_user=True)

    if request.method == 'POST':
        item = Item(
            priority=request.form['priority'],
            title=request.form['name'],
            description=request.form['description'],
            category=request.form['category'],
            status=request.form['status'],
            location=request.form['location'],
            contact_info=request.form['contact_info'],
            owner_id=current_user.id
        )

        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_folder = os.path.join('static', 'images')
            os.makedirs(upload_folder, exist_ok=True)
            image_path = os.path.join(upload_folder, filename)
            file.save(image_path)
            item.image = image_path

        db.session.add(item)
        db.session.commit()

        flash("Report successfully submitted!", "success")
        return redirect(url_for('dashboard'))

    return render_template('return.html')

@app.route('/show_locations')
@login_required
def show_locations():
    items = Item.query.all()

    lost_items = []
    for item in items:
        if item.latitude is not None and item.longitude is not None:
            lost_items.append([
                item.title,
                item.status,
                float(item.latitude),
                float(item.longitude),
                item.contact_info,
                item.image
            ])

    return render_template('show_locations.html', lost_items=lost_items)

@app.route('/create', methods=['GET', 'POST'])
def create():
    cookie_limit = request.cookies.get('rate_limit')

    if request.method == 'POST':
        if cookie_limit:
            last_request_time = datetime.strptime(cookie_limit, '%Y-%m-%d %H:%M:%S')
            if datetime.now() - last_request_time < timedelta(seconds=60):
                flash('You are being rate-limited. Please wait a minute before trying again.')
                return redirect(url_for('create'))

        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords don't match. Please try again.")
            return redirect(url_for('create'))

        # ✅ SQLite/SQLAlchemy check instead of MySQL cursor
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists. Please choose another one.")
            return redirect(url_for('create'))

        # ✅ SQLite/SQLAlchemy insert instead of MySQL INSERT
        new_user = User(username=username, password=password, role='user')
        db.session.add(new_user)
        db.session.commit()

        flash("Account created successfully! You can now log in.")

        response = make_response(redirect(url_for('login')))
        response.set_cookie(
            'rate_limit',
            datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            max_age=60  # 60 seconds
        )
        logging.debug("Setting rate-limit cookie.")
        return response

    return render_template('create.html')



@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = current_user

    posts = Item.query.filter_by(owner_id=user.id).all()

    if request.method == 'POST':
        post_id = request.form.get('post_id')
        if post_id:
            post = Item.query.filter_by(id=post_id, owner_id=user.id).first()
            if post:
                if post.image and os.path.exists(post.image):
                    os.remove(post.image)

                db.session.delete(post)
                db.session.commit()

                flash('Post deleted successfully', 'success')
                return redirect(url_for('profile'))

    return render_template('profile.html', user=user, posts=posts)
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def get_user_info():
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        if user:
            return {
                "id": user.id,
                "username": user.username,
                "role": user.role
            }
    return None

from it_admin import it_admin_bp
app.register_blueprint(it_admin_bp)

with app.app_context():
    db.create_all()

    it_admin = User.query.filter_by(username="itadmin").first()
    if not it_admin:
        it_admin = User(username="itadmin", role="it_admin")
        it_admin.set_password("StrongPass123")
        db.session.add(it_admin)
        db.session.commit()
        print("IT Admin created")

if __name__ == '__main__':
    app.run(debug=True)



