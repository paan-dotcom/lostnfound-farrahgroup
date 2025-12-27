from datetime import datetime # Fixes the NameError you had
from datetime import datetime
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
    category = db.Column(db.String(50))               # Form data needs this
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))              # Form data needs this
    contact_info = db.Column(db.String(100))          # Form data needs this
    image_path = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

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



@app.route("/report", methods=["GET", "POST"])
@login_required
def report():
    if request.method == "POST":
        new_item = Item(
            type=request.form["type"],
            title=request.form["title"],
            category=request.form["category"],
            location=request.form["location"],
            description=request.form["description"],
            contact_info=request.form["contact"],
            owner_id=current_user.id
        )

        db.session.add(new_item)
        db.session.commit()

        flash("Report submitted successfully!")
        # THIS LINE is the key. Make sure it matches your main page function name.
        return redirect(url_for("home")) 

    return render_template("report.html")




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
    # 1. Start with all items
    query = Item.query

    # 2. Get the filter values from the URL
    search_txt = request.args.get("search", "")
    status_val = request.args.get("status", "all")
    cat_val = request.args.get("category", "all")

    # 3. Apply filters if they aren't "all" or empty
    if search_txt:
        # Searches title OR description
        query = query.filter(Item.title.contains(search_txt) | Item.description.contains(search_txt))
    
    if status_val != "all":
        query = query.filter(Item.type == status_val)

    if cat_val != "all":
        query = query.filter(Item.category == cat_val)

    # 4. Get the results
    items = query.order_by(Item.id.desc()).all()
    
    # Stats for the top cards (Always show total count)
    total_items = Item.query.count()
    total_lost = Item.query.filter_by(type="lost").count()
    total_found = Item.query.filter_by(type="found").count()

    return render_template("home.html", 
                           user=current_user, 
                           items=items,
                           total_items=total_items,
                           total_lost=total_lost,
                           total_found=total_found)

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
