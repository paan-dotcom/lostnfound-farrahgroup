from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    print("Resetting database...")
    # This wipes everything and applies the new schema (failed_attempts, is_blocked, etc.)
    db.drop_all() 
    db.create_all()
    
    # 1. Create IT Admin Account (Accesses Security Logs & Unblocking)
    it_admin = User(
        username='it_master', 
        email='it@unikl.edu.my', 
        password=generate_password_hash('ITadmin2026!'), 
        role='it_admin'
    )
    
    # 2. Create General Admin Account (Accesses Item Management)
    gen_admin = User(
        username='admin_user', 
        email='admin@unikl.edu.my', 
        password=generate_password_hash('Admin2026!'), 
        role='admin'
    )

    # 3. Create a Test Student Account
    test_user = User(
        username='student_test', 
        email='student@smail.unikl.edu.my', 
        password=generate_password_hash('Student2026!'), 
        role='user'
    )

    db.session.add_all([it_admin, gen_admin, test_user])
    db.session.commit()
    
    print("-" * 30)
    print("SUCCESS: Database reset and accounts created!")
    print(f"IT Admin:    it_master  / ITadmin2026!")
    print(f"Gen Admin:   admin_user / Admin2026!")
    print(f"Test User:   student_test / Student2026!")
    print("-" * 30)