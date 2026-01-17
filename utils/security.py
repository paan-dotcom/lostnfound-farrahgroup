from flask import request
from flask_login import current_user
from models import ActivityLog
from app import db
from datetime import datetime, timedelta
from models import LoginAttempt
from models import SecurityLog


def detect_bruteforce(ip):
    ten_min_ago = datetime.utcnow() - timedelta(minutes=10)
    return LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > ten_min_ago
    ).count() >= 5


def log_activity(action):
    log = ActivityLog(
        user_id=current_user.id,
        role=current_user.role,
        action=action,
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent')
    )
    db.session.add(log)
    db.session.commit()

def detect_sql_injection(input_data):
    keywords = ["'", " OR ", "--", ";", "1=1"]
    return any(k.lower() in input_data.lower() for k in keywords)
