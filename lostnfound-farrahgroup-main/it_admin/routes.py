from flask import render_template
from flask_login import login_required
from . import it_admin_bp
from utils.decorators import role_required   
from models import ActivityLog, SecurityLog
from models import LoginAttempt
from utils.security import detect_bruteforce
from flask import render_template
from flask_login import login_required
from utils.decorators import role_required
from models import ActivityLog, SecurityLog
from . import it_admin_bp

@it_admin_bp.route('/dashboard')
@login_required
@role_required('it_admin')
def dashboard():
    return render_template('it_admin/dashboard.html')

@it_admin_bp.route('/activity-logs')
@login_required
@role_required('it_admin')
def activity_logs():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('it_admin/activity_logs.html', logs=logs)

@it_admin_bp.route('/security-logs')
@login_required
@role_required('it_admin')
def security_logs():
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).all()
    return render_template('it_admin/security_logs.html', logs=logs)


@it_admin_bp.route('/dashboard')
@login_required
@role_required('it_admin')
def dashboard():
    return render_template('it_admin/dashboard.html')


@it_admin_bp.route('/activity-logs')
@login_required
@role_required('it_admin')
def activity_logs():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template('it_admin/activity_logs.html', logs=logs)


@it_admin_bp.route('/security-logs')
@login_required
@role_required('it_admin')
def security_logs():
    logs = SecurityLog.query.order_by(SecurityLog.timestamp.desc()).all()
    return render_template('it_admin/security_logs.html', logs=logs)
