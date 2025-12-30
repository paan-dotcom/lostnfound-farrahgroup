# UniKL Lost & Found Secure System

## 1. Project Description
A secure web application for UniKL students to report and track lost/found items, featuring RBAC and Audit Logging.

## 2. Security Features (OWASP Compliance)
- **A01:2021-Broken Access Control**: Role-based access for Admins and Users.
- **A07:2021-Identification and Authentication Failures**: Secure password hashing using PBKDF2.
- **A09:2021-Security Logging and Monitoring**: Full Audit Log tracking user actions and IP addresses.

## 3. Installation & Run
1. Install dependencies: `pip install -r requirements.txt`
2. Set up `.env` file.
3. Run: `python app_clean.py`

## 4. Dependencies
- Flask, Flask-SQLAlchemy, Flask-Login, Python-Dotenv