from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from cryptography.fernet import Fernet, InvalidToken
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import html

os.makedirs('logs', exist_ok=True)

log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
file_handler = RotatingFileHandler('logs/app.log', maxBytes=2*1024*1024, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.INFO)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.handlers = []
logger.addHandler(file_handler)
logger.addHandler(console_handler)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', 'your-secret-key'),
    SQLALCHEMY_DATABASE_URI='sqlite:///users.db',
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600
)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
limiter = Limiter(app=app, key_func=get_remote_address)

talisman = Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self' 'unsafe-inline'",
    'style-src': "'self' 'unsafe-inline'",
    'img-src': "'self' data:",
    'font-src': "'self'",
    'form-action': "'self'",
    'frame-ancestors': "'none'",
    'base-uri': "'self'",
    'object-src': "'none'"
})

ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', b'1Qw1Qw2Qw3Qw4Qw5Qw6Qw7Qw8Qw9Qw0Qw1Qw2Qw3Qw4=')
fernet = Fernet(ENCRYPTION_KEY)

def sanitize_input(input_str):
    return html.escape(input_str.strip()) if input_str else None

def validate_username(username):
    if not username:
        return False, "Username is required"
    if not 3 <= len(username) <= 20:
        return False, "Username must be between 3 and 20 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, "Username is valid"

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Za-z]', password):
        return False, "Password must contain at least one letter"
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]', password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def encrypt_field(value):
    return fernet.encrypt(value.encode()).decode() if value else None

def decrypt_field(value):
    try:
        return fernet.decrypt(value.encode()).decode() if value else None
    except (InvalidToken, AttributeError):
        return None

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    full_name = db.Column(db.String(100))
    _bio = db.Column('bio', db.Text)
    _location = db.Column('location', db.String(100))
    _interests = db.Column('interests', db.String(200))

    @property
    def bio(self):
        return decrypt_field(self._bio)
    @bio.setter
    def bio(self, value):
        self._bio = encrypt_field(value)

    @property
    def location(self):
        return decrypt_field(self._location)
    @location.setter
    def location(self, value):
        self._location = encrypt_field(value)

    @property
    def interests(self):
        return decrypt_field(self._interests)
    @interests.setter
    def interests(self, value):
        self._interests = encrypt_field(value)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def register():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        is_valid_username, username_message = validate_username(username)
        if not is_valid_username:
            logger.warning(f"Registration failed: {username_message} (username: {username})")
            flash(username_message)
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            logger.warning(f"Registration failed: Username already exists ({username})")
            flash('Username already exists')
            return redirect(url_for('register'))
        
        is_valid, message = validate_password(password)
        if not is_valid:
            logger.warning(f"Registration failed: {message} (username: {username})")
            flash(message)
            return redirect(url_for('register'))
        
        try:
            user = User(username=username)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            logger.info(f"User registered successfully: {username}")
            flash('Registration successful!')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Registration error for {username}: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("20 per minute")
def login():
    if request.method == 'POST':
        username = sanitize_input(request.form.get('username'))
        password = request.form.get('password')
        
        if not username or not password:
            logger.warning("Login failed: Missing username or password")
            flash('Please provide both username and password')
            return redirect(url_for('login'))
        
        try:
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                login_user(user)
                logger.info(f"User logged in: {username}")
                return redirect(url_for('dashboard'))
            
            logger.warning(f"Login failed: Invalid credentials for {username}")
            flash('Invalid username or password')
        except Exception as e:
            logger.error(f"Login error for {username}: {str(e)}")
            flash('An error occurred during login. Please try again.')
    
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.full_name = sanitize_input(request.form.get('full_name'))
        current_user.bio = sanitize_input(request.form.get('bio'))
        current_user.location = sanitize_input(request.form.get('location'))
        current_user.interests = sanitize_input(request.form.get('interests'))
        try:
            db.session.commit()
            logger.info(f"Profile updated for user: {current_user.username}")
            flash('Profile updated successfully!')
        except Exception as e:
            db.session.rollback()
            logger.error(f"Profile update error for {current_user.username}: {str(e)}")
            flash('An error occurred while updating your profile.')
        return redirect(url_for('profile'))
    return render_template('profile.html')

@app.route('/user/<username>')
def user_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    return render_template('user_profile.html', user=user)

@app.errorhandler(404)
def not_found_error(error):
    logger.warning(f"404 Not Found: {request.path}")
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"500 Internal Server Error: {str(error)}")
    return render_template('500.html'), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning(f"Rate limit exceeded: {request.path}")
    return jsonify(error="Rate limit exceeded"), 429

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True,
        ssl_context=None
    ) 