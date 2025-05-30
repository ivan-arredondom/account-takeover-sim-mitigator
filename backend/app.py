"""
Account Takeover Detection and Mitigation System - Main Flask Application
"""

import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import redis
import geoip2.database
from loguru import logger
import json

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///ato_system.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-change-in-production')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Initialize Redis for rate limiting and session storage
try:
    redis_client = redis.Redis(
        host=os.environ.get('REDIS_HOST', 'localhost'),
        port=int(os.environ.get('REDIS_PORT', 6379)),
        db=0,
        decode_responses=True
    )
    redis_client.ping()  # Test connection
    logger.info("Redis connection established")
except Exception as e:
    logger.error(f"Redis connection failed: {e}")
    redis_client = None

# Initialize rate limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],
    storage_uri=f"redis://{os.environ.get('REDIS_HOST', 'localhost')}:{os.environ.get('REDIS_PORT', 6379)}"
)

# Enable CORS
CORS(app)

# Configure logging
logger.add("logs/ato_system.log", rotation="500 MB", level="INFO")

# Models
class User(db.Model):
    """User model for authentication"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    is_locked = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        """Required for Flask-Login"""
        return str(self.id)
    
    def is_authenticated(self):
        return True
    
    def is_anonymous(self):
        return False

class LoginAttempt(db.Model):
    """Model to track all login attempts for analysis"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 compatible
    user_agent = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, nullable=False)
    country = db.Column(db.String(10))
    city = db.Column(db.String(100))
    risk_score = db.Column(db.Float, default=0.0)
    blocked = db.Column(db.Boolean, default=False)
    mitigation_applied = db.Column(db.String(100))  # CAPTCHA, RATE_LIMIT, etc.
    
    def __repr__(self):
        return f'<LoginAttempt {self.username}@{self.ip_address}>'

class Session(db.Model):
    """Model to track active sessions"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Utility Functions
def get_client_ip():
    """Get client IP address, handling proxies"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr

def get_geolocation(ip_address):
    """Get geolocation data for IP address"""
    try:
        # You'll need to download GeoLite2 database
        # with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
        #     response = reader.city(ip_address)
        #     return {
        #         'country': response.country.iso_code,
        #         'city': response.city.name
        #     }
        # For now, return mock data
        return {'country': 'US', 'city': 'Unknown'}
    except Exception as e:
        logger.error(f"Geolocation lookup failed: {e}")
        return {'country': 'Unknown', 'city': 'Unknown'}

def calculate_risk_score(username, ip_address, user_agent):
    """Calculate risk score for login attempt"""
    risk_score = 0.0
    
    # Check for recent failed attempts from this IP
    recent_failures = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.success == False,
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=1)
    ).count()
    
    risk_score += min(recent_failures * 0.2, 1.0)
    
    # Check for geographic anomalies (simplified)
    user = User.query.filter_by(username=username).first()
    if user:
        recent_successful_login = LoginAttempt.query.filter(
            LoginAttempt.username == username,
            LoginAttempt.success == True,
            LoginAttempt.timestamp > datetime.utcnow() - timedelta(days=7)
        ).order_by(LoginAttempt.timestamp.desc()).first()
        
        if recent_successful_login:
            current_geo = get_geolocation(ip_address)
            if current_geo['country'] != recent_successful_login.country:
                risk_score += 0.3
    
    # Check for unusual time patterns (simplified)
    current_hour = datetime.utcnow().hour
    if current_hour < 6 or current_hour > 23:  # Late night/early morning
        risk_score += 0.1
    
    return min(risk_score, 1.0)

def apply_mitigation(risk_score, ip_address):
    """Apply mitigation measures based on risk score"""
    mitigation = None
    
    if risk_score > 0.7:
        # High risk - block IP temporarily
        if redis_client:
            redis_client.setex(f"blocked_ip:{ip_address}", 3600, "high_risk")  # 1 hour block
        mitigation = "IP_BLOCKED"
    elif risk_score > 0.4:
        # Medium risk - require CAPTCHA
        mitigation = "CAPTCHA_REQUIRED"
    elif risk_score > 0.2:
        # Low risk - rate limit
        mitigation = "RATE_LIMITED"
    
    return mitigation

# Routes
@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'redis_connected': redis_client is not None
    })

@app.route('/api/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    """User registration endpoint"""
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password') or not data.get('email'):
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'error': 'Username already exists'}), 409
    
    if User.query.filter_by(email=data['email']).first():
        return jsonify({'error': 'Email already exists'}), 409
    
    # Create new user
    user = User(
        username=data['username'],
        email=data['email']
    )
    user.set_password(data['password'])
    
    try:
        db.session.add(user)
        db.session.commit()
        logger.info(f"New user registered: {user.username}")
        return jsonify({'message': 'User created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration failed: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    """User login endpoint with ATO detection"""
    data = request.get_json()
    ip_address = get_client_ip()
    user_agent = request.headers.get('User-Agent', '')
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Missing credentials'}), 400
    
    username = data['username']
    password = data['password']
    
    # Check if IP is blocked
    if redis_client and redis_client.get(f"blocked_ip:{ip_address}"):
        logger.warning(f"Login attempt from blocked IP: {ip_address}")
        return jsonify({'error': 'Access temporarily blocked'}), 429
    
    # Calculate risk score
    risk_score = calculate_risk_score(username, ip_address, user_agent)
    
    # Get geolocation data
    geo_data = get_geolocation(ip_address)
    
    # Find user
    user = User.query.filter_by(username=username).first()
    
    # Attempt authentication
    login_success = False
    if user and not user.is_locked and user.check_password(password):
        login_success = True
        user.failed_login_attempts = 0
        user.last_failed_login = None
        login_user(user)
        
        # Create session token
        session_token = jwt.encode({
            'user_id': user.id,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['JWT_SECRET_KEY'], algorithm='HS256')
        
        # Store session
        session_obj = Session(
            user_id=user.id,
            session_token=session_token,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(session_obj)
    else:
        # Failed login
        if user:
            user.failed_login_attempts += 1
            user.last_failed_login = datetime.utcnow()
            
            # Lock account after 5 failed attempts
            if user.failed_login_attempts >= 5:
                user.is_locked = True
                logger.warning(f"Account locked: {username}")
    
    # Apply mitigation measures
    mitigation = apply_mitigation(risk_score, ip_address)
    
    # Log the attempt
    attempt = LoginAttempt(
        username=username,
        ip_address=ip_address,
        user_agent=user_agent,
        success=login_success,
        country=geo_data['country'],
        city=geo_data['city'],
        risk_score=risk_score,
        blocked=(mitigation == "IP_BLOCKED"),
        mitigation_applied=mitigation
    )
    db.session.add(attempt)
    
    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Database commit failed: {e}")
    
    # Return response based on mitigation
    if mitigation == "IP_BLOCKED":
        return jsonify({'error': 'Access temporarily blocked due to suspicious activity'}), 429
    elif mitigation == "CAPTCHA_REQUIRED":
        return jsonify({
            'error': 'CAPTCHA verification required',
            'captcha_required': True,
            'risk_score': risk_score
        }), 200
    elif not login_success:
        return jsonify({'error': 'Invalid credentials'}), 401
    else:
        return jsonify({
            'message': 'Login successful',
            'token': session_token,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'risk_score': risk_score
        }), 200

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    """User logout endpoint"""
    # Invalidate session in database
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        session_obj = Session.query.filter_by(session_token=token).first()
        if session_obj:
            session_obj.is_active = False
            db.session.commit()
    
    logout_user()
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats():
    """Get system statistics for dashboard"""
    # Recent login attempts
    recent_attempts = LoginAttempt.query.filter(
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).count()
    
    # Successful vs failed logins
    successful_logins = LoginAttempt.query.filter(
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=24),
        LoginAttempt.success == True
    ).count()
    
    failed_logins = recent_attempts - successful_logins
    
    # Top countries
    country_stats = db.session.query(
        LoginAttempt.country,
        db.func.count(LoginAttempt.id).label('count')
    ).filter(
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=24)
    ).group_by(LoginAttempt.country).order_by(db.desc('count')).limit(5).all()
    
    # High risk attempts
    high_risk_attempts = LoginAttempt.query.filter(
        LoginAttempt.timestamp > datetime.utcnow() - timedelta(hours=24),
        LoginAttempt.risk_score > 0.5
    ).count()
    
    return jsonify({
        'recent_attempts': recent_attempts,
        'successful_logins': successful_logins,
        'failed_logins': failed_logins,
        'high_risk_attempts': high_risk_attempts,
        'top_countries': [{'country': c[0], 'count': c[1]} for c in country_stats],
        'active_users': User.query.filter_by(is_active=True).count()
    })

# Database initialization
@app.before_first_request
def create_tables():
    """Create database tables"""
    db.create_all()
    logger.info("Database tables created")

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)