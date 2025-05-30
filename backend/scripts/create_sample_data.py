#!/usr/bin/env python3
"""
Sample Data Creation Script for ATO Detection System
Creates test users and sample login attempts for demonstration purposes.
"""

import sys
import os
from datetime import datetime, timedelta
import random

# Add parent directory to path to import app modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User, LoginAttempt, Session
from werkzeug.security import generate_password_hash

def create_sample_users():
    """Create sample users for testing"""
    sample_users = [
        {
            'username': 'admin',
            'email': 'admin@example.com',
            'password': 'admin123'
        },
        {
            'username': 'user1',
            'email': 'user1@example.com', 
            'password': 'password123'
        },
        {
            'username': 'test_user',
            'email': 'test@example.com',
            'password': 'testpass123'
        },
        {
            'username': 'demo',
            'email': 'demo@example.com',
            'password': 'demo123'
        },
        {
            'username': 'security_analyst',
            'email': 'analyst@example.com',
            'password': 'analyst123'
        }
    ]
    
    created_users = []
    
    for user_data in sample_users:
        # Check if user already exists
        existing_user = User.query.filter_by(username=user_data['username']).first()
        if existing_user:
            print(f"User {user_data['username']} already exists, skipping...")
            continue
            
        # Create new user
        user = User(
            username=user_data['username'],
            email=user_data['email']
        )
        user.set_password(user_data['password'])
        
        db.session.add(user)
        created_users.append(user)
        print(f"Created user: {user_data['username']}")
    
    try:
        db.session.commit()
        print(f"Successfully created {len(created_users)} users")
        return created_users
    except Exception as e:
        db.session.rollback()
        print(f"Error creating users: {e}")
        return []

def create_sample_login_attempts():
    """Create sample login attempts for dashboard demonstration"""
    
    # Get existing users
    users = User.query.all()
    if not users:
        print("No users found. Creating sample users first...")
        users = create_sample_users()
    
    # Sample IP addresses (mix of legitimate and suspicious)
    sample_ips = [
        '192.168.1.100',    # Local network
        '192.168.1.101',    # Local network  
        '10.0.0.50',        # Local network
        '203.0.113.45',     # Suspicious foreign IP
        '198.51.100.23',    # Suspicious foreign IP
        '192.0.2.67',       # Suspicious foreign IP
        '172.16.0.10',      # Corporate network
        '8.8.8.8',          # Google DNS (suspicious for login)
        '1.1.1.1',          # Cloudflare DNS (suspicious for login)
    ]
    
    # Sample countries/cities
    geo_data = [
        ('US', 'New York'),
        ('US', 'San Francisco'),
        ('US', 'Chicago'),
        ('CN', 'Beijing'),
        ('RU', 'Moscow'),
        ('BR', 'São Paulo'),
        ('IN', 'Mumbai'),
        ('DE', 'Berlin'),
        ('GB', 'London'),
    ]
    
    # Sample user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15',
        'Python-requests/2.25.1',  # Bot-like user agent
        'curl/7.68.0',             # Bot-like user agent
    ]
    
    # Mitigation types
    mitigations = ['NONE', 'CAPTCHA_REQUIRED', 'RATE_LIMITED', 'IP_BLOCKED']
    
    sample_attempts = []
    
    # Generate login attempts for the last 7 days
    end_time = datetime.utcnow()
    start_time = end_time - timedelta(days=7)
    
    # Create 500-1000 login attempts
    num_attempts = random.randint(500, 1000)
    
    for i in range(num_attempts):
        # Random timestamp within the last 7 days
        random_time = start_time + timedelta(
            seconds=random.randint(0, int((end_time - start_time).total_seconds()))
        )
        
        # Choose random user (80% legitimate users, 20% random usernames)
        if random.random() < 0.8 and users:
            username = random.choice(users).username
            # Legitimate users have higher success rate
            success_rate = 0.85
        else:
            # Random/non-existent usernames (credential stuffing attempts)
            fake_usernames = ['root', 'administrator', 'guest', 'test123', 'admin123', 'user123', 'hacker']
            username = random.choice(fake_usernames)
            success_rate = 0.05  # Very low success rate for fake usernames
        
        # Determine if login was successful
        success = random.random() < success_rate
        
        # Choose IP and geo data
        ip_address = random.choice(sample_ips)
        country, city = random.choice(geo_data)
        
        # Calculate risk score (higher for foreign IPs, failed attempts, etc.)
        risk_score = 0.0
        if country not in ['US']:
            risk_score += 0.3
        if not success:
            risk_score += 0.2
        if ip_address in ['203.0.113.45', '198.51.100.23', '192.0.2.67']:
            risk_score += 0.4
        if 'Python' in random.choice(user_agents) or 'curl' in random.choice(user_agents):
            risk_score += 0.3
        
        # Add some randomness
        risk_score += random.uniform(-0.1, 0.2)
        risk_score = max(0.0, min(1.0, risk_score))  # Clamp between 0 and 1
        
        # Choose mitigation based on risk score
        if risk_score > 0.7:
            mitigation = 'IP_BLOCKED'
            blocked = True
        elif risk_score > 0.5:
            mitigation = random.choice(['CAPTCHA_REQUIRED', 'RATE_LIMITED'])
            blocked = False
        elif risk_score > 0.3:
            mitigation = 'RATE_LIMITED'
            blocked = False
        else:
            mitigation = 'NONE'
            blocked = False
        
        attempt = LoginAttempt(
            username=username,
            ip_address=ip_address,
            user_agent=random.choice(user_agents),
            timestamp=random_time,
            success=success,
            country=country,
            city=city,
            risk_score=round(risk_score, 3),
            blocked=blocked,
            mitigation_applied=mitigation
        )
        
        sample_attempts.append(attempt)
        db.session.add(attempt)
    
    try:
        db.session.commit()
        print(f"Successfully created {len(sample_attempts)} sample login attempts")
        
        # Print some statistics
        successful = sum(1 for a in sample_attempts if a.success)
        failed = len(sample_attempts) - successful
        high_risk = sum(1 for a in sample_attempts if a.risk_score > 0.5)
        blocked = sum(1 for a in sample_attempts if a.blocked)
        
        print(f"Statistics:")
        print(f"  Total attempts: {len(sample_attempts)}")
        print(f"  Successful: {successful}")
        print(f"  Failed: {failed}")
        print(f"  High risk: {high_risk}")
        print(f"  Blocked: {blocked}")
        
    except Exception as e:
        db.session.rollback()
        print(f"Error creating sample attempts: {e}")

def create_sample_sessions():
    """Create sample active sessions"""
    users = User.query.all()
    if not users:
        print("No users found for session creation")
        return
    
    # Create 5-10 active sessions
    num_sessions = random.randint(5, 10)
    
    for i in range(num_sessions):
        user = random.choice(users)
        
        session = Session(
            user_id=user.id,
            session_token=f"sample_token_{i}_{random.randint(1000, 9999)}",
            ip_address=random.choice(['192.168.1.100', '192.168.1.101', '10.0.0.50']),
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 12)),
            last_activity=datetime.utcnow() - timedelta(minutes=random.randint(1, 60)),
            is_active=True
        )
        
        db.session.add(session)
    
    try:
        db.session.commit()
        print(f"Successfully created {num_sessions} sample sessions")
    except Exception as e:
        db.session.rollback()
        print(f"Error creating sample sessions: {e}")

def main():
    """Main function to create all sample data"""
    print("Creating sample data for ATO Detection System...")
    print("=" * 50)
    
    with app.app_context():
        # Create tables if they don't exist
        db.create_all()
        
        # Create sample data
        create_sample_users()
        print()
        create_sample_login_attempts()
        print()
        create_sample_sessions()
        
        print("=" * 50)
        print("Sample data creation completed!")
        print("\nYou can now:")
        print("1. Start the Flask application: python app.py")
        print("2. View the dashboard at: http://localhost:3000")
        print("3. Run attack simulations to generate more data")
        print("\nSample login credentials:")
        print("  admin / admin123")
        print("  user1 / password123")
        print("  demo / demo123")

if __name__ == "__main__":
    main()