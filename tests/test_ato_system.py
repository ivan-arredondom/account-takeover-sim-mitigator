#!/usr/bin/env python3
"""
Comprehensive test suite for Account Takeover Detection and Mitigation System
"""

import unittest
import json
import time
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app, db, User, LoginAttempt, Session
import redis

class ATOSystemTestCase(unittest.TestCase):
    """Base test case for ATO system"""
    
    def setUp(self):
        """Set up test client and database"""
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        
        db.create_all()
        
        # Create test user
        self.test_user = User(
            username='testuser',
            email='test@example.com'
        )
        self.test_user.set_password('testpass123')
        db.session.add(self.test_user)
        db.session.commit()
    
    def tearDown(self):
        """Clean up after tests"""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

class AuthenticationTests(ATOSystemTestCase):
    """Test authentication functionality"""
    
    def test_user_registration(self):
        """Test user registration endpoint"""
        response = self.app.post('/api/register', 
            data=json.dumps({
                'username': 'newuser',
                'email': 'newuser@example.com',
                'password': 'newpass123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('message', data)
        
        # Verify user was created in database
        user = User.query.filter_by(username='newuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'newuser@example.com')
    
    def test_duplicate_user_registration(self):
        """Test that duplicate usernames are rejected"""
        response = self.app.post('/api/register',
            data=json.dumps({
                'username': 'testuser',  # Already exists
                'email': 'duplicate@example.com',
                'password': 'password123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 409)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_successful_login(self):
        """Test successful login"""
        response = self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'testpass123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('token', data)
        self.assertIn('user', data)
        self.assertEqual(data['user']['username'], 'testuser')
    
    def test_failed_login(self):
        """Test login with wrong password"""
        response = self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'wrongpassword'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 401)
        data = json.loads(response.data)
        self.assertIn('error', data)
    
    def test_login_attempt_logging(self):
        """Test that login attempts are logged"""
        # Clear existing attempts
        LoginAttempt.query.delete()
        db.session.commit()
        
        # Make login attempt
        self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'testpass123'
            }),
            content_type='application/json'
        )
        
        # Check if attempt was logged
        attempt = LoginAttempt.query.first()
        self.assertIsNotNone(attempt)
        self.assertEqual(attempt.username, 'testuser')
        self.assertTrue(attempt.success)

class RiskCalculationTests(ATOSystemTestCase):
    """Test risk calculation and scoring"""
    
    def test_risk_score_calculation(self):
        """Test that risk scores are calculated correctly"""
        # Import risk calculation function
        from app import calculate_risk_score
        
        # Test low risk scenario
        risk_score = calculate_risk_score('testuser', '192.168.1.100', 'Normal User Agent')
        self.assertGreaterEqual(risk_score, 0.0)
        self.assertLessEqual(risk_score, 1.0)
        
        # Risk score should be calculated (exact value depends on implementation)
        self.assertIsInstance(risk_score, float)
    
    def test_failed_attempt_risk_increase(self):
        """Test that failed attempts increase risk score"""
        from app import calculate_risk_score
        
        ip_address = '192.168.1.100'
        
        # Create failed login attempts
        for i in range(3):
            attempt = LoginAttempt(
                username='testuser',
                ip_address=ip_address,
                user_agent='Test Agent',
                timestamp=datetime.utcnow(),
                success=False,
                risk_score=0.2
            )
            db.session.add(attempt)
        db.session.commit()
        
        # Calculate risk score - should be higher due to failed attempts
        risk_score = calculate_risk_score('testuser', ip_address, 'Test Agent')
        self.assertGreater(risk_score, 0.0)

class MitigationTests(ATOSystemTestCase):
    """Test mitigation measures"""
    
    def test_mitigation_application(self):
        """Test that mitigation measures are applied correctly"""
        from app import apply_mitigation
        
        # Test high risk mitigation
        mitigation = apply_mitigation(0.8, '192.168.1.100')
        self.assertEqual(mitigation, 'IP_BLOCKED')
        
        # Test medium risk mitigation
        mitigation = apply_mitigation(0.5, '192.168.1.101')
        self.assertEqual(mitigation, 'CAPTCHA_REQUIRED')
        
        # Test low risk mitigation
        mitigation = apply_mitigation(0.3, '192.168.1.102')
        self.assertEqual(mitigation, 'RATE_LIMITED')
        
        # Test no mitigation needed
        mitigation = apply_mitigation(0.1, '192.168.1.103')
        self.assertIsNone(mitigation)
    
    def test_account_lockout(self):
        """Test account lockout after multiple failed attempts"""
        # Make 5 failed login attempts
        for i in range(5):
            response = self.app.post('/api/login',
                data=json.dumps({
                    'username': 'testuser',
                    'password': 'wrongpassword'
                }),
                content_type='application/json'
            )
            self.assertEqual(response.status_code, 401)
        
        # Check if account is locked
        user = User.query.filter_by(username='testuser').first()
        self.assertTrue(user.is_locked)
        
        # Try to login with correct password - should fail due to lockout
        response = self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'testpass123'
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 401)

class RateLimitingTests(ATOSystemTestCase):
    """Test rate limiting functionality"""
    
    def test_rate_limiting(self):
        """Test that rate limiting works correctly"""
        # Make multiple rapid requests
        responses = []
        for i in range(15):  # Exceeds 10 per minute limit
            response = self.app.post('/api/login',
                data=json.dumps({
                    'username': 'testuser',
                    'password': 'testpass123'
                }),
                content_type='application/json'
            )
            responses.append(response.status_code)
        
        # At least some requests should be rate limited (429)
        rate_limited_count = responses.count(429)
        self.assertGreater(rate_limited_count, 0, "Rate limiting should have triggered")

class StatisticsTests(ATOSystemTestCase):
    """Test statistics and reporting functionality"""
    
    def test_stats_endpoint(self):
        """Test statistics endpoint"""
        # Create some test data
        self.create_test_login_attempts()
        
        # Login first to get access
        login_response = self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'testpass123'
            }),
            content_type='application/json'
        )
        token = json.loads(login_response.data)['token']
        
        # Get statistics
        response = self.app.get('/api/stats',
            headers={'Authorization': f'Bearer {token}'}
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # Check that required fields are present
        required_fields = ['recent_attempts', 'successful_logins', 'failed_logins', 
                          'high_risk_attempts', 'top_countries', 'active_users']
        for field in required_fields:
            self.assertIn(field, data)
    
    def create_test_login_attempts(self):
        """Helper method to create test login attempts"""
        # Create various types of login attempts
        attempts_data = [
            {'username': 'testuser', 'success': True, 'country': 'US', 'risk_score': 0.1},
            {'username': 'testuser', 'success': False, 'country': 'CN', 'risk_score': 0.7},
            {'username': 'admin', 'success': False, 'country': 'RU', 'risk_score': 0.8},
            {'username': 'root', 'success': False, 'country': 'US', 'risk_score': 0.6},
        ]
        
        for attempt_data in attempts_data:
            attempt = LoginAttempt(
                username=attempt_data['username'],
                ip_address='192.168.1.100',
                user_agent='Test Agent',
                timestamp=datetime.utcnow(),
                success=attempt_data['success'],
                country=attempt_data['country'],
                city='Test City',
                risk_score=attempt_data['risk_score']
            )
            db.session.add(attempt)
        
        db.session.commit()

class SecurityTests(ATOSystemTestCase):
    """Test security features and vulnerabilities"""
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed"""
        user = User.query.filter_by(username='testuser').first()
        
        # Password should not be stored in plain text
        self.assertNotEqual(user.password_hash, 'testpass123')
        
        # Should be able to verify correct password
        self.assertTrue(user.check_password('testpass123'))
        
        # Should reject incorrect password
        self.assertFalse(user.check_password('wrongpassword'))
    
    def test_sql_injection_protection(self):
        """Test protection against SQL injection attacks"""
        # Attempt SQL injection in username field
        malicious_payload = "'; DROP TABLE users; --"
        
        response = self.app.post('/api/login',
            data=json.dumps({
                'username': malicious_payload,
                'password': 'anypassword'
            }),
            content_type='application/json'
        )
        
        # Should not crash and users table should still exist
        self.assertIn(response.status_code, [400, 401])
        users_count = User.query.count()
        self.assertGreater(users_count, 0)
    
    def test_xss_protection(self):
        """Test protection against XSS attacks"""
        xss_payload = "<script>alert('xss')</script>"
        
        response = self.app.post('/api/register',
            data=json.dumps({
                'username': xss_payload,
                'email': 'xss@example.com',
                'password': 'password123'
            }),
            content_type='application/json'
        )
        
        # Should handle malicious input gracefully
        self.assertIn(response.status_code, [400, 409])

class GeolocationTests(ATOSystemTestCase):
    """Test geolocation functionality"""
    
    def test_geolocation_data_capture(self):
        """Test that geolocation data is captured for login attempts"""
        response = self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'testpass123'
            }),
            content_type='application/json',
            headers={'X-Forwarded-For': '203.0.113.45'}  # Mock foreign IP
        )
        
        # Check if geolocation was captured
        attempt = LoginAttempt.query.filter_by(username='testuser').first()
        self.assertIsNotNone(attempt)
        self.assertIsNotNone(attempt.country)

class PerformanceTests(ATOSystemTestCase):
    """Test system performance under load"""
    
    def test_concurrent_login_handling(self):
        """Test handling of concurrent login requests"""
        import threading
        import time
        
        results = []
        
        def make_login_request():
            response = self.app.post('/api/login',
                data=json.dumps({
                    'username': 'testuser',
                    'password': 'testpass123'
                }),
                content_type='application/json'
            )
            results.append(response.status_code)
        
        # Create 10 concurrent threads
        threads = []
        for i in range(10):
            thread = threading.Thread(target=make_login_request)
            threads.append(thread)
        
        # Start all threads
        start_time = time.time()
        for thread in threads:
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        end_time = time.time()
        
        # All requests should complete within reasonable time
        self.assertLess(end_time - start_time, 5.0)  # 5 seconds max
        
        # Most requests should succeed (some may be rate limited)
        success_count = results.count(200)
        self.assertGreater(success_count, 0)

class IntegrationTests(ATOSystemTestCase):
    """Integration tests for complete workflows"""
    
    def test_complete_attack_detection_workflow(self):
        """Test complete workflow from attack to detection to mitigation"""
        
        # Step 1: Simulate credential stuffing attack
        common_passwords = ['password', '123456', 'admin', 'qwerty']
        
        for password in common_passwords:
            response = self.app.post('/api/login',
                data=json.dumps({
                    'username': 'admin',  # Common target username
                    'password': password
                }),
                content_type='application/json',
                headers={'X-Forwarded-For': '203.0.113.45'}  # Foreign IP
            )
            # Most should fail
            self.assertIn(response.status_code, [401, 429])
        
        # Step 2: Check that attempts were logged with appropriate risk scores
        attempts = LoginAttempt.query.filter_by(username='admin').all()
        self.assertGreater(len(attempts), 0)
        
        # Step 3: Verify risk scores are calculated
        high_risk_attempts = [a for a in attempts if a.risk_score > 0.5]
        self.assertGreater(len(high_risk_attempts), 0)
        
        # Step 4: Verify mitigation was applied
        mitigated_attempts = [a for a in attempts if a.mitigation_applied != 'NONE']
        self.assertGreater(len(mitigated_attempts), 0)
    
    def test_legitimate_user_workflow(self):
        """Test that legitimate users are not impacted by security measures"""
        
        # Legitimate login from local IP
        response = self.app.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'testpass123'
            }),
            content_type='application/json',
            headers={'X-Forwarded-For': '192.168.1.100'}  # Local IP
        )
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        
        # Should have low risk score
        self.assertLess(data.get('risk_score', 1.0), 0.5)
        
        # Should receive valid token
        self.assertIn('token', data)

class MockRedisTests(ATOSystemTestCase):
    """Test Redis functionality with mocking"""
    
    def setUp(self):
        super().setUp()
        # Mock Redis for testing
        app.config['TESTING_REDIS'] = True
    
    def test_redis_rate_limiting(self):
        """Test Redis-based rate limiting"""
        # This would require mocking Redis or using a test Redis instance
        # For now, we'll test that the rate limiting logic works
        pass

def run_security_scan():
    """Run basic security scans"""
    print("\n" + "="*50)
    print("SECURITY SCAN RESULTS")
    print("="*50)
    
    # Check for common security issues
    security_issues = []
    
    # Check if default secrets are being used
    if app.config.get('SECRET_KEY') == 'dev-secret-key-change-in-production':
        security_issues.append("⚠️  Default SECRET_KEY detected - change in production!")
    
    if app.config.get('JWT_SECRET_KEY') == 'jwt-secret-change-in-production':
        security_issues.append("⚠️  Default JWT_SECRET_KEY detected - change in production!")
    
    # Check database configuration
    db_url = app.config.get('SQLALCHEMY_DATABASE_URI', '')
    if 'sqlite' in db_url.lower():
        security_issues.append("ℹ️  Using SQLite database - consider PostgreSQL for production")
    
    # Print results
    if security_issues:
        for issue in security_issues:
            print(issue)
    else:
        print("✅ No obvious security issues detected")
    
    print("="*50)

def run_performance_benchmark():
    """Run basic performance benchmarks"""
    print("\n" + "="*50)
    print("PERFORMANCE BENCHMARK")
    print("="*50)
    
    import time
    
    # Test database query performance
    start_time = time.time()
    User.query.all()
    db_query_time = time.time() - start_time
    print(f"Database query time: {db_query_time:.4f} seconds")
    
    # Test login endpoint performance
    app_client = app.test_client()
    start_time = time.time()
    
    for i in range(100):
        app_client.post('/api/login',
            data=json.dumps({
                'username': 'testuser',
                'password': 'wrongpassword'
            }),
            content_type='application/json'
        )
    
    total_time = time.time() - start_time
    avg_time = total_time / 100
    
    print(f"Average login request time: {avg_time:.4f} seconds")
    print(f"Requests per second: {1/avg_time:.2f}")
    
    if avg_time > 0.1:
        print("⚠️  Login requests are slower than recommended (>100ms)")
    else:
        print("✅ Login performance is acceptable")
    
    print("="*50)

if __name__ == '__main__':
    # Create test suite
    test_classes = [
        AuthenticationTests,
        RiskCalculationTests,
        MitigationTests,
        RateLimitingTests,
        StatisticsTests,
        SecurityTests,
        GeolocationTests,
        PerformanceTests,
        IntegrationTests
    ]
    
    # Create test suite
    suite = unittest.TestSuite()
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Run additional scans
    with app.app_context():
        db.create_all()
        run_security_scan()
        run_performance_benchmark()
    
    # Print summary
    print(f"\n{'='*50}")
    print("TEST SUMMARY")
    print(f"{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")
    
    if result.failures:
        print("\nFAILURES:")
        for test, failure in result.failures:
            print(f"❌ {test}: {failure.split('AssertionError: ')[-1].split()[0]}")
    
    if result.errors:
        print("\nERRORS:")
        for test, error in result.errors:
            print(f"💥 {test}: {error.split()[-1]}")
    
    print(f"{'='*50}")
    
    # Exit with appropriate code
    exit_code = 0 if len(result.failures) == 0 and len(result.errors) == 0 else 1
    exit(exit_code)