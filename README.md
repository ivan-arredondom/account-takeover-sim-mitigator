# Account Takeover Detection and Mitigation System

This project simulates and defends against Account Takeover (ATO) attacks such as credential stuffing, session hijacking, and bot-based login attempts. It demonstrates comprehensive security design, real-time detection techniques, and mitigation strategies inspired by real-world practices at companies like Meta.

## Project Goals

- Simulate common ATO attacks, including credential stuffing and session hijacking
- Detect anomalous login behavior using rule-based logic and optional machine learning
- Mitigate attacks using CAPTCHA, rate limiting, IP blacklisting, and session controls
- Provide a live dashboard for monitoring attack patterns and system responses

## System Components

### 1. Simulated Login Portal
- Technology: Python (Flask or FastAPI) or Node.js (Express)
- Features:
  - User registration and login with bcrypt password hashing
  - JWT-based session management
  - Logging of IP address, user-agent, timestamps, and geolocation

### 2. ATO Attack Simulator
- Technology: Python scripts using `requests` or `selenium`
- Features:
  - Simulate credential stuffing with mock leaked credentials
  - Automate login attempts mimicking bot behavior
  - Simulate session hijacking via stale tokens or cookie reuse

### 3. Anomaly Detection Layer
- Technology: Python or Go backend with optional ML using scikit-learn
- Detection Rules:
  - Geolocation anomaly (IP origin change within a short time span)
  - Device or user-agent mismatch
  - Time-of-day login pattern deviations
  - Login failure threshold triggering risk assessment

### 4. Mitigation Engine
- Technology: Redis, CAPTCHA APIs (hCaptcha or reCAPTCHA)
- Features:
  - CAPTCHA enforcement for suspicious activity
  - Redis-based token bucket login rate limiter
  - Blacklisting of abusive IPs
  - Session invalidation upon hijack detection

### 5. Monitoring Dashboard
- Technology: React frontend with Grafana or Kibana
- Features:
  - Real-time login heatmaps and alerting
  - Attack origin, frequency, and user-based breakdowns
  - Manual controls for IP banning or forcing 2FA

## Technology Stack

| Category          | Tools / Libraries                               |
|------------------|--------------------------------------------------|
| Backend           | Python (Flask/FastAPI), Go, Node.js (Express)   |
| Frontend          | React                                           |
| Security          | bcrypt, JWT, geoip2, CAPTCHA APIs               |
| Rate Limiting     | Redis                                           |
| Monitoring        | Grafana, Kibana, ELK Stack                      |
| Machine Learning  | scikit-learn, pandas, numpy (optional)         |

## Getting Started

### Prerequisites
- Python 3.9+ or Node.js 18+
- Redis server
- CAPTCHA API keys (hCaptcha or reCAPTCHA)
- Optional: Docker and Docker Compose

### Setup Instructions
```bash
# Clone the repository
git clone https://github.com/yourusername/ato-detection-system.git
cd ato-detection-system

# Set up backend (example: Flask)
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start Redis
redis-server

# Run the Flask app
python app.py
