import React, { useState } from 'react';
import { Shield, Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react';

const LoginForm = ({ onLogin }) => {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [captchaRequired, setCaptchaRequired] = useState(false);

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear error when user starts typing
    if (error) setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setCaptchaRequired(false);

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData)
      });

      const data = await response.json();

      if (response.ok) {
        if (data.captcha_required) {
          setCaptchaRequired(true);
          setError('CAPTCHA verification required due to suspicious activity. Please try again.');
        } else if (data.token) {
          // Successful login
          onLogin(data.token, data.user);
        }
      } else {
        // Handle different error types
        if (response.status === 429) {
          setError('Too many login attempts. Please try again later.');
        } else if (response.status === 401) {
          setError('Invalid username or password.');
        } else {
          setError(data.error || 'Login failed. Please try again.');
        }
      }
    } catch (error) {
      console.error('Login error:', error);
      setError('Network error. Please check your connection and try again.');
    } finally {
      setLoading(false);
    }
  };

  const demoCredentials = [
    { username: 'admin', password: 'admin123', label: 'Admin User' },
    { username: 'user1', password: 'password123', label: 'Regular User' },
    { username: 'demo', password: 'demo123', label: 'Demo User' }
  ];

  const fillDemoCredentials = (username, password) => {
    setFormData({ username, password });
    setError('');
    setCaptchaRequired(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
      <div className="max-w-md w-full">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="mx-auto w-16 h-16 bg-blue-600 rounded-full flex items-center justify-center mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            ATO Detection System
          </h1>
          <p className="text-gray-600">
            Sign in to access the security dashboard
          </p>
        </div>

        {/* Main Login Card */}
        <div className="bg-white rounded-xl shadow-lg p-8 mb-6">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Username Field */}
            <div>
              <label htmlFor="username" className="form-label">
                Username
              </label>
              <input
                id="username"
                name="username"
                type="text"
                required
                value={formData.username}
                onChange={handleInputChange}
                className="form-input"
                placeholder="Enter your username"
                disabled={loading}
              />
            </div>

            {/* Password Field */}
            <div>
              <label htmlFor="password" className="form-label">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={formData.password}
                  onChange={handleInputChange}
                  className="form-input pr-10"
                  placeholder="Enter your password"
                  disabled={loading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center"
                  disabled={loading}
                >
                  {showPassword ? (
                    <EyeOff className="h-5 w-5 text-gray-400" />
                  ) : (
                    <Eye className="h-5 w-5 text-gray-400" />
                  )}
                </button>
              </div>
            </div>

            {/* Error Message */}
            {error && (
              <div className="alert alert-error animate-fade-in">
                <div className="flex">
                  <AlertCircle className="h-5 w-5 mr-2 flex-shrink-0" />
                  <span className="text-sm">{error}</span>
                </div>
              </div>
            )}

            {/* CAPTCHA Notice */}
            {captchaRequired && (
              <div className="alert alert-warning animate-fade-in">
                <div className="text-sm">
                  <strong>Security Notice:</strong> Your login attempt has been flagged as suspicious. 
                  In a production system, you would see a CAPTCHA challenge here.
                </div>
              </div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary flex items-center justify-center"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Signing in...
                </>
              ) : (
                'Sign In'
              )}
            </button>
          </form>
        </div>

        {/* Demo Credentials */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">
            Demo Credentials
          </h3>
          <p className="text-sm text-gray-600 mb-4">
            Click any credential below to auto-fill the form:
          </p>
          <div className="space-y-2">
            {demoCredentials.map((cred, index) => (
              <button
                key={index}
                type="button"
                onClick={() => fillDemoCredentials(cred.username, cred.password)}
                className="w-full text-left p-3 rounded-lg border border-gray-200 hover:border-blue-300 hover:bg-blue-50 transition-colors duration-200"
                disabled={loading}
              >
                <div className="flex justify-between items-center">
                  <div>
                    <div className="font-medium text-gray-900">{cred.label}</div>
                    <div className="text-sm text-gray-500">
                      {cred.username} / {cred.password}
                    </div>
                  </div>
                  <div className="text-blue-600 text-sm">Click to use</div>
                </div>
              </button>
            ))}
          </div>
        </div>

        {/* Security Notice */}
        <div className="mt-6 text-center">
          <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <div className="flex items-center justify-center text-yellow-800">
              <AlertCircle className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">Security Notice</span>
            </div>
            <p className="text-xs text-yellow-700 mt-2">
              This is a demonstration system. Login attempts are monitored and analyzed for security research purposes.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-sm text-gray-500">
          <p>
            Account Takeover Detection & Mitigation System
          </p>
          <p className="mt-1">
            Built for security demonstration and testing
          </p>
        </div>
      </div>
    </div>
  );
};

export default LoginForm;