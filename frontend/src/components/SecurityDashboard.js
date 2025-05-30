import React, { useState, useEffect } from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import { Shield, AlertTriangle, Users, Globe, Activity, Eye, Ban, CheckCircle } from 'lucide-react';

const SecurityDashboard = () => {
  const [stats, setStats] = useState({
    recent_attempts: 0,
    successful_logins: 0,
    failed_logins: 0,
    high_risk_attempts: 0,
    top_countries: [],
    active_users: 0
  });
  
  const [realtimeData, setRealtimeData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  // Mock data for demonstration
  const mockTimeSeriesData = [
    { time: '00:00', attempts: 45, blocked: 12 },
    { time: '04:00', attempts: 23, blocked: 8 },
    { time: '08:00', attempts: 67, blocked: 15 },
    { time: '12:00', attempts: 89, blocked: 22 },
    { time: '16:00', attempts: 134, blocked: 45 },
    { time: '20:00', attempts: 167, blocked: 67 },
  ];

  const mockAttackTypes = [
    { name: 'Credential Stuffing', value: 65, color: '#ef4444' },
    { name: 'Session Hijacking', value: 20, color: '#f97316' },
    { name: 'Bot Attacks', value: 15, color: '#eab308' },
  ];

  const mockGeoData = [
    { country: 'US', attempts: 245 },
    { country: 'CN', attempts: 189 },
    { country: 'RU', attempts: 156 },
    { country: 'BR', attempts: 98 },
    { country: 'IN', attempts: 76 },
  ];

  const mockAlerts = [
    {
      id: 1,
      type: 'high_risk',
      message: 'High-risk login attempt from China (IP: 203.0.113.45)',
      timestamp: new Date().toISOString(),
      severity: 'error'
    },
    {
      id: 2,
      type: 'rate_limit',
      message: 'Rate limiting applied to IP 192.168.1.100',
      timestamp: new Date(Date.now() - 300000).toISOString(),
      severity: 'warning'
    },
    {
      id: 3,
      type: 'captcha',
      message: 'CAPTCHA challenge triggered for user "admin"',
      timestamp: new Date(Date.now() - 600000).toISOString(),
      severity: 'info'
    }
  ];

  useEffect(() => {
    // Simulate API call
    const fetchStats = async () => {
      setLoading(true);
      try {
        // In real implementation, this would be:
        // const response = await axios.get('/api/stats');
        // setStats(response.data);
        
        // Mock data for demo
        setTimeout(() => {
          setStats({
            recent_attempts: 1247,
            successful_logins: 892,
            failed_logins: 355,
            high_risk_attempts: 89,
            top_countries: mockGeoData,
            active_users: 156
          });
          setAlerts(mockAlerts);
          setLoading(false);
        }, 1000);
      } catch (error) {
        console.error('Failed to fetch stats:', error);
        setLoading(false);
      }
    };

    fetchStats();
    
    // Set up real-time updates
    const interval = setInterval(() => {
      const newDataPoint = {
        time: new Date().toLocaleTimeString(),
        attempts: Math.floor(Math.random() * 50) + 20,
        blocked: Math.floor(Math.random() * 15) + 5
      };
      
      setRealtimeData(prev => [...prev.slice(-23), newDataPoint]);
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const StatCard = ({ title, value, icon: Icon, trend, color = "blue" }) => (
    <div className="bg-white rounded-lg shadow-md p-6 border-l-4 border-blue-500">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value.toLocaleString()}</p>
          {trend && (
            <p className={`text-sm ${trend > 0 ? 'text-red-600' : 'text-green-600'}`}>
              {trend > 0 ? '↑' : '↓'} {Math.abs(trend)}% from last hour
            </p>
          )}
        </div>
        <div className={`p-3 rounded-full bg-${color}-100`}>
          <Icon className={`h-8 w-8 text-${color}-600`} />
        </div>
      </div>
    </div>
  );

  const AlertItem = ({ alert }) => {
    const severityColors = {
      error: 'border-red-500 bg-red-50',
      warning: 'border-yellow-500 bg-yellow-50',
      info: 'border-blue-500 bg-blue-50'
    };

    const severityIcons = {
      error: AlertTriangle,
      warning: AlertTriangle,
      info: Activity
    };

    const Icon = severityIcons[alert.severity];

    return (
      <div className={`border-l-4 p-4 ${severityColors[alert.severity]}`}>
        <div className="flex items-start">
          <Icon className="h-5 w-5 mt-0.5 mr-3 text-gray-600" />
          <div className="flex-1">
            <p className="text-sm font-medium text-gray-900">{alert.message}</p>
            <p className="text-xs text-gray-500 mt-1">
              {new Date(alert.timestamp).toLocaleString()}
            </p>
          </div>
        </div>
      </div>
    );
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-2xl font-bold text-gray-900">
                ATO Detection & Mitigation Dashboard
              </h1>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center text-sm text-gray-500">
                <div className="w-3 h-3 bg-green-500 rounded-full mr-2 animate-pulse"></div>
                Live Monitoring Active
              </div>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <StatCard
            title="Login Attempts (24h)"
            value={stats.recent_attempts}
            icon={Activity}
            trend={12}
            color="blue"
          />
          <StatCard
            title="Successful Logins"
            value={stats.successful_logins}
            icon={CheckCircle}
            trend={-5}
            color="green"
          />
          <StatCard
            title="High Risk Attempts"
            value={stats.high_risk_attempts}
            icon={AlertTriangle}
            trend={23}
            color="red"
          />
          <StatCard
            title="Active Users"
            value={stats.active_users}
            icon={Users}
            color="purple"
          />
        </div>

        {/* Charts Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Login Attempts Timeline */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Login Attempts Timeline
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={mockTimeSeriesData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="attempts" 
                  stroke="#3b82f6" 
                  strokeWidth={2}
                  name="Total Attempts"
                />
                <Line 
                  type="monotone" 
                  dataKey="blocked" 
                  stroke="#ef4444" 
                  strokeWidth={2}
                  name="Blocked"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>

          {/* Attack Types Distribution */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Attack Types Distribution
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={mockAttackTypes}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={120}
                  dataKey="value"
                >
                  {mockAttackTypes.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
            <div className="mt-4 space-y-2">
              {mockAttackTypes.map((type, index) => (
                <div key={index} className="flex items-center justify-between text-sm">
                  <div className="flex items-center">
                    <div 
                      className="w-3 h-3 rounded-full mr-2" 
                      style={{ backgroundColor: type.color }}
                    ></div>
                    <span className="text-gray-700">{type.name}</span>
                  </div>
                  <span className="font-medium">{type.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Geographic Distribution and Alerts */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Geographic Distribution */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Globe className="h-5 w-5 mr-2" />
              Top Countries by Attempts
            </h3>
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={mockGeoData} layout="horizontal">
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="country" type="category" width={40} />
                <Tooltip />
                <Bar dataKey="attempts" fill="#6366f1" />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Recent Alerts */}
          <div className="bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center">
              <Eye className="h-5 w-5 mr-2" />
              Recent Security Alerts
            </h3>
            <div className="space-y-3 max-h-80 overflow-y-auto">
              {alerts.map((alert) => (
                <AlertItem key={alert.id} alert={alert} />
              ))}
            </div>
          </div>
        </div>

        {/* Real-time Feed */}
        {realtimeData.length > 0 && (
          <div className="mt-8 bg-white rounded-lg shadow-md p-6">
            <h3 className="text-lg font-semibold text-gray-900 mb-4">
              Real-time Activity Feed
            </h3>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={realtimeData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="time" />
                <YAxis />
                <Tooltip />
                <Line 
                  type="monotone" 
                  dataKey="attempts" 
                  stroke="#10b981" 
                  strokeWidth={2}
                  dot={false}
                  name="Live Attempts"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </main>
    </div>
  );
};

export default SecurityDashboard;