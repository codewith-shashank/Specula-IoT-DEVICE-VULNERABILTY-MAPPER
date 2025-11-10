import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import Navbar from '../components/Navbar';
import { Shield, AlertTriangle, Activity, Database } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const Dashboard = () => {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [recentDevices, setRecentDevices] = useState([]);

  useEffect(() => {
    fetchStats();
  }, []);

  const fetchStats = async () => {
    try {
      const response = await axios.get(`${API}/stats`);
      setStats(response.data);
      setRecentDevices(response.data.recent_devices || []);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching stats:', error);
      setLoading(false);
    }
  };

  const getRiskColor = (level) => {
    const colors = {
      low: '#10b981',
      medium: '#f59e0b',
      high: '#ef4444',
      critical: '#dc2626',
      unknown: '#94a3b8'
    };
    return colors[level] || colors.unknown;
  };

  if (loading) {
    return (
      <>
        <Navbar />
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p className="loading-text">Loading dashboard...</p>
        </div>
      </>
    );
  }

  return (
    <>
      <Navbar />
      <div className="container" data-testid="dashboard-container">
        <div className="page-header">
          <h1 className="page-title">Specula Dashboard</h1>
          <p className="page-subtitle">IoT Device Vulnerability Monitoring & Risk Assessment</p>
        </div>

        <div className="stats-grid">
          <div className="stat-card" data-testid="total-devices-stat">
            <div className="stat-label">
              <Database size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
              Total Devices
            </div>
            <div className="stat-value">{stats?.total_devices || 0}</div>
            <div className="stat-change">Discovered across network</div>
          </div>

          <div className="stat-card" data-testid="total-vulnerabilities-stat">
            <div className="stat-label">
              <AlertTriangle size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
              Total Vulnerabilities
            </div>
            <div className="stat-value">{stats?.total_vulnerabilities || 0}</div>
            <div className="stat-change">Known CVEs identified</div>
          </div>

          <div className="stat-card" data-testid="critical-devices-stat">
            <div className="stat-label">
              <Shield size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
              Critical Risk Devices
            </div>
            <div className="stat-value" style={{ color: '#dc2626' }}>
              {stats?.risk_distribution?.critical || 0}
            </div>
            <div className="stat-change" style={{ color: '#dc2626' }}>Immediate attention required</div>
          </div>

          <div className="stat-card" data-testid="high-risk-stat">
            <div className="stat-label">
              <Activity size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
              High Risk Devices
            </div>
            <div className="stat-value" style={{ color: '#ef4444' }}>
              {stats?.risk_distribution?.high || 0}
            </div>
            <div className="stat-change" style={{ color: '#ef4444' }}>Needs mitigation</div>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem', marginTop: '2rem' }}>
          <div className="glass-card">
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4' }}>Risk Distribution</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {stats?.risk_distribution && Object.entries(stats.risk_distribution).map(([level, count]) => (
                <div key={level} style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                  <div style={{ minWidth: '100px', textTransform: 'capitalize', color: '#e2e8f0' }}>{level}</div>
                  <div style={{ flex: 1, background: 'rgba(6, 182, 212, 0.1)', borderRadius: '10px', overflow: 'hidden', height: '30px' }}>
                    <div
                      style={{
                        width: `${stats.total_devices > 0 ? (count / stats.total_devices) * 100 : 0}%`,
                        height: '100%',
                        background: getRiskColor(level),
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: 'white',
                        fontWeight: '600',
                        transition: 'width 0.5s'
                      }}
                    >
                      {count > 0 && count}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-card">
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4' }}>Quick Actions</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <button
                className="btn btn-primary"
                onClick={() => navigate('/discovery')}
                data-testid="scan-network-btn"
                style={{ width: '100%' }}
              >
                🔍 Scan Network
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => navigate('/attack-graph')}
                data-testid="view-attack-paths-btn"
                style={{ width: '100%' }}
              >
                🎯 Attack Paths
              </button>
              <button
                className="btn btn-secondary"
                onClick={() => navigate('/vulnerabilities')}
                data-testid="vulnerability-database-btn"
                style={{ width: '100%' }}
              >
                📊 Vulnerabilities
              </button>
            </div>
          </div>
        </div>

        {recentDevices.length > 0 && (
          <div className="glass-card" style={{ marginTop: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4' }}>Recently Discovered Devices</h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {recentDevices.map((device, idx) => (
                <div
                  key={idx}
                  data-testid={`recent-device-${idx}`}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '1rem',
                    background: 'rgba(6, 182, 212, 0.05)',
                    borderRadius: '10px',
                    border: '1px solid rgba(6, 182, 212, 0.1)',
                    cursor: 'pointer',
                    transition: 'background 0.3s'
                  }}
                  onMouseEnter={(e) => e.currentTarget.style.background = 'rgba(6, 182, 212, 0.1)'}
                  onMouseLeave={(e) => e.currentTarget.style.background = 'rgba(6, 182, 212, 0.05)'}
                >
                  <div>
                    <div style={{ fontWeight: '600', color: '#e2e8f0' }}>{device.device_type || 'Unknown Device'}</div>
                    <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>{device.ip}</div>
                  </div>
                  <span className={`risk-badge risk-${device.risk_level || 'unknown'}`}>
                    {device.risk_level || 'unknown'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {stats?.total_devices === 0 && (
          <div className="empty-state">
            <div className="empty-state-icon">🔍</div>
            <div className="empty-state-text">No devices discovered yet</div>
            <button className="btn btn-primary" onClick={() => navigate('/discovery')} data-testid="start-scanning-btn">
              Start Scanning
            </button>
          </div>
        )}
      </div>
    </>
  );
};

export default Dashboard;