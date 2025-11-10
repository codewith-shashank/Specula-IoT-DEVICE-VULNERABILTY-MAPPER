import React, { useEffect, useState } from 'react';
import axios from 'axios';
import Navbar from '../components/Navbar';
import { Target, AlertTriangle, Shield } from 'lucide-react';
import { toast } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const AttackGraph = () => {
  const [attackPaths, setAttackPaths] = useState([]);
  const [loading, setLoading] = useState(true);
  const [generating, setGenerating] = useState(false);

  useEffect(() => {
    fetchAttackPaths();
  }, []);

  const fetchAttackPaths = async () => {
    try {
      const response = await axios.get(`${API}/attack-paths`);
      setAttackPaths(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching attack paths:', error);
      setLoading(false);
    }
  };

  const generatePaths = async () => {
    setGenerating(true);
    toast.info('Generating attack path simulations with AI...');

    try {
      const response = await axios.post(`${API}/attack-paths/generate`);
      toast.success(`Generated ${response.data.paths_generated} attack paths`);
      fetchAttackPaths();
      setGenerating(false);
    } catch (error) {
      console.error('Error generating attack paths:', error);
      toast.error('Failed to generate attack paths');
      setGenerating(false);
    }
  };

  const getLikelihoodColor = (likelihood) => {
    const colors = {
      low: '#10b981',
      medium: '#f59e0b',
      high: '#ef4444'
    };
    return colors[likelihood] || colors.medium;
  };

  if (loading) {
    return (
      <>
        <Navbar />
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p className="loading-text">Loading attack paths...</p>
        </div>
      </>
    );
  }

  return (
    <>
      <Navbar />
      <div className="container" data-testid="attack-graph-container">
        <div className="page-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <h1 className="page-title">Attack Path Simulation</h1>
              <p className="page-subtitle">AI-generated potential attack scenarios and lateral movement paths</p>
            </div>
            <button
              className="btn btn-primary"
              data-testid="generate-paths-btn"
              onClick={generatePaths}
              disabled={generating}
            >
              {generating ? (
                <>
                  <div className="loading-spinner" style={{ width: '20px', height: '20px', borderWidth: '2px', display: 'inline-block', marginRight: '0.5rem' }}></div>
                  Generating...
                </>
              ) : (
                <>
                  <Target size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
                  Generate Attack Paths
                </>
              )}
            </button>
          </div>
        </div>

        {attackPaths.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">🎯</div>
            <div className="empty-state-text">No attack paths generated yet</div>
            <p style={{ color: '#94a3b8', marginBottom: '1.5rem' }}>Generate AI-powered attack simulations to identify potential threats</p>
            <button className="btn btn-primary" onClick={generatePaths} disabled={generating} data-testid="generate-paths-empty-btn">
              Generate Attack Paths
            </button>
          </div>
        ) : (
          <div className="attack-path-container">
            {attackPaths.map((path, pathIdx) => (
              <div key={path.id} className="glass-card" data-testid={`attack-path-${pathIdx}`}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '1.5rem' }}>
                  <div>
                    <h2 style={{ color: '#06b6d4', marginBottom: '0.5rem' }}>Attack Scenario #{pathIdx + 1}</h2>
                    <div style={{ color: '#94a3b8', fontSize: '0.9rem' }}>Entry Point: Device {path.entry_device_id.slice(0, 8)}</div>
                  </div>
                  <span
                    style={{
                      padding: '0.5rem 1rem',
                      borderRadius: '20px',
                      fontSize: '0.85rem',
                      fontWeight: '600',
                      textTransform: 'uppercase',
                      background: `${getLikelihoodColor(path.likelihood)}20`,
                      color: getLikelihoodColor(path.likelihood),
                      border: `1px solid ${getLikelihoodColor(path.likelihood)}`
                    }}
                  >
                    {path.likelihood} Likelihood
                  </span>
                </div>

                {path.path && path.path.length > 0 && (
                  <div style={{ marginBottom: '1.5rem' }}>
                    <h3 style={{ color: '#06b6d4', marginBottom: '1rem', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Target size={18} />
                      Attack Steps
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                      {path.path.map((step, stepIdx) => (
                        <div
                          key={stepIdx}
                          style={{
                            display: 'flex',
                            gap: '1rem',
                            alignItems: 'start',
                            padding: '1rem',
                            background: 'rgba(6, 182, 212, 0.05)',
                            borderLeft: '3px solid #06b6d4',
                            borderRadius: '8px'
                          }}
                        >
                          <div
                            style={{
                              minWidth: '32px',
                              height: '32px',
                              borderRadius: '50%',
                              background: 'linear-gradient(135deg, #06b6d4, #0891b2)',
                              display: 'flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              color: 'white',
                              fontWeight: '700',
                              fontSize: '0.9rem'
                            }}
                          >
                            {step.step || stepIdx + 1}
                          </div>
                          <div style={{ flex: 1 }}>
                            <div style={{ color: '#e2e8f0', fontWeight: '600', marginBottom: '0.25rem' }}>{step.action}</div>
                            <div style={{ color: '#94a3b8', fontSize: '0.9rem', marginBottom: '0.25rem' }}>Target: {step.target}</div>
                            <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Technique: {step.technique}</div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{ marginBottom: '1.5rem' }}>
                  <h3 style={{ color: '#ef4444', marginBottom: '0.75rem', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <AlertTriangle size={18} />
                    Impact Assessment
                  </h3>
                  <p style={{ color: '#e2e8f0', lineHeight: '1.6' }}>{path.impact_assessment}</p>
                </div>

                {path.mitigation_steps && path.mitigation_steps.length > 0 && (
                  <div>
                    <h3 style={{ color: '#10b981', marginBottom: '0.75rem', fontSize: '1.1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Shield size={18} />
                      Mitigation Steps
                    </h3>
                    <ul style={{ listStyle: 'none', padding: 0 }}>
                      {path.mitigation_steps.map((step, idx) => (
                        <li
                          key={idx}
                          style={{
                            color: '#94a3b8',
                            marginBottom: '0.5rem',
                            paddingLeft: '1.5rem',
                            position: 'relative'
                          }}
                        >
                          <Shield size={16} style={{ position: 'absolute', left: 0, top: '2px', color: '#10b981' }} />
                          {step}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
};

export default AttackGraph;