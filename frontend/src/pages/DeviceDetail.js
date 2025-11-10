import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import Navbar from '../components/Navbar';
import { ArrowLeft, Shield, AlertTriangle, Info } from 'lucide-react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const DeviceDetail = () => {
  const { deviceId } = useParams();
  const navigate = useNavigate();
  const [device, setDevice] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [riskAssessment, setRiskAssessment] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDeviceDetails();
  }, [deviceId]);

  const fetchDeviceDetails = async () => {
    try {
      const [deviceRes, vulnRes] = await Promise.all([
        axios.get(`${API}/devices/${deviceId}`),
        axios.get(`${API}/devices/${deviceId}/vulnerabilities`)
      ]);

      setDevice(deviceRes.data);
      setVulnerabilities(vulnRes.data);

      // Try to get risk assessment
      try {
        const riskRes = await axios.get(`${API}/devices/${deviceId}/risk-analysis`);
        setRiskAssessment(riskRes.data);
      } catch (e) {
        // Risk assessment might not exist yet
        console.log('No risk assessment yet');
      }

      setLoading(false);
    } catch (error) {
      console.error('Error fetching device details:', error);
      setLoading(false);
    }
  };

  const getSeverityColor = (severity) => {
    const colors = {
      CRITICAL: '#dc2626',
      HIGH: '#ef4444',
      MEDIUM: '#f59e0b',
      LOW: '#10b981',
      UNKNOWN: '#94a3b8'
    };
    return colors[severity] || colors.UNKNOWN;
  };

  if (loading) {
    return (
      <>
        <Navbar />
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p className="loading-text">Loading device details...</p>
        </div>
      </>
    );
  }

  if (!device) {
    return (
      <>
        <Navbar />
        <div className="container">
          <div className="empty-state">
            <div className="empty-state-text">Device not found</div>
            <button className="btn btn-primary" onClick={() => navigate('/discovery')}>
              Back to Discovery
            </button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <Navbar />
      <div className="container" data-testid="device-detail-container">
        <button
          className="btn btn-secondary"
          data-testid="back-btn"
          onClick={() => navigate('/discovery')}
          style={{ marginBottom: '1.5rem' }}
        >
          <ArrowLeft size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
          Back to Discovery
        </button>

        <div className="page-header">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div>
              <h1 className="page-title">{device.device_type || 'Unknown Device'}</h1>
              <p className="page-subtitle">{device.ip}</p>
            </div>
            <span className={`risk-badge risk-${device.risk_level}`} data-testid="device-risk-badge" style={{ fontSize: '1rem', padding: '0.5rem 1.5rem' }}>
              {device.risk_level} RISK
            </span>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '2rem' }}>
          <div className="glass-card">
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Info size={20} />
              Device Information
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>IP Address</div>
                <div style={{ color: '#e2e8f0', fontWeight: '500' }}>{device.ip}</div>
              </div>
              {device.hostname && (
                <div>
                  <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>Hostname</div>
                  <div style={{ color: '#e2e8f0', fontWeight: '500' }}>{device.hostname}</div>
                </div>
              )}
              {device.mac && (
                <div>
                  <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>MAC Address</div>
                  <div style={{ color: '#e2e8f0', fontWeight: '500' }}>{device.mac}</div>
                </div>
              )}
              {device.manufacturer && (
                <div>
                  <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>Manufacturer</div>
                  <div style={{ color: '#e2e8f0', fontWeight: '500' }}>{device.manufacturer}</div>
                </div>
              )}
              {device.os_info && (
                <div>
                  <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>Operating System</div>
                  <div style={{ color: '#e2e8f0', fontWeight: '500' }}>{device.os_info}</div>
                </div>
              )}
            </div>
          </div>

          <div className="glass-card">
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Shield size={20} />
              Security Overview
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>Risk Level</div>
                <div style={{ color: getSeverityColor(device.risk_level?.toUpperCase()), fontWeight: '600', fontSize: '1.2rem', textTransform: 'uppercase' }}>
                  {device.risk_level}
                </div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>Known Vulnerabilities</div>
                <div style={{ color: '#e2e8f0', fontWeight: '600', fontSize: '1.5rem' }}>{vulnerabilities.length}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '0.25rem' }}>Open Ports</div>
                <div style={{ color: '#e2e8f0', fontWeight: '500' }}>
                  {device.open_ports.length > 0 ? device.open_ports.join(', ') : 'None detected'}
                </div>
              </div>
            </div>
          </div>
        </div>

        {device.services && device.services.length > 0 && (
          <div className="glass-card" style={{ marginBottom: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4' }}>Running Services</h2>
            <table className="vuln-table">
              <thead>
                <tr>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {device.services.map((service, idx) => (
                  <tr key={idx}>
                    <td>{service.port}</td>
                    <td>{service.service || 'Unknown'}</td>
                    <td>{service.product || '-'}</td>
                    <td>{service.version || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {riskAssessment && (
          <div className="glass-card" style={{ marginBottom: '2rem' }}>
            <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              🤖 AI Risk Assessment
            </h2>
            <div style={{ marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', marginBottom: '1rem' }}>
                <div>
                  <div style={{ color: '#94a3b8', fontSize: '0.85rem' }}>Risk Score</div>
                  <div style={{ color: '#06b6d4', fontSize: '2rem', fontWeight: '700' }}>{riskAssessment.risk_score}/100</div>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ background: 'rgba(6, 182, 212, 0.1)', borderRadius: '10px', overflow: 'hidden', height: '20px' }}>
                    <div
                      style={{
                        width: `${riskAssessment.risk_score}%`,
                        height: '100%',
                        background: getSeverityColor(riskAssessment.risk_level?.toUpperCase()),
                        transition: 'width 0.5s'
                      }}
                    ></div>
                  </div>
                </div>
              </div>
              <p style={{ color: '#e2e8f0', lineHeight: '1.6' }}>{riskAssessment.ai_analysis}</p>
            </div>

            {riskAssessment.threat_vectors && riskAssessment.threat_vectors.length > 0 && (
              <div style={{ marginBottom: '1.5rem' }}>
                <h3 style={{ color: '#06b6d4', marginBottom: '0.75rem', fontSize: '1.1rem' }}>Threat Vectors</h3>
                <ul style={{ listStyle: 'none', padding: 0 }}>
                  {riskAssessment.threat_vectors.map((vector, idx) => (
                    <li key={idx} style={{ color: '#94a3b8', marginBottom: '0.5rem', paddingLeft: '1.5rem', position: 'relative' }}>
                      <AlertTriangle size={16} style={{ position: 'absolute', left: 0, top: '2px', color: '#f59e0b' }} />
                      {vector}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {riskAssessment.recommendations && riskAssessment.recommendations.length > 0 && (
              <div>
                <h3 style={{ color: '#06b6d4', marginBottom: '0.75rem', fontSize: '1.1rem' }}>Recommendations</h3>
                <ul style={{ listStyle: 'none', padding: 0 }}>
                  {riskAssessment.recommendations.map((rec, idx) => (
                    <li key={idx} style={{ color: '#94a3b8', marginBottom: '0.5rem', paddingLeft: '1.5rem', position: 'relative' }}>
                      <Shield size={16} style={{ position: 'absolute', left: 0, top: '2px', color: '#10b981' }} />
                      {rec}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        <div className="glass-card">
          <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle size={20} />
            Known Vulnerabilities ({vulnerabilities.length})
          </h2>
          {vulnerabilities.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-text">No vulnerabilities found</div>
              <p style={{ color: '#94a3b8' }}>This device appears to be secure</p>
            </div>
          ) : (
            <table className="vuln-table">
              <thead>
                <tr>
                  <th>CVE ID</th>
                  <th>Severity</th>
                  <th>CVSS Score</th>
                  <th>Description</th>
                </tr>
              </thead>
              <tbody>
                {vulnerabilities.map((vuln) => (
                  <tr key={vuln.id}>
                    <td>
                      <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`} target="_blank" rel="noopener noreferrer" style={{ color: '#06b6d4', textDecoration: 'none' }}>
                        {vuln.cve_id}
                      </a>
                    </td>
                    <td>
                      <span
                        style={{
                          color: getSeverityColor(vuln.severity),
                          fontWeight: '600',
                          textTransform: 'uppercase',
                          fontSize: '0.85rem'
                        }}
                      >
                        {vuln.severity}
                      </span>
                    </td>
                    <td style={{ fontWeight: '600', color: '#e2e8f0' }}>{vuln.cvss_score || 'N/A'}</td>
                    <td style={{ maxWidth: '400px' }}>{vuln.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
};

export default DeviceDetail;