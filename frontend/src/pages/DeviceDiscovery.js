import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import Navbar from '../components/Navbar';
import { Search, Wifi, Shield } from 'lucide-react';
import { toast } from 'sonner';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

const DeviceDiscovery = () => {
  const navigate = useNavigate();
  const [target, setTarget] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState('basic');
  const [scanning, setScanning] = useState(false);
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      const response = await axios.get(`${API}/devices`);
      setDevices(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Error fetching devices:', error);
      setLoading(false);
    }
  };

  const startScan = async () => {
    if (!target) {
      toast.error('Please enter a target IP or range');
      return;
    }

    setScanning(true);
    toast.info('Starting network scan...');

    try {
      const response = await axios.post(`${API}/scan`, {
        target,
        scan_type: scanType
      });

      toast.success(`Scan complete! Found ${response.data.devices_found} devices`);
      fetchDevices();
      setScanning(false);
    } catch (error) {
      console.error('Scan error:', error);
      toast.error(error.response?.data?.detail || 'Scan failed');
      setScanning(false);
    }
  };

  const scanVulnerabilities = async (deviceId) => {
    toast.info('Scanning for vulnerabilities...');

    try {
      const response = await axios.post(`${API}/devices/${deviceId}/vulnerabilities`);
      toast.success(`Found ${response.data.vulnerabilities_found} vulnerabilities`);
      fetchDevices();
    } catch (error) {
      console.error('Vulnerability scan error:', error);
      toast.error('Vulnerability scan failed');
    }
  };

  const analyzeRisk = async (deviceId) => {
    toast.info('Analyzing device risk with AI...');

    try {
      await axios.post(`${API}/devices/${deviceId}/risk-analysis`);
      toast.success('Risk analysis complete!');
      fetchDevices();
    } catch (error) {
      console.error('Risk analysis error:', error);
      toast.error('Risk analysis failed');
    }
  };

  if (loading) {
    return (
      <>
        <Navbar />
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p className="loading-text">Loading devices...</p>
        </div>
      </>
    );
  }

  return (
    <>
      <Navbar />
      <div className="container" data-testid="device-discovery-container">
        <div className="page-header">
          <h1 className="page-title">Device Discovery</h1>
          <p className="page-subtitle">Scan your network for IoT devices and assess vulnerabilities</p>
        </div>

        <div className="glass-card" style={{ marginBottom: '2rem' }}>
          <h2 style={{ marginBottom: '1.5rem', color: '#06b6d4', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Wifi size={24} />
            Network Scanner
          </h2>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr auto', gap: '1rem', alignItems: 'end' }}>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Target IP / Range</label>
              <input
                type="text"
                className="form-input"
                data-testid="target-input"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g., 192.168.1.0/24 or 192.168.1.100"
                disabled={scanning}
              />
            </div>
            <div className="form-group" style={{ marginBottom: 0 }}>
              <label className="form-label">Scan Type</label>
              <select
                className="form-select"
                data-testid="scan-type-select"
                value={scanType}
                onChange={(e) => setScanType(e.target.value)}
                disabled={scanning}
              >
                <option value="basic">Basic (Fast)</option>
                <option value="detailed">Detailed (Slow)</option>
              </select>
            </div>
            <button
              className="btn btn-primary"
              data-testid="start-scan-btn"
              onClick={startScan}
              disabled={scanning}
              style={{ height: '50px' }}
            >
              {scanning ? (
                <>
                  <div className="loading-spinner" style={{ width: '20px', height: '20px', borderWidth: '2px', display: 'inline-block', marginRight: '0.5rem' }}></div>
                  Scanning...
                </>
              ) : (
                <>
                  <Search size={20} style={{ display: 'inline', marginRight: '0.5rem' }} />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </div>

        {devices.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">📡</div>
            <div className="empty-state-text">No devices discovered yet</div>
            <p style={{ color: '#94a3b8' }}>Start a network scan to discover IoT devices</p>
          </div>
        ) : (
          <>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
              <h2 style={{ color: '#06b6d4' }}>Discovered Devices ({devices.length})</h2>
            </div>
            <div className="device-grid">
              {devices.map((device) => (
                <div key={device.id} className="device-card" data-testid={`device-card-${device.id}`}>
                  <div className="device-header">
                    <div>
                      <div className="device-type">{device.device_type || 'Unknown Device'}</div>
                      <div className="device-info" style={{ marginTop: '0.25rem' }}>
                        <Shield size={14} style={{ display: 'inline', marginRight: '0.25rem' }} />
                        {device.ip}
                      </div>
                    </div>
                    <span className={`risk-badge risk-${device.risk_level}`} data-testid={`risk-badge-${device.id}`}>
                      {device.risk_level}
                    </span>
                  </div>

                  <div style={{ marginTop: '1rem' }}>
                    {device.manufacturer && (
                      <div className="device-info">
                        <strong>Manufacturer:</strong> {device.manufacturer}
                      </div>
                    )}
                    {device.os_info && (
                      <div className="device-info">
                        <strong>OS:</strong> {device.os_info}
                      </div>
                    )}
                    {device.open_ports.length > 0 && (
                      <div className="device-info">
                        <strong>Open Ports:</strong> {device.open_ports.slice(0, 5).join(', ')}
                        {device.open_ports.length > 5 && '...'}
                      </div>
                    )}
                    <div className="device-info">
                      <strong>Vulnerabilities:</strong> {device.vulnerability_count || 0}
                    </div>
                  </div>

                  <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <button
                      className="btn btn-primary"
                      data-testid={`scan-vuln-btn-${device.id}`}
                      onClick={() => scanVulnerabilities(device.id)}
                      style={{ flex: 1, fontSize: '0.85rem', padding: '0.5rem' }}
                    >
                      Scan CVEs
                    </button>
                    <button
                      className="btn btn-secondary"
                      data-testid={`analyze-risk-btn-${device.id}`}
                      onClick={() => analyzeRisk(device.id)}
                      style={{ flex: 1, fontSize: '0.85rem', padding: '0.5rem' }}
                    >
                      AI Analysis
                    </button>
                    <button
                      className="btn btn-secondary"
                      data-testid={`view-details-btn-${device.id}`}
                      onClick={() => navigate(`/device/${device.id}`)}
                      style={{ flex: 1, fontSize: '0.85rem', padding: '0.5rem' }}
                    >
                      Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </>
  );
};

export default DeviceDiscovery;