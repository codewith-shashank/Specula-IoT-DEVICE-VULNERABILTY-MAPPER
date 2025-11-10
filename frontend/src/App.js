import React, { useState } from 'react';
import '@/App.css';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import DeviceDiscovery from './pages/DeviceDiscovery';
import DeviceDetail from './pages/DeviceDetail';
import AttackGraph from './pages/AttackGraph';
import VulnerabilityDatabase from './pages/VulnerabilityDatabase';

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/discovery" element={<DeviceDiscovery />} />
          <Route path="/device/:deviceId" element={<DeviceDetail />} />
          <Route path="/attack-graph" element={<AttackGraph />} />
          <Route path="/vulnerabilities" element={<VulnerabilityDatabase />} />
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;