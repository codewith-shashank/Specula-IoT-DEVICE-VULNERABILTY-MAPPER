import React from 'react';
import { Link, useLocation } from 'react-router-dom';

const Navbar = () => {
  const location = useLocation();

  const isActive = (path) => location.pathname === path;

  return (
    <nav className="navbar" data-testid="navbar">
      <Link to="/" className="navbar-brand" data-testid="navbar-brand">
        <div className="navbar-brand-icon">🛡️</div>
        Specula
      </Link>
      <ul className="navbar-menu">
        <li>
          <Link
            to="/"
            className={`navbar-link ${isActive('/') ? 'active' : ''}`}
            data-testid="nav-dashboard"
          >
            Dashboard
          </Link>
        </li>
        <li>
          <Link
            to="/discovery"
            className={`navbar-link ${isActive('/discovery') ? 'active' : ''}`}
            data-testid="nav-discovery"
          >
            Discovery
          </Link>
        </li>
        <li>
          <Link
            to="/attack-graph"
            className={`navbar-link ${isActive('/attack-graph') ? 'active' : ''}`}
            data-testid="nav-attack-graph"
          >
            Attack Graph
          </Link>
        </li>
        <li>
          <Link
            to="/vulnerabilities"
            className={`navbar-link ${isActive('/vulnerabilities') ? 'active' : ''}`}
            data-testid="nav-vulnerabilities"
          >
            Vulnerabilities
          </Link>
        </li>
      </ul>
    </nav>
  );
};

export default Navbar;