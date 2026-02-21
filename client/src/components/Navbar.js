import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import logo from '../logo.svg';

const Navbar = ({ user, onLogout }) => {
  const navigate = useNavigate();

  const handleLogout = () => {
    onLogout();
    navigate('/login');
  };

  return (
    <header className="header">
      <div className="container">
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <img src={logo} alt="Secure Password Vault Logo" className="logo-image" />
          <h1 style={{ margin: 0 }}>
            <Link to="/" style={{ color: 'white', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '10px' }}>
              Secure Password Vault
            </Link>
          </h1>
        </div>
        <div className="user-info">
          <span>Welcome, {user?.username}</span>
          <Link to="/add-password" className="btn">
            Add Password
          </Link>
          <button onClick={handleLogout} className="btn">
            Logout
          </button>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
