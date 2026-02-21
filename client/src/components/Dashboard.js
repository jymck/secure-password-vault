import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const Dashboard = () => {
  const [stats, setStats] = useState({
    totalPasswords: 0,
    recentPasswords: [],
    weakPasswords: 0
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get('/api/passwords', {
        withCredentials: true
      });
      
      const passwords = response.data;
      setStats({
        totalPasswords: passwords.length,
        recentPasswords: passwords.slice(-5).reverse(),
        weakPasswords: passwords.filter(p => {
          // This is a simplified check - in reality, you'd decrypt and check strength
          return p.title.toLowerCase().includes('test') || p.title.toLowerCase().includes('temp');
        }).length
      });
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div>
      <div className="card">
        <h3>Dashboard</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px', marginBottom: '30px' }}>
          <div style={{ textAlign: 'center', padding: '20px', background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', color: 'white', borderRadius: '8px' }}>
            <h3 style={{ margin: '0 0 10px 0', fontSize: '32px' }}>{stats.totalPasswords}</h3>
            <p style={{ margin: 0 }}>Total Passwords</p>
          </div>
          <div style={{ textAlign: 'center', padding: '20px', background: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)', color: 'white', borderRadius: '8px' }}>
            <h3 style={{ margin: '0 0 10px 0', fontSize: '32px' }}>{stats.weakPasswords}</h3>
            <p style={{ margin: 0 }}>Weak Passwords</p>
          </div>
        </div>
        
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
          <h3>Recent Passwords</h3>
          <Link to="/passwords" className="btn">View All</Link>
        </div>
        
        {stats.recentPasswords.length > 0 ? (
          <div className="password-list">
            {stats.recentPasswords.map(password => (
              <div key={password.id} className="password-item">
                <h3>{password.title}</h3>
                <div className="password-details">
                  {password.username && <p>Username: {password.username}</p>}
                  {password.url && <p>URL: {password.url}</p>}
                  <p>Created: {new Date(password.created_at).toLocaleDateString()}</p>
                </div>
                <div className="actions">
                  <Link to={`/edit-password/${password.id}`} className="btn btn-secondary">
                    Edit
                  </Link>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
            <h3>No passwords yet</h3>
            <p>Start by adding your first password to the vault.</p>
            <Link to="/add-password" className="btn" style={{ marginTop: '20px' }}>
              Add Your First Password
            </Link>
          </div>
        )}
      </div>
      <div style={{ textAlign: 'center', padding: '15px', fontSize: '11px', color: '#999', lineHeight: '1.4' }}>
        Developed by YCR
      </div>
      <div style={{ textAlign: 'center', padding: '0 0 20px 0', fontSize: '10px', color: '#999', lineHeight: '1.4', fontStyle: 'italic' }}>
        This application is for educational purposes. Store sensitive data at your own risk.
      </div>
    </div>
  );
};

export default Dashboard;
