import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import logo from '../logo.svg';

const Recovery = () => {
  const [formData, setFormData] = useState({
    username: '',
    recoveryAnswer: '',
    newPassword: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [securityQuestion, setSecurityQuestion] = useState('');
  const [showSecurityQuestion, setShowSecurityQuestion] = useState(false);
  const [securityVerified, setSecurityVerified] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const fetchSecurityQuestion = async () => {
    if (!formData.username.trim()) {
      setError('Please enter your username first');
      return;
    }

    try {
      const response = await axios.post('/api/auth/get-security-question', {
        username: formData.username
      });

      if (response.data.question) {
        setSecurityQuestion(response.data.question);
        setShowSecurityQuestion(true);
        setError('');
      } else {
        setError('User not found');
      }
    } catch (error) {
      setError('Failed to fetch security question');
    }
  };

  const verifySecurityAnswer = async () => {
    if (!formData.recoveryAnswer.trim()) {
      setError('Please answer the security question');
      return;
    }

    try {
      const response = await axios.post('/api/auth/verify-security-answer', {
        username: formData.username,
        answer: formData.recoveryAnswer
      });

      if (response.data.verified) {
        setSecurityVerified(true);
        setError('');
        setSuccess('Security verified! You can now set a new password.');
      } else {
        setError('Incorrect security answer');
        setSecurityVerified(false);
      }
    } catch (error) {
      setError('Security verification failed');
      setSecurityVerified(false);
    }
  };

  const checkPasswordStrength = (password) => {
    let strength = 0;
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) strength++;
    if (/\d/.test(password)) strength++;
    if (/[^a-zA-Z\d]/.test(password)) strength++;
    
    if (strength <= 2) return 'weak';
    if (strength <= 4) return 'medium';
    return 'strong';
  };

  const getPasswordStrengthColor = (strength) => {
    switch (strength) {
      case 'weak': return '#dc3545';
      case 'medium': return '#ffc107';
      case 'strong': return '#28a745';
      default: return '#dee2e6';
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setSuccess('');

    if (formData.newPassword !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (checkPasswordStrength(formData.newPassword) === 'weak') {
      setError('Password is too weak. Please use a stronger password.');
      setLoading(false);
      return;
    }

    try {
      const response = await axios.post('/api/auth/recover', {
        username: formData.username,
        recoveryAnswer: formData.recoveryAnswer,
        newPassword: formData.newPassword
      });

      setSuccess('Password recovered successfully! Redirecting to login...');
      setTimeout(() => {
        navigate('/login');
      }, 2000);
    } catch (error) {
      setError(error.response?.data?.error || 'Recovery failed');
    } finally {
      setLoading(false);
    }
  };

  const passwordStrength = checkPasswordStrength(formData.newPassword);

  return (
    <div className="auth-card">
      <div className="logo-container">
        <img src={logo} alt="Secure Password Vault Logo" className="logo-image" />
        <div>
          <h1>Change Password</h1>
          <p>Reset Your Vault Access</p>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {success && <div className="success">{success}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              required
              autoComplete="username"
              style={{ flex: 1 }}
            />
            <button
              type="button"
              onClick={fetchSecurityQuestion}
              className="btn btn-secondary"
              disabled={!formData.username.trim()}
            >
              Get Question
            </button>
          </div>
        </div>
        
        {showSecurityQuestion && (
          <div className="form-group">
            <label><strong>Security Question:</strong></label>
            <div style={{ 
              background: '#f8f9fa', 
              border: '1px solid #dee2e6', 
              borderRadius: '8px', 
              padding: '15px',
              marginBottom: '15px',
              fontStyle: 'italic',
              color: '#495057'
            }}>
              {securityQuestion}
            </div>
          </div>
        )}
        
        <div className="form-group">
          <label htmlFor="recoveryAnswer">Recovery Answer</label>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input
              type="text"
              id="recoveryAnswer"
              name="recoveryAnswer"
              value={formData.recoveryAnswer}
              onChange={handleChange}
              required
              placeholder="Enter your answer to the security question"
              disabled={!showSecurityQuestion}
              style={{ flex: 1 }}
            />
            <button
              type="button"
              onClick={verifySecurityAnswer}
              className="btn btn-secondary"
              disabled={!showSecurityQuestion || !formData.recoveryAnswer.trim() || securityVerified}
            >
              {securityVerified ? 'Verified ✓' : 'Verify'}
            </button>
          </div>
          {!showSecurityQuestion && (
            <small style={{ color: '#6c757d', fontSize: '12px' }}>
              Please enter your username and click "Get Question" first
            </small>
          )}
        </div>

        {securityVerified && (
          <>
            <div className="form-group">
              <label htmlFor="newPassword">New Password</label>
              <input
                type="password"
                id="newPassword"
                name="newPassword"
                value={formData.newPassword}
                onChange={handleChange}
                required
                autoComplete="new-password"
              />
              {formData.newPassword && (
                <div>
                  <div 
                    className="strength-indicator"
                    style={{ backgroundColor: getPasswordStrengthColor(passwordStrength) }}
                  />
                  <div className={`password-strength-text strength-${passwordStrength}`}>
                    Password strength: {passwordStrength}
                  </div>
                </div>
              )}
            </div>

            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm New Password</label>
              <input
                type="password"
                id="confirmPassword"
                name="confirmPassword"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
                autoComplete="new-password"
              />
            </div>
          </>
        )}

        {!securityVerified && showSecurityQuestion && (
          <div style={{ 
            background: '#e3f2fd', 
            border: '1px solid #2196f3', 
            borderRadius: '8px', 
            padding: '15px',
            marginBottom: '20px',
            textAlign: 'center',
            color: '#1976d2'
          }}>
            🔒 Answer the security question above to set a new password
          </div>
        )}
        {securityVerified && (
        <button type="submit" className="btn" disabled={loading}>
          {loading ? 'Changing Password...' : 'Change Password'}
        </button>
      )}
      </form>
      <div className="auth-links">
        <p>
          <Link to="/login">Back to Login</Link>
        </p>
        <p style={{ marginTop: '15px', fontSize: '11px', color: '#999', lineHeight: '1.4' }}>
          Developed by YCR
        </p>
        <p style={{ fontSize: '10px', color: '#999', lineHeight: '1.4', fontStyle: 'italic' }}>
          This application is for educational purposes. Store sensitive data at your own risk.
        </p>
      </div>
    </div>
  );
};

export default Recovery;
