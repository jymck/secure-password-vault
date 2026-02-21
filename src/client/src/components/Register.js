import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import logo from '../logo.svg';

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    recoveryQuestion: '',
    recoveryAnswer: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [recoveryKey, setRecoveryKey] = useState('');
  const [showRecoveryKey, setShowRecoveryKey] = useState(false);
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
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

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      setLoading(false);
      return;
    }

    if (checkPasswordStrength(formData.password) === 'weak') {
      setError('Password is too weak. Please use a stronger password.');
      setLoading(false);
      return;
    }

    try {
      const response = await axios.post('/api/auth/register', {
        username: formData.username,
        email: formData.email,
        password: formData.password,
        recoveryQuestion: formData.recoveryQuestion,
        recoveryAnswer: formData.recoveryAnswer
      });

      setRecoveryKey(response.data.recoveryKey);
      setShowRecoveryKey(true);
      setSuccess('Account created successfully!');
    } catch (error) {
      setError(error.response?.data?.error || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRecoveryKeySaved = () => {
    navigate('/login');
  };

  if (showRecoveryKey) {
    return (
      <div className="auth-card">
        <h2>Save Your Recovery Key</h2>
        {success && <div className="success">{success}</div>}
        <div className="recovery-key">
          <strong>Recovery Key:</strong>
          <div>{recoveryKey}</div>
          <div className="warning">
            ⚠️ Save this key in a secure location. You will need it to recover your account if you forget your password.
          </div>
        </div>
        <button className="btn btn-success" onClick={handleRecoveryKeySaved}>
          I have saved my recovery key
        </button>
      </div>
    );
  }

  const passwordStrength = checkPasswordStrength(formData.password);

  return (
    <div className="auth-card">
      <div className="logo-container">
        <img src={logo} alt="Secure Password Vault Logo" className="logo-image" />
        <div>
          <h1>Create Account</h1>
          <p>Join Secure Password Vault</p>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            name="username"
            value={formData.username}
            onChange={handleChange}
            required
            autoComplete="username"
          />
        </div>
        <div className="form-group">
          <label htmlFor="email">Email</label>
          <input
            type="email"
            id="email"
            name="email"
            value={formData.email}
            onChange={handleChange}
            required
            autoComplete="email"
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            required
            autoComplete="new-password"
          />
          {formData.password && (
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
          <label htmlFor="confirmPassword">Confirm Password</label>
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
        <div className="form-group">
          <label htmlFor="recoveryQuestion">Recovery Question</label>
          <select
            id="recoveryQuestion"
            name="recoveryQuestion"
            value={formData.recoveryQuestion}
            onChange={handleChange}
            required
          >
            <option value="">Select a question</option>
            <option value="What was your first pet's name?">What was your first pet's name?</option>
            <option value="What is your mother's maiden name?">What is your mother's maiden name?</option>
            <option value="What city were you born in?">What city were you born in?</option>
            <option value="What was your first school's name?">What was your first school's name?</option>
            <option value="What is your favorite book?">What is your favorite book?</option>
          </select>
        </div>
        <div className="form-group">
          <label htmlFor="recoveryAnswer">Recovery Answer</label>
          <input
            type="text"
            id="recoveryAnswer"
            name="recoveryAnswer"
            value={formData.recoveryAnswer}
            onChange={handleChange}
            required
          />
        </div>
        <button type="submit" className="btn" disabled={loading}>
          {loading ? 'Creating Account...' : 'Create Account'}
        </button>
      </form>
      <div className="auth-links">
        <p>
          Already have an account? <Link to="/login">Login</Link>
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

export default Register;
