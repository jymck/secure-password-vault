import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const AddPassword = () => {
  const [formData, setFormData] = useState({
    title: '',
    username: '',
    password: '',
    url: '',
    notes: '',
    category: 'Other'
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [categories, setCategories] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    fetchCategories();
  }, []);

  const fetchCategories = async () => {
    try {
      const response = await axios.get('/api/categories', {
        withCredentials: true
      });
      setCategories(response.data.categories);
    } catch (error) {
      console.error('Failed to fetch categories:', error);
    }
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const checkPasswordStrength = (password) => {
    if (!password) return { strength: 'weak', score: 0 };
    
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password)) score++;
    if (/[^a-zA-Z\d]/.test(password)) score++;
    
    if (score <= 2) return { strength: 'weak', score };
    if (score <= 4) return { strength: 'medium', score };
    return { strength: 'strong', score };
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

    if (!formData.title || !formData.password) {
      setError('Title and password are required');
      setLoading(false);
      return;
    }

    try {
      await axios.post('/api/passwords', formData, {
        withCredentials: true
      });

      setSuccess('Password saved successfully!');
      setTimeout(() => {
        navigate('/passwords');
      }, 1500);
    } catch (error) {
      setError(error.response?.data?.error || 'Failed to save password');
    } finally {
      setLoading(false);
    }
  };

  const passwordStrength = checkPasswordStrength(formData.password);

  return (
    <div className="card">
      <h3>Add New Password</h3>
      {error && <div className="error">{error}</div>}
      {success && <div className="success">{success}</div>}
      
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="title">Title *</label>
          <input
            type="text"
            id="title"
            name="title"
            value={formData.title}
            onChange={handleChange}
            required
            placeholder="e.g., Gmail Account"
          />
        </div>

        <div className="form-group">
          <label htmlFor="category">Category</label>
          <select
            id="category"
            name="category"
            value={formData.category}
            onChange={handleChange}
            required
          >
            {categories.map((category, index) => (
              <option key={index} value={category}>
                {category}
              </option>
            ))}
          </select>
        </div>

        <div className="form-group">
          <label htmlFor="username">Username/Email</label>
          <input
            type="text"
            id="username"
            name="username"
            value={formData.username}
            onChange={handleChange}
            placeholder="e.g., john.doe@gmail.com"
          />
        </div>

        <div className="form-group">
          <label htmlFor="password">Password *</label>
          <div style={{ display: 'flex', gap: '10px' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              id="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              required
              placeholder="Enter password"
              style={{ flex: 1 }}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="btn btn-secondary"
            >
              {showPassword ? 'Hide' : 'Show'}
            </button>
          </div>
          {formData.password && (
            <div>
              <div 
                className="strength-indicator"
                style={{ 
                  backgroundColor: getPasswordStrengthColor(passwordStrength.strength),
                  width: `${(passwordStrength.score / 6) * 100}%`
                }}
              />
              <div className={`password-strength-text strength-${passwordStrength.strength}`}>
                Password strength: {passwordStrength.strength} ({passwordStrength.score}/6)
              </div>
            </div>
          )}
        </div>

        <div className="form-group">
          <label htmlFor="url">URL</label>
          <input
            type="url"
            id="url"
            name="url"
            value={formData.url}
            onChange={handleChange}
            placeholder="e.g., https://gmail.com"
          />
        </div>

        <div className="form-group">
          <label htmlFor="notes">Notes</label>
          <textarea
            id="notes"
            name="notes"
            value={formData.notes}
            onChange={handleChange}
            rows={4}
            placeholder="Additional notes..."
          />
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button type="submit" className="btn" disabled={loading}>
            {loading ? 'Saving...' : 'Save Password'}
          </button>
          <button
            type="button"
            onClick={() => navigate('/passwords')}
            className="btn btn-secondary"
          >
            Cancel
          </button>
        </div>
      </form>
      <div style={{ textAlign: 'center', padding: '15px', fontSize: '11px', color: '#999', lineHeight: '1.4' }}>
        Developed by YCR
      </div>
      <div style={{ textAlign: 'center', padding: '0 0 20px 0', fontSize: '10px', color: '#999', lineHeight: '1.4', fontStyle: 'italic' }}>
        This application is for educational purposes. Store sensitive data at your own risk.
      </div>
    </div>
  );
};

export default AddPassword;
