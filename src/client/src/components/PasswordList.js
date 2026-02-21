import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const PasswordList = () => {
  const [passwords, setPasswords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [visiblePasswords, setVisiblePasswords] = useState({});
  const [passwordValues, setPasswordValues] = useState({});
  const [deleteModal, setDeleteModal] = useState({ show: false, passwordId: null, passwordTitle: '' });
  const [confirmText, setConfirmText] = useState('');
  const [groupByCategory, setGroupByCategory] = useState(true);
  const [backupModal, setBackupModal] = useState({ show: false, type: '' });
  const [restoreFile, setRestoreFile] = useState(null);
  const [backupStatus, setBackupStatus] = useState('');

  useEffect(() => {
    fetchPasswords();
  }, []);

  // Backup passwords to Excel
  const [backupPassword, setBackupPassword] = useState('');
  
  const handleBackup = async () => {
    if (!backupPassword) {
      setBackupModal({ show: true, type: 'backup' });
      return;
    }
    
    try {
      setBackupStatus('Creating backup...');
      const response = await axios.post('/api/backup', 
        { password: backupPassword },
        {
          withCredentials: true,
          responseType: 'blob'
        }
      );
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `password-backup-${new Date().toISOString().split('T')[0]}.xlsx`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
      
      setBackupStatus('Backup downloaded successfully! 🔐 Excel is password-protected with your password.');
      setBackupPassword('');
      setBackupModal({ show: false, type: '' });
      setTimeout(() => setBackupStatus(''), 5000);
    } catch (error) {
      setBackupStatus('Backup failed. Please check your password and try again.');
      setTimeout(() => setBackupStatus(''), 3000);
    }
  };

  // Restore passwords from Excel
  const handleRestore = async () => {
    if (!restoreFile) {
      setError('Please select a backup file');
      return;
    }

    const formData = new FormData();
    formData.append('backupFile', restoreFile);

    try {
      setBackupStatus('Restoring passwords...');
      const response = await axios.post('/api/restore', formData, {
        withCredentials: true,
        headers: { 'Content-Type': 'multipart/form-data' }
      });
      
      setBackupStatus(`Restore completed! ${response.data.imported} passwords imported.`);
      fetchPasswords(); // Refresh the list
      setBackupModal({ show: false, type: '' });
      setRestoreFile(null);
      setTimeout(() => setBackupStatus(''), 5000);
    } catch (error) {
      setBackupStatus('Restore failed. Please check the file and try again.');
      setTimeout(() => setBackupStatus(''), 5000);
    }
  };

  const fetchPasswords = async () => {
    try {
      const response = await axios.get('/api/passwords', {
        withCredentials: true
      });
      setPasswords(response.data);
    } catch (error) {
      setError('Failed to fetch passwords');
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteClick = (id, title) => {
    setDeleteModal({ show: true, passwordId: id, passwordTitle: title });
  };

  const confirmDelete = async () => {
    if (confirmText.toLowerCase() !== 'confirm') {
      setError('Please type "confirm" to delete this password');
      return;
    }

    try {
      await axios.delete(`/api/passwords/${deleteModal.passwordId}`, {
        withCredentials: true
      });
      setPasswords(passwords.filter(p => p.id !== deleteModal.passwordId));
      setDeleteModal({ show: false, passwordId: null, passwordTitle: '' });
      setConfirmText('');
      setError('');
    } catch (error) {
      setError('Failed to delete password');
    }
  };

  const cancelDelete = () => {
    setDeleteModal({ show: false, passwordId: null, passwordTitle: '' });
    setConfirmText('');
    setError('');
  };

  const togglePasswordVisibility = async (id) => {
    if (!visiblePasswords[id]) {
      // Fetch actual password when showing
      try {
        const response = await axios.get(`/api/passwords/${id}`, {
          withCredentials: true
        });
        // The server now returns decrypted password in password_encrypted field
        setPasswordValues(prev => ({
          ...prev,
          [id]: response.data.password_encrypted
        }));
      } catch (error) {
        setError('Failed to fetch password');
        return;
      }
    }
    setVisiblePasswords(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(() => {
      console.log('Password copied to clipboard');
    }).catch(err => {
      console.error('Failed to copy password:', err);
    });
  };

  const filteredPasswords = passwords.filter(password =>
    password.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (password.username && password.username.toLowerCase().includes(searchTerm.toLowerCase())) ||
    (password.url && password.url.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  const groupPasswordsByCategory = (passwords) => {
    const grouped = {};
    passwords.forEach(password => {
      const category = password.category || 'Other';
      if (!grouped[category]) {
        grouped[category] = [];
      }
      grouped[category].push(password);
    });
    return grouped;
  };

  const groupedPasswords = groupByCategory ? groupPasswordsByCategory(filteredPasswords) : { 'All Passwords': filteredPasswords };

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
      </div>
    );
  }

  return (
    <div className="card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <Link to="/dashboard" className="btn btn-secondary" style={{ padding: '8px 16px', fontSize: '14px' }}>
            ← Back to Dashboard
          </Link>
          <h3 style={{ margin: 0 }}>Your Passwords</h3>
        </div>
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <label style={{ fontSize: '14px', color: '#666' }}>
            <input
              type="checkbox"
              checked={groupByCategory}
              onChange={(e) => setGroupByCategory(e.target.checked)}
              style={{ marginRight: '5px' }}
            />
            Group by Category
          </label>
          <button
            onClick={handleBackup}
            className="btn btn-secondary"
            style={{ padding: '8px 16px', fontSize: '14px' }}
          >
            📥 Backup
          </button>
          <button
            onClick={() => setBackupModal({ show: true, type: 'restore' })}
            className="btn btn-success"
            style={{ padding: '8px 16px', fontSize: '14px' }}
          >
            📤 Restore
          </button>
          <Link to="/add-password" className="btn">
            Add New Password
          </Link>
        </div>
      </div>

      {error && <div className="error">{error}</div>}

      <div className="form-group" style={{ marginBottom: '20px' }}>
        <input
          type="text"
          placeholder="Search passwords..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          style={{ maxWidth: '400px' }}
        />
      </div>

      {Object.keys(groupedPasswords).length > 0 ? (
        <div className="password-list">
          {Object.entries(groupedPasswords).map(([category, categoryPasswords]) => (
            <div key={category} style={{ marginBottom: '30px' }}>
              <h4 style={{ 
                background: '#f8f9fa', 
                padding: '10px 15px', 
                borderRadius: '8px', 
                marginBottom: '15px',
                border: '1px solid #dee2e6',
                fontSize: '14px',
                color: '#495057'
              }}>
                {category} ({categoryPasswords.length})
              </h4>
              {categoryPasswords.map(password => (
                <div key={password.id} className="password-item">
                  <h4>{password.title}</h4>
                  <div className="password-details">
                    {password.username && <p><strong>Username:</strong> {password.username}</p>}
                    <p>
                      <strong>Password:</strong>{' '}
                      {visiblePasswords[password.id] ? (
                        <span style={{ fontFamily: 'monospace', background: '#f0f0f0', padding: '4px 8px', borderRadius: '4px' }}>
                          {passwordValues[password.id] || 'Loading...'}
                        </span>
                      ) : (
                        <span style={{ fontFamily: 'monospace', letterSpacing: '2px' }}>••••••••••••</span>
                      )}
                      <button
                        onClick={() => togglePasswordVisibility(password.id)}
                        className="btn btn-secondary"
                        style={{ marginLeft: '10px', padding: '4px 8px', fontSize: '12px' }}
                      >
                        {visiblePasswords[password.id] ? 'Hide' : 'Show'}
                      </button>
                      {visiblePasswords[password.id] && passwordValues[password.id] && (
                        <button
                          onClick={() => copyToClipboard(passwordValues[password.id])}
                          className="btn btn-success"
                          style={{ marginLeft: '5px', padding: '4px 8px', fontSize: '12px' }}
                        >
                          Copy
                        </button>
                      )}
                    </p>
                    {password.url && (
                      <p>
                        <strong>URL:</strong>{' '}
                        <a href={password.url} target="_blank" rel="noopener noreferrer" style={{ color: '#667eea' }}>
                          {password.url}
                        </a>
                      </p>
                    )}
                    <p><strong>Created:</strong> {new Date(password.created_at).toLocaleDateString()}</p>
                    <p><strong>Updated:</strong> {new Date(password.updated_at).toLocaleDateString()}</p>
                  </div>
                  <div className="actions">
                    <Link to={`/edit-password/${password.id}`} className="btn btn-secondary">
                      Edit
                    </Link>
                    <button
                      onClick={() => handleDeleteClick(password.id, password.title)}
                      className="btn btn-danger"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>
      ) : (
        <div style={{ textAlign: 'center', padding: '40px', color: '#666' }}>
          <h3>{searchTerm ? 'No passwords found' : 'No passwords yet'}</h3>
          <p>{searchTerm ? 'Try adjusting your search terms.' : 'Start by adding your first password to the vault.'}</p>
          {!searchTerm && (
            <Link to="/add-password" className="btn" style={{ marginTop: '20px' }}>
              Add Your First Password
            </Link>
          )}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModal.show && (
        <div className="modal">
          <div className="modal-content">
            <div className="modal-header">
              <h2>⚠️ Delete Password</h2>
              <button className="close-btn" onClick={cancelDelete}>
                ×
              </button>
            </div>
            <div style={{ marginBottom: '20px' }}>
              <p style={{ fontSize: '16px', marginBottom: '10px' }}>
                Are you sure you want to delete this password?
              </p>
              <div style={{ 
                background: '#f8f9fa', 
                border: '1px solid #dee2e6', 
                borderRadius: '8px', 
                padding: '15px',
                marginBottom: '15px'
              }}>
                <strong>{deleteModal.passwordTitle}</strong>
              </div>
              <p style={{ color: '#dc3545', fontSize: '14px', fontWeight: 'bold', marginBottom: '15px' }}>
                This password data will be permanently deleted.
              </p>
              <div className="form-group">
                <label htmlFor="confirmText">
                  Type <strong>"confirm"</strong> to delete this password:
                </label>
                <input
                  type="text"
                  id="confirmText"
                  value={confirmText}
                  onChange={(e) => setConfirmText(e.target.value)}
                  placeholder="Type confirm here"
                  autoComplete="off"
                  style={{ marginTop: '5px' }}
                />
              </div>
              {error && <div className="error" style={{ marginTop: '10px' }}>{error}</div>}
            </div>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={cancelDelete}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                className="btn btn-danger"
                disabled={confirmText.toLowerCase() !== 'confirm'}
              >
                Delete Password
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Backup Password Modal */}
      {backupModal.show && backupModal.type === 'backup' && (
        <div className="modal">
          <div className="modal-content">
            <div className="modal-header">
              <h2>📥 Backup Passwords</h2>
              <button className="close-btn" onClick={() => { setBackupModal({ show: false, type: '' }); setBackupPassword(''); }}>
                ×
              </button>
            </div>
            <div style={{ marginBottom: '20px' }}>
              <p style={{ fontSize: '14px', marginBottom: '15px', color: '#666' }}>
                Enter your login password to create a password-protected backup.
              </p>
              <p style={{ fontSize: '12px', color: '#28a745', marginBottom: '15px' }}>
                ✓ The Excel file will be protected with this password.
              </p>
              <input
                type="password"
                placeholder="Enter your password"
                value={backupPassword}
                onChange={(e) => setBackupPassword(e.target.value)}
                style={{ padding: '10px', border: '1px solid #ddd', borderRadius: '4px', width: '100%' }}
              />
            </div>
            {backupStatus && (
              <div style={{ 
                padding: '10px', 
                background: backupStatus.includes('failed') ? '#f8d7da' : '#d4edda',
                border: `1px solid ${backupStatus.includes('failed') ? '#f5c6cb' : '#c3e6cb'}`,
                borderRadius: '4px',
                marginBottom: '15px',
                fontSize: '14px',
                color: backupStatus.includes('failed') ? '#721c24' : '#155724'
              }}>
                {backupStatus}
              </div>
            )}
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => { setBackupModal({ show: false, type: '' }); setBackupPassword(''); }}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleBackup}
                className="btn"
                disabled={!backupPassword}
              >
                Create Backup
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Restore Modal */}
      {backupModal.show && backupModal.type === 'restore' && (
        <div className="modal">
          <div className="modal-content">
            <div className="modal-header">
              <h2>📤 Restore Passwords</h2>
              <button className="close-btn" onClick={() => setBackupModal({ show: false, type: '' })}>
                ×
              </button>
            </div>
            <div style={{ marginBottom: '20px' }}>
              <p style={{ fontSize: '14px', marginBottom: '15px', color: '#666' }}>
                Select a password-protected backup Excel file (.xlsx) to restore your passwords.
              </p>
              <p style={{ fontSize: '12px', color: '#dc3545', marginBottom: '15px' }}>
                ⚠️ Note: This will add passwords to your existing list. Use your <strong>login password</strong> to unlock the file.
              </p>
              <input
                type="file"
                accept=".xlsx"
                onChange={(e) => setRestoreFile(e.target.files[0])}
                style={{ padding: '10px', border: '1px solid #ddd', borderRadius: '4px', width: '100%' }}
              />
              {restoreFile && (
                <p style={{ fontSize: '12px', color: '#28a745', marginTop: '5px' }}>
                  ✓ Selected: {restoreFile.name}
                </p>
              )}
            </div>
            {backupStatus && (
              <div style={{ 
                padding: '10px', 
                background: backupStatus.includes('failed') ? '#f8d7da' : '#d4edda',
                border: `1px solid ${backupStatus.includes('failed') ? '#f5c6cb' : '#c3e6cb'}`,
                borderRadius: '4px',
                marginBottom: '15px',
                fontSize: '14px',
                color: backupStatus.includes('failed') ? '#721c24' : '#155724'
              }}>
                {backupStatus}
              </div>
            )}
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button
                onClick={() => {
                  setBackupModal({ show: false, type: '' });
                  setRestoreFile(null);
                  setBackupStatus('');
                }}
                className="btn btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={handleRestore}
                className="btn btn-success"
                disabled={!restoreFile}
              >
                Restore Passwords
              </button>
            </div>
          </div>
        </div>
      )}

      <div style={{ textAlign: 'center', padding: '15px', fontSize: '11px', color: '#999', lineHeight: '1.4' }}>
        Developed by YCR
      </div>
      <div style={{ textAlign: 'center', padding: '0 0 20px 0', fontSize: '10px', color: '#999', lineHeight: '1.4', fontStyle: 'italic' }}>
        This application is for educational purposes. Store sensitive data at your own risk.
      </div>
    </div>
  );
};

export default PasswordList;
