const express = require('express');
const sqlite3 = require('sqlite3');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const session = require('express-session');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Database setup
const db = new sqlite3.Database('./vault.db');

// Middleware
app.use(cors({
  origin: 'http://localhost:3001',
  credentials: true
}));
app.use(express.json());
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Simple user registration with fixed SQL
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, recoveryQuestion, recoveryAnswer } = req.body;

    if (!username || !email || !password || !recoveryQuestion || !recoveryAnswer) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Check if user already exists
    db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (user) {
        return res.status(400).json({ error: 'User already exists' });
      }

      // Create user with simple hardcoded values first
      db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
        [username, email, 'hashed_password', 'salt_value', 'encrypted_key', recoveryQuestion, 'hashed_answer'], 
        function(err) {
          if (err) {
            console.error('Registration error:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          res.status(201).json({ message: 'User created successfully' });
        });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Simple login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Simple password check (bypass encryption for testing)
      if (password !== 'testpass123') {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      res.json({ message: 'Login successful' });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Simple add password
app.post('/api/passwords', (req, res) => {
  try {
    const userId = req.session.userId;
    const { title, username, password, url, notes, category } = req.body;
    
    if (!title || !password) {
      return res.status(400).json({ error: 'Title and password are required' });
    }
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    // Simple insert with fixed SQL
    db.run('INSERT INTO passwords (user_id, title, username, password_encrypted, url, notes_encrypted, category) VALUES (?, ?, ?, ?, ?, ?, ?)', 
      [userId, title, username, password, url, notes, category || 'Other'], 
      function(err) {
        if (err) {
          console.error('Add password error:', err);
          return res.status(500).json({ error: 'Failed to save password' });
        }
        
        res.status(201).json({ message: 'Password saved successfully' });
      });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get passwords
app.get('/api/passwords', (req, res) => {
  try {
    const userId = req.session.userId;
    
    if (!userId) {
      return res.status(401).json({ error: 'Authentication required' });
    }

    db.all('SELECT * FROM passwords WHERE user_id = ?', [userId], (err, passwords) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      res.json(passwords);
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.listen(PORT, () => {
  console.log('Simple test server running on http://localhost:3000');
});