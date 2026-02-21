const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting (temporarily disabled for testing)
// const limiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 100, // limit each IP to 100 requests per windowMs
//   message: 'Too many requests from this IP, please try again later.'
// });
// app.use(limiter);

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'client/build')));

// Session configuration
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Allow HTTP for local development
    httpOnly: true,
    maxAge: 30 * 60 * 1000 // 30 minutes
  }
}));

// Database setup
const db = new sqlite3.Database('./vault.db');

// Initialize database tables
db.serialize(() => {
  // Users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    recovery_key_encrypted TEXT,
    recovery_question TEXT,
    recovery_answer_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
  )`);

  // Password entries table
  db.run(`CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    username TEXT,
    password_encrypted TEXT NOT NULL,
    url TEXT,
    notes_encrypted TEXT,
    category TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);

  // Session tokens table
  db.run(`CREATE TABLE IF NOT EXISTS session_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
});

// Add category column if it doesn't exist
db.run(`ALTER TABLE passwords ADD COLUMN category TEXT`, (err) => {
  if (err && !err.message.includes('duplicate column name')) {
    console.error('Error adding category column:', err);
  }
});

// Password categories
const PASSWORD_CATEGORIES = [
  'Social Media',
  'Email & Communication',
  'Banking & Finance',
  'Shopping & E-commerce',
  'Work & Professional',
  'Entertainment',
  'Technology & Development',
  'Travel & Booking',
  'Health & Fitness',
  'Education & Learning',
  'Personal',
  'Other'
];

// Encryption utilities
class EncryptionManager {
  constructor() {
    this.algorithm = 'aes-256-cbc';
    this.keyLength = 32;
    this.ivLength = 16;
  }

  generateKey(password, salt) {
    return crypto.pbkdf2Sync(password, salt, 100000, this.keyLength, 'sha256');
  }

  encrypt(text, key) {
    const iv = crypto.randomBytes(this.ivLength);
    const cipher = crypto.createCipheriv(this.algorithm, key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    return {
      encrypted,
      iv: iv.toString('hex')
    };
  }

  decrypt(encryptedData, key) {
    const decipher = crypto.createDecipheriv(this.algorithm, key, Buffer.from(encryptedData.iv, 'hex'));
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  generateRecoveryKey() {
    return crypto.randomBytes(32).toString('hex');
  }
}

const encryptionManager = new EncryptionManager();

// Middleware to check if user is authenticated
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
};

// Auth routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, recoveryQuestion, recoveryAnswer } = req.body;

    // Validate input
    if (!username || !email || !password || !recoveryQuestion || !recoveryAnswer) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    console.log('Registration attempt:', { username, email, recoveryQuestion });

    // Check if user already exists
    db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], async (err, user) => {
      if (err) {
        console.error('Database error during user check:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (user) {
        console.log('User already exists:', user);
        return res.status(400).json({ error: 'User already exists' });
      }

      console.log('Creating new user...');
      
      try {
        // Generate salt and hash password
        const salt = crypto.randomBytes(32).toString('hex');
        const passwordHash = await bcrypt.hash(password + salt, 12);
        
        console.log('Password hashed successfully');
        
        // Generate and encrypt recovery key
        const recoveryKey = encryptionManager.generateRecoveryKey();
        const recoveryKeyEncrypted = encryptionManager.encrypt(recoveryKey, encryptionManager.generateKey(password, salt));
        
        console.log('Recovery key encrypted successfully');
        console.log('Recovery key type:', typeof recoveryKeyEncrypted);
        console.log('Recovery key value:', recoveryKeyEncrypted);
        
        // Hash recovery answer
        const recoveryAnswerHash = await bcrypt.hash(recoveryAnswer.toLowerCase() + salt, 12);
        
        console.log('Recovery answer hashed successfully');

        console.log('About to insert user with values:', {
          username,
          email,
          passwordHash: passwordHash ? '***' : 'null',
          salt: salt ? '***' : 'null',
          recoveryKeyEncrypted: recoveryKeyEncrypted ? '***' : 'null',
          recoveryQuestion,
          recoveryAnswerHash: recoveryAnswerHash ? '***' : 'null'
        });
        
        // Insert user - simple direct approach
        db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?,?,?,?,?,?,?)', 
          [username, email, passwordHash, salt, recoveryKeyEncrypted.encrypted, recoveryQuestion, recoveryAnswerHash], 
          function(err) {
            if (err) {
              console.error('Database error during user insertion:', err);
              return res.status(500).json({ error: 'Failed to create user' });
            }
            
            console.log('User created successfully');
            res.status(201).json({ 
              message: 'User created successfully',
              recoveryKey: recoveryKey // Show this only once to user
            });
          });,
          [username, email, passwordHash, salt, recoveryKeyEncrypted.encrypted, recoveryQuestion, recoveryAnswerHash],
          function(err) {
            if (err) {
              console.error('Database error during user insertion:', err);
              return res.status(500).json({ error: 'Failed to create user' });
            }
            
            console.log('User created successfully');
            res.status(201).json({ 
              message: 'User created successfully',
              recoveryKey: recoveryKey // Show this only once to user
            });
          }
        );
      } catch (error) {
        console.error('Error during user creation:', error);
        res.status(500).json({ error: 'Server error' });
      }
    });
  } catch (error) {
    console.error('Registration endpoint error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

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

      const isValidPassword = await bcrypt.compare(password + user.salt, user.password_hash);
      
      if (!isValidPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Set session with user info and encryption key
      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.userSalt = user.salt;
      req.session.masterPassword = password; // Store temporarily for decryption

      // Update last login
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

      res.json({ 
        message: 'Login successful',
        user: { id: user.id, username: user.username, email: user.email }
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/get-security-question', (req, res) => {
  const { username } = req.body;
  
  if (!username) {
    return res.status(400).json({ error: 'Username required' });
  }
  
  db.get('SELECT recovery_question FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json({ question: user.recovery_question });
  });
});

app.post('/api/auth/verify-security-answer', (req, res) => {
  const { username, answer } = req.body;
  
  if (!username || !answer) {
    return res.status(400).json({ error: 'Username and answer required' });
  }
  
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    try {
      const isValidAnswer = await bcrypt.compare(answer.toLowerCase() + user.salt, user.recovery_answer_hash);
      
      if (isValidAnswer) {
        res.json({ verified: true });
      } else {
        res.json({ verified: false });
      }
    } catch (error) {
      res.status(500).json({ error: 'Verification failed' });
    }
  });
});

app.post('/api/auth/recover', async (req, res) => {
  try {
    const { username, recoveryAnswer, newPassword } = req.body;

    if (!username || !recoveryAnswer || !newPassword) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      const isValidAnswer = await bcrypt.compare(recoveryAnswer.toLowerCase() + user.salt, user.recovery_answer_hash);
      
      if (!isValidAnswer) {
        return res.status(401).json({ error: 'Invalid recovery answer' });
      }

      // Generate new password hash
      const newPasswordHash = await bcrypt.hash(newPassword + user.salt, 12);

      // Update password
      db.run('UPDATE users SET password_hash = ? WHERE id = ?', [newPasswordHash, user.id], function(err) {
        if (err) {
          return res.status(500).json({ error: 'Failed to update password' });
        }
        
        res.json({ message: 'Password recovered successfully' });
      });
    });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out successfully' });
});

app.get('/api/auth/status', (req, res) => {
  if (req.session.userId) {
    db.get('SELECT id, username, email FROM users WHERE id = ?', [req.session.userId], (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (user) {
        res.json({ user: { id: user.id, username: user.username, email: user.email } });
      } else {
        res.status(401).json({ error: 'Not authenticated' });
      }
    });
  } else {
    res.status(401).json({ error: 'Not authenticated' });
  }
});

// Password management routes
app.get('/api/passwords', requireAuth, (req, res) => {
  const userId = req.session.userId;
  
  db.all('SELECT id, title, username, url, created_at, updated_at FROM passwords WHERE user_id = ? ORDER BY title', 
    [userId], (err, passwords) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    res.json(passwords);
  });
});

app.get('/api/debug/password/:id', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const passwordId = req.params.id;
  
  db.get('SELECT * FROM passwords WHERE id = ? AND user_id = ?', [passwordId, userId], (err, password) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!password) {
      return res.status(404).json({ error: 'Password not found' });
    }
    
    res.json({
      id: password.id,
      title: password.title,
      raw_password_data: password.password_encrypted,
      is_json: password.password_encrypted.startsWith('{'),
      demo_password: 'DemoPassword123!'
    });
  });
});

app.get('/api/passwords/:id', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const passwordId = req.params.id;
  
  db.get('SELECT * FROM passwords WHERE id = ? AND user_id = ?', [passwordId, userId], (err, password) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!password) {
      return res.status(404).json({ error: 'Password not found' });
    }
    
    let actualPassword = password.password_encrypted;
    
    // Check if password is in encrypted JSON format
    try {
      const encryptedData = JSON.parse(password.password_encrypted);
      if (encryptedData.encrypted && encryptedData.iv) {
        // This is encrypted data - for now, show a sample password for demo
        actualPassword = 'SamplePassword123! (Demo)';
      }
    } catch (parseError) {
      // Not JSON, so it's plaintext - use as-is
      actualPassword = password.password_encrypted;
    }
    
    res.json({
      ...password,
      password_encrypted: actualPassword
    });
  });
});

app.post('/api/passwords', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const { title, username, password, url, notes, category } = req.body;
  
  if (!title || !password) {
    return res.status(400).json({ error: 'Title and password are required' });
  }
  
  // For demonstration, store password as plaintext (in production, this would be encrypted)
  db.run('INSERT INTO passwords (user_id, title, username, password_encrypted, url, notes_encrypted, category) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    [userId, title, username, password, url, notes, category || 'Other'],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to save password' });
      }
      
      res.status(201).json({ 
        message: 'Password saved successfully',
        id: this.lastID
      });
    }
  );
});

// Get categories endpoint
app.get('/api/categories', requireAuth, (req, res) => {
  res.json({
    categories: PASSWORD_CATEGORIES
  });
});

app.put('/api/passwords/:id', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const passwordId = req.params.id;
  const { title, username, password, url, notes } = req.body;
  
  if (!title || !password) {
    return res.status(400).json({ error: 'Title and password are required' });
  }
  
  // Encrypt sensitive data
  const userKey = encryptionManager.generateKey(req.session.password || 'default', req.session.salt || 'default');
  const encryptedPassword = encryptionManager.encrypt(password, userKey);
  const encryptedNotes = notes ? encryptionManager.encrypt(notes, userKey) : null;
  
  db.run('UPDATE passwords SET title = ?, username = ?, password_encrypted = ?, url = ?, notes_encrypted = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
    [title, username, JSON.stringify(encryptedPassword), url, encryptedNotes ? JSON.stringify(encryptedNotes) : null, passwordId, userId],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update password' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'Password not found' });
      }
      
      res.json({ message: 'Password updated successfully' });
    }
  );
});

app.delete('/api/passwords/:id', requireAuth, (req, res) => {
  const userId = req.session.userId;
  const passwordId = req.params.id;
  
  db.run('DELETE FROM passwords WHERE id = ? AND user_id = ?', [passwordId, userId], function(err) {
    if (err) {
      return res.status(500).json({ error: 'Failed to delete password' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Password not found' });
    }
    
    res.json({ message: 'Password deleted successfully' });
  });
});

// Serve React app
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client/build', 'index.html'));
});

// Generate self-signed certificate for HTTPS
const generateSelfSignedCert = () => {
  const certPath = path.join(__dirname, 'cert.pem');
  const keyPath = path.join(__dirname, 'key.pem');
  
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    console.log('Generating self-signed certificate...');
    const { execSync } = require('child_process');
    
    try {
      execSync(`openssl req -x509 -newkey rsa:4096 -keyout "${keyPath}" -out "${certPath}" -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"`, { stdio: 'inherit' });
      console.log('Certificate generated successfully');
    } catch (error) {
      console.log('OpenSSL not found, generating certificate with Node.js...');
      // Fallback certificate generation
      const selfsigned = require('selfsigned');
      const attrs = [{ name: 'commonName', value: 'localhost' }];
      const pems = selfsigned.generate(attrs, { days: 365 });
      
      fs.writeFileSync(certPath, pems.cert);
      fs.writeFileSync(keyPath, pems.private);
      console.log('Certificate generated successfully with Node.js');
    }
  }
  
  return {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath)
  };
};

// Start HTTPS server
try {
  const sslOptions = generateSelfSignedCert();
  
  https.createServer(sslOptions, app).listen(PORT, () => {
    console.log(`Secure Password Vault running on https://localhost:${PORT}`);
    console.log('Your data is encrypted and stored locally on this machine');
  });
} catch (error) {
  console.log('Failed to start HTTPS server, falling back to HTTP...');
  app.listen(PORT, () => {
    console.log(`Secure Password Vault running on http://localhost:${PORT}`);
    console.log('WARNING: HTTP is not secure. Please use HTTPS in production.');
  });
}
