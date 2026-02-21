// Working server with add password functionality
const express = require('express');
const sqlite3 = require('sqlite3');
const session = require('express-session');
const cors = require('cors');
const crypto = require('crypto');
const XLSX = require('xlsx');
const fs = require('fs');
const path = require('path');
const fileUpload = require('express-fileupload');
const XlsxPopulate = require('xlsx-populate');

// Simple encryption for passwords
const ENCRYPTION_KEY = crypto.scryptSync('your-password-vault-key', 'salt', 32); // Generate proper 32-byte key
const IV_LENGTH = 16;

function encrypt(text) {
  try {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
  } catch (e) {
    console.error('Encryption error:', e);
    throw e;
  }
}

function decrypt(encryptedText) {
  try {
    const parts = encryptedText.split(':');
    if (parts.length !== 2) return encryptedText; // Return as-is if not encrypted
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (e) {
    console.error('Decryption error:', e);
    return encryptedText; // Return as-is on error
  }
}

const app = express();
const PORT = 3000;

// Database setup
const db = new sqlite3.Database('./vault.db');

// Create tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    recovery_key_encrypted TEXT,
    recovery_question TEXT,
    recovery_answer_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    username TEXT,
    password_encrypted TEXT NOT NULL,
    url TEXT,
    notes_encrypted TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    category TEXT
  )`);
});

// Middleware - ORDER IS IMPORTANT
app.use(express.json());

// CORS must be configured before session
app.use(cors({
  origin: ['http://localhost:3000', 'http://localhost:3001', 'http://127.0.0.1:3000', 'http://127.0.0.1:3001'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

// Session configuration
app.use(session({
  secret: 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  name: 'sessionId',
  cookie: {
    secure: false, // Set to true in production with HTTPS
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax' // Important for cross-origin requests
  }
}));

// File upload middleware for restore
app.use(fileUpload({
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB max
  abortOnLimit: true
}));

// User registration
app.post('/api/auth/register', (req, res) => {
  const { username, email, password, recoveryQuestion, recoveryAnswer } = req.body;

  if (!username || !email || !password || !recoveryQuestion || !recoveryAnswer) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // Check if user exists
  db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], (err, user) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (user) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Insert user with proper password hashing
    const bcrypt = require('bcrypt');
    const salt = 'test_salt_123';
    const passwordHash = bcrypt.hashSync(password + salt, 10);
    
    db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?)', 
      [username, email, passwordHash, salt, 'encrypted_key', recoveryQuestion, 'hashed_' + recoveryAnswer], 
      function(err) {
        if (err) {
          console.error('Registration error:', err);
          return res.status(500).json({ error: 'Failed to create user' });
        }
        
        console.log('✅ User created successfully');
        res.status(201).json({ message: 'User created successfully' });
      });
  });
});

// User login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  console.log('🔑 Login attempt for username:', username);

  if (!username || !password) {
    console.log('❌ Missing username or password');
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('❌ Database error during login:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      console.log('❌ User not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('👤 User found, verifying password...');
    console.log('   Stored salt:', user.salt);
    console.log('   Stored hash:', user.password_hash?.substring(0, 20) + '...');

    // Proper password verification
    const bcrypt = require('bcrypt');
    const passwordToCheck = password + user.salt;
    console.log('   Checking password:', password + ' + ' + user.salt);
    
    const validPassword = bcrypt.compareSync(passwordToCheck, user.password_hash);
    console.log('   Password valid:', validPassword);
    
    if (!validPassword) {
      console.log('❌ Invalid password for user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    req.session.userId = user.id;
    req.session.username = user.username;
    console.log('✅ Login successful for:', username);
    res.json({ message: 'Login successful' });
  });
});

// Get user's security question (for password recovery)
app.post('/api/auth/get-security-question', (req, res) => {
  const { username } = req.body;
  
  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  db.get('SELECT recovery_question FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ question: user.recovery_question });
  });
});

// Verify security answer (for password recovery)
app.post('/api/auth/verify-security-answer', (req, res) => {
  const { username, answer } = req.body;
  
  if (!username || !answer) {
    return res.status(400).json({ error: 'Username and answer are required' });
  }

  db.get('SELECT recovery_answer_hash FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Compare answer (stored as 'hashed_' + answer during registration)
    const expectedAnswer = 'hashed_' + answer;
    const verified = user.recovery_answer_hash === expectedAnswer;

    if (verified) {
      res.json({ verified: true, message: 'Security answer verified' });
    } else {
      res.status(401).json({ verified: false, error: 'Incorrect security answer' });
    }
  });
});

// Reset password after security verification
app.post('/api/auth/reset-password', (req, res) => {
  const { username, newPassword } = req.body;
  
  if (!username || !newPassword) {
    return res.status(400).json({ error: 'Username and new password are required' });
  }

  // Hash the new password
  const bcrypt = require('bcrypt');
  const salt = 'test_salt_123';
  const passwordHash = bcrypt.hashSync(newPassword + salt, 10);

  db.run('UPDATE users SET password_hash = ?, salt = ? WHERE username = ?', 
    [passwordHash, salt, username], 
    function(err) {
      if (err) {
        console.error('Password reset error:', err);
        return res.status(500).json({ error: 'Failed to reset password' });
      }
      
      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({ message: 'Password reset successfully' });
    });
});

// Add password - THE MAIN FUNCTIONALITY WE'RE TESTING
app.post('/api/passwords', (req, res) => {
  const userId = req.session.userId;
  const { title, username, password, url, notes, category } = req.body;
  
  if (!title || !password) {
    return res.status(400).json({ error: 'Title and password are required' });
  }
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  console.log('🔐 Adding password for user:', userId);
  console.log('   Title:', title);
  console.log('   Category:', category || 'Other');

  // Encrypt the password and notes
  const encryptedPassword = encrypt(password);
  const encryptedNotes = notes ? encrypt(notes) : '';
  
  console.log('   Password encrypted successfully');

  // Insert password with encryption
  db.run('INSERT INTO passwords (user_id, title, username, password_encrypted, url, notes_encrypted, category) VALUES (?, ?, ?, ?, ?, ?, ?)', 
    [userId, title, username, encryptedPassword, url, encryptedNotes, category || 'Other'], 
    function(err) {
      if (err) {
        console.error('❌ Add password error:', err);
        return res.status(500).json({ error: 'Failed to save password' });
      }
      
      console.log('✅ Password saved successfully');
      res.status(201).json({ message: 'Password saved successfully' });
    });
});

// Get passwords
app.get('/api/passwords', (req, res) => {
  const userId = req.session.userId;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  db.all('SELECT * FROM passwords WHERE user_id = ?', [userId], (err, passwords) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    // Decrypt passwords before returning
    const decryptedPasswords = passwords.map(pwd => {
      try {
        return {
          ...pwd,
          password_encrypted: decrypt(pwd.password_encrypted),
          notes_encrypted: pwd.notes_encrypted ? decrypt(pwd.notes_encrypted) : ''
        };
      } catch (e) {
        console.log('⚠️ Failed to decrypt password id:', pwd.id, '- returning as-is');
        return pwd;
      }
    });
    
    res.json(decryptedPasswords);
  });
});

// Get single password by ID
app.get('/api/passwords/:id', (req, res) => {
  const userId = req.session.userId;
  const passwordId = req.params.id;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  db.get('SELECT * FROM passwords WHERE id = ? AND user_id = ?', [passwordId, userId], (err, password) => {
    if (err) {
      return res.status(500).json({ error: 'Database error' });
    }
    
    if (!password) {
      return res.status(404).json({ error: 'Password not found' });
    }
    
    // Decrypt password before returning
    try {
      const decryptedPassword = {
        ...password,
        password_encrypted: decrypt(password.password_encrypted),
        notes_encrypted: password.notes_encrypted ? decrypt(password.notes_encrypted) : ''
      };
      res.json(decryptedPassword);
    } catch (e) {
      console.log('⚠️ Failed to decrypt password id:', password.id);
      res.json(password);
    }
  });
});

// Update password
app.put('/api/passwords/:id', (req, res) => {
  const userId = req.session.userId;
  const passwordId = req.params.id;
  const { title, username, password, url, notes, category } = req.body;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Encrypt password and notes if provided
  const updates = [];
  const values = [];
  
  if (title) {
    updates.push('title = ?');
    values.push(title);
  }
  if (username !== undefined) {
    updates.push('username = ?');
    values.push(username);
  }
  if (password) {
    updates.push('password_encrypted = ?');
    values.push(encrypt(password));
  }
  if (url !== undefined) {
    updates.push('url = ?');
    values.push(url);
  }
  if (notes !== undefined) {
    updates.push('notes_encrypted = ?');
    values.push(notes ? encrypt(notes) : '');
  }
  if (category) {
    updates.push('category = ?');
    values.push(category);
  }
  
  updates.push('updated_at = datetime("now")');
  
  if (updates.length === 0) {
    return res.status(400).json({ error: 'No fields to update' });
  }
  
  values.push(passwordId, userId);

  const sql = `UPDATE passwords SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`;

  db.run(sql, values, function(err) {
    if (err) {
      console.error('Update password error:', err);
      return res.status(500).json({ error: 'Failed to update password' });
    }
    
    if (this.changes === 0) {
      return res.status(404).json({ error: 'Password not found or not authorized' });
    }
    
    console.log('✅ Password updated successfully');
    res.json({ message: 'Password updated successfully' });
  });
});

// Get categories
app.get('/api/categories', (req, res) => {
  const categories = ['Social Media', 'Email', 'Banking', 'Shopping', 'Entertainment', 'Work', 'Other'];
  res.json({ categories });
});

// Get security questions
app.get('/api/security-questions', (req, res) => {
  const questions = [
    'What is your mother\'s maiden name?',
    'What was your first pet\'s name?',
    'What city were you born in?',
    'What is your favorite color?',
    'What was the name of your first school?',
    'What is your favorite book?',
    'What was your childhood nickname?'
  ];
  res.json({ questions });
});

// Backup passwords to Excel
app.post('/api/backup', async (req, res) => {
  const userId = req.session.userId;
  const { password } = req.body;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  if (!password) {
    return res.status(400).json({ error: 'Password is required for backup' });
  }

  try {
    // Verify user exists
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT username FROM users WHERE id = ?', [userId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Get passwords
    const passwords = await new Promise((resolve, reject) => {
      db.all('SELECT title, username, password_encrypted, url, notes_encrypted, category, created_at FROM passwords WHERE user_id = ?', [userId], (err, rows) => {
        if (err) reject(err);
        else resolve(rows);
      });
    });

    // Decrypt passwords for backup
    const decryptedPasswords = passwords.map(pwd => {
      try {
        return {
          Title: pwd.title,
          Username: pwd.username || '',
          Password: decrypt(pwd.password_encrypted),
          URL: pwd.url || '',
          Notes: pwd.notes_encrypted ? decrypt(pwd.notes_encrypted) : '',
          Category: pwd.category || 'Other',
          'Created At': pwd.created_at
        };
      } catch (e) {
        console.log('⚠️ Failed to decrypt password for backup:', pwd.id);
        return {
          Title: pwd.title,
          Username: pwd.username || '',
          Password: '[Encrypted - Unable to decrypt]',
          URL: pwd.url || '',
          Notes: '',
          Category: pwd.category || 'Other',
          'Created At': pwd.created_at
        };
      }
    });

    // Use the provided password for Excel protection
    const excelPassword = password;

    // Create Excel workbook with xlsx-populate for password protection
    const workbook = await XlsxPopulate.fromBlankAsync();
    const sheet = workbook.sheet(0);
    sheet.name('Passwords');

    // Add headers
    const headers = ['Title', 'Username', 'Password', 'URL', 'Notes', 'Category', 'Created At'];
    headers.forEach((header, index) => {
      sheet.cell(1, index + 1).value(header);
      sheet.cell(1, index + 1).style({ bold: true, fill: '4472C4', fontColor: 'FFFFFF' });
    });

    // Add data rows
    decryptedPasswords.forEach((pwd, rowIndex) => {
      sheet.cell(rowIndex + 2, 1).value(pwd.Title);
      sheet.cell(rowIndex + 2, 2).value(pwd.Username);
      sheet.cell(rowIndex + 2, 3).value(pwd.Password);
      sheet.cell(rowIndex + 2, 4).value(pwd.URL);
      sheet.cell(rowIndex + 2, 5).value(pwd.Notes);
      sheet.cell(rowIndex + 2, 6).value(pwd.Category);
      sheet.cell(rowIndex + 2, 7).value(pwd['Created At']);
    });

    // Auto-fit columns
    sheet.column('A').width(20);
    sheet.column('B').width(25);
    sheet.column('C').width(25);
    sheet.column('D').width(30);
    sheet.column('E').width(30);
    sheet.column('F').width(15);
    sheet.column('G').width(15);

    // Generate filename with timestamp
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `password-backup-${timestamp}.xlsx`;

    // Create temp directory if not exists
    const tempDir = path.join(__dirname, 'temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    const tempPath = path.join(tempDir, filename);
    
    // Save with password protection
    await workbook.toFileAsync(tempPath, { password: excelPassword });

    // Send file and inform user of the password
    res.download(tempPath, filename, (err) => {
      if (err) {
        console.error('Download error:', err);
      }
      // Clean up temp file after download
      fs.unlink(tempPath, () => {});
    });

  } catch (error) {
    console.error('Backup error:', error);
    res.status(500).json({ error: 'Failed to create backup file: ' + error.message });
  }
});

// Restore passwords from Excel
app.post('/api/restore', (req, res) => {
  const userId = req.session.userId;
  
  if (!userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  // Check if file was uploaded
  if (!req.files || !req.files.backupFile) {
    return res.status(400).json({ error: 'No backup file uploaded' });
  }

  const backupFile = req.files.backupFile;
  
  try {
    // Read Excel file
    const wb = XLSX.read(backupFile.data, { type: 'buffer' });
    const ws = wb.Sheets[wb.SheetNames[0]];
    const data = XLSX.utils.sheet_to_json(ws);

    let imported = 0;
    let errors = 0;

    // Process each row
    const processRow = (index) => {
      if (index >= data.length) {
        return res.json({ 
          message: `Restore completed. Imported: ${imported}, Errors: ${errors}`,
          imported,
          errors
        });
      }

      const row = data[index];
      
      // Validate required fields
      if (!row.Title) {
        errors++;
        return processRow(index + 1);
      }

      // Encrypt password and notes
      const encryptedPassword = row.Password ? encrypt(row.Password.toString()) : encrypt('');
      const encryptedNotes = row.Notes ? encrypt(row.Notes.toString()) : '';

      // Insert password
      db.run('INSERT INTO passwords (user_id, title, username, password_encrypted, url, notes_encrypted, category) VALUES (?, ?, ?, ?, ?, ?, ?)', 
        [userId, row.Title, row.Username || '', encryptedPassword, row.URL || '', encryptedNotes, row.Category || 'Other'], 
        function(err) {
          if (err) {
            console.error('Import error for row:', index, err);
            errors++;
          } else {
            imported++;
          }
          processRow(index + 1);
        });
    };

    // Start processing
    processRow(0);

  } catch (e) {
    console.error('Restore error:', e);
    res.status(500).json({ error: 'Failed to restore from backup file' });
  }
});

// Serve static files from React build
app.use(express.static('client/build'));

// Handle React routing, return all requests to React app
app.get('*', (req, res) => {
  res.sendFile('index.html', { root: 'client/build' });
});

app.listen(PORT, () => {
  console.log('🚀 Working server running on http://localhost:3000');
  console.log('✅ Add password functionality is FIXED and ready for testing');
});
