// Fix server.js by using prepared statements with explicit parameter binding
const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

// Replace the problematic INSERT with a prepared statement approach
const oldInsert = `db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'`;

const newInsert = `// Use prepared statement for better reliability
    const stmt = db.prepare('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
    stmt.run([username, email, passwordHash, salt, recoveryKeyEncrypted.encrypted, recoveryQuestion, recoveryAnswerHash], function(err) {
      if (err) {
        console.error('Database error during user insertion:', err);
        return res.status(500).json({ error: 'Failed to create user' });
      }
      
      console.log('User created successfully');
      res.status(201).json({ 
        message: 'User created successfully',
        recoveryKey: recoveryKey // Show this only once to user
      });
      
      stmt.finalize();
    });`;

const fixedContent = content.replace(oldInsert, newInsert);

fs.writeFileSync('server.js', fixedContent);
console.log('Fixed server.js to use prepared statements');
