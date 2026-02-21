// Alternative: Use a simpler SQL approach with explicit column count
const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

// Replace with a simpler approach - count columns explicitly
const oldInsert = `        // Insert user
        // Use prepared statement for better reliability
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

const newInsert = `        // Insert user - using explicit column approach
        const columns = ['username', 'email', 'password_hash', 'salt', 'recovery_key_encrypted', 'recovery_question', 'recovery_answer_hash'];
        const values = [username, email, passwordHash, salt, recoveryKeyEncrypted.encrypted, recoveryQuestion, recoveryAnswerHash];
        const placeholders = columns.map(() => '?').join(', ');
        const columnNames = columns.join(', ');
        
        const sql = \`INSERT INTO users (\${columnNames}) VALUES (\${placeholders})\`;
        console.log('SQL:', sql);
        console.log('Values count:', values.length);
        
        db.run(sql, values, function(err) {
          if (err) {
            console.error('Database error during user insertion:', err);
            return res.status(500).json({ error: 'Failed to create user' });
          }
          
          console.log('User created successfully');
          res.status(201).json({ 
            message: 'User created successfully',
            recoveryKey: recoveryKey // Show this only once to user
          });
        });`;

const fixedContent = content.replace(oldInsert, newInsert);

fs.writeFileSync('server.js', fixedContent);
console.log('Fixed server.js with explicit column approach');
