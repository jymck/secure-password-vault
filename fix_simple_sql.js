// Simple fix: Use a different SQL format to avoid the placeholder counting issue
const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

// Replace the problematic INSERT with a simpler format
const oldInsert = `        // Insert user - using explicit column approach
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

const newInsert = `        // Insert user - simple direct approach
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
          });`;

const fixedContent = content.replace(oldInsert, newInsert);

fs.writeFileSync('server.js', fixedContent);
console.log('Fixed server.js with simple SQL format');
