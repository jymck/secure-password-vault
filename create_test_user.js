const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./vault.db');

console.log('Creating test user...');
db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
  ['testuser', 'test@example.com', 'hash123', 'salt123', 'encrypted123', 'What is your favorite color?', 'blue'], 
  function(err) {
    if (err) {
      console.error('Create user error:', err);
    } else {
      console.log('Test user created successfully');
    }
    db.close();
  });
