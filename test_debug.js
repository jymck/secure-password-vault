const sqlite3 = require('sqlite3');

// Test with a completely new database
const db = new sqlite3.Database('./test_vault.db');

console.log('Creating test table...');
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
)`, function(err) {
  if (err) {
    console.error('Create table error:', err);
    return;
  }
  
  console.log('Table created successfully');
  
  console.log('Testing simple insert...');
  // Try the simplest possible insert first
  db.run('INSERT INTO users (username) VALUES (?)', 
    ['testuser'], 
    function(err) {
      if (err) {
        console.error('Simple insert error:', err);
      } else {
        console.log('Simple insert successful');
      }
      
      console.log('Testing 2-column insert...');
      db.run('INSERT INTO users (username, email) VALUES (?, ?)', 
        ['testuser2', 'test2@example.com'], 
        function(err) {
          if (err) {
            console.error('2-column insert error:', err);
          } else {
            console.log('2-column insert successful');
          }
          
          console.log('Testing 7-column insert...');
          db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
            ['testuser3', 'test3@example.com', 'hash123', 'salt123', '{"encrypted":"test_encrypted","iv":"test_iv"}', 'What is your favorite color?', 'blue'], 
            function(err) {
              if (err) {
                console.error('7-column insert error:', err);
              } else {
                console.log('7-column insert successful');
              }
              db.close();
            });
        });
    });
});
