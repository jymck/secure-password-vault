const sqlite3 = require('sqlite3');

// Test with exact SQL debugging
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
  
  // Test with explicit column names and values
  const sql = 'INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
  const values = ['testuser3', 'test3@example.com', 'hash123', 'salt123', '{"encrypted":"test_encrypted","iv":"test_iv"}', 'What is your favorite color?', 'blue'];
  
  console.log('SQL statement:', sql);
  console.log('Number of placeholders:', (sql.match(/\?/g) || []).length);
  console.log('Number of values:', values.length);
  console.log('Values:', values);
  
  db.run(sql, values, function(err) {
    if (err) {
      console.error('Insert error:', err);
    } else {
      console.log('Insert successful');
    }
    db.close();
  });
});
