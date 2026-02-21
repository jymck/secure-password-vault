const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');

async function testWithHardcodedSQL() {
  const db = new sqlite3.Database('./vault.db');
  
  const username = 'testuser';
  const password = 'testpass123';
  const salt = 'test_salt_123';
  const email = 'test@example.com';
  const recoveryQuestion = 'What is your favorite color?';
  const recoveryAnswer = 'blue';
  
  try {
    // Hash password
    const passwordHash = await bcrypt.hash(password + salt, 12);
    
    // Hash recovery answer
    const recoveryAnswerHash = await bcrypt.hash(recoveryAnswer.toLowerCase() + salt, 12);
    
    console.log('Testing with hardcoded SQL...');
    
    // Try with the exact same SQL but hardcoded
    const sql = 'INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    console.log('SQL:', JSON.stringify(sql));
    console.log('Placeholders:', (sql.match(/\?/g) || []).length);
    
    db.run(sql, [username, email, passwordHash, salt, '{"encrypted":"test_encrypted","iv":"test_iv"}', recoveryQuestion, recoveryAnswerHash], function(err) {
      if (err) {
        console.error('Hardcoded SQL error:', err);
      } else {
        console.log('Hardcoded SQL successful');
      }
      db.close();
    });
  } catch (error) {
    console.error('Error:', error);
    db.close();
  }
}

testWithHardcodedSQL();
