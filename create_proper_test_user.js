const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./vault.db');

async function createTestUser() {
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
    
    // Insert user
    db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
      [username, email, passwordHash, salt, '{"encrypted":"test_encrypted","iv":"test_iv"}', recoveryQuestion, recoveryAnswerHash], 
      function(err) {
        if (err) {
          console.error('Create user error:', err);
        } else {
          console.log('Test user created successfully');
        }
        db.close();
      });
  } catch (error) {
    console.error('Error:', error);
    db.close();
  }
}

createTestUser();
