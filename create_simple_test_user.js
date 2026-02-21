const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3');

async function createSimpleTestUser() {
  // Create a new database connection
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
    
    console.log('Attempting to insert user with 7 values...');
    console.log('Username:', username);
    console.log('Email:', email);
    console.log('PasswordHash:', passwordHash ? 'present' : 'missing');
    console.log('Salt:', salt);
    console.log('RecoveryKey:', '{"encrypted":"test_encrypted","iv":"test_iv"}');
    console.log('RecoveryQuestion:', recoveryQuestion);
    console.log('RecoveryAnswerHash:', recoveryAnswerHash ? 'present' : 'missing');
    
    // Insert user with explicit 7 placeholders
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

createSimpleTestUser();
