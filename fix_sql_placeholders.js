// Simple fix for SQL placeholder issue
const fs = require('fs');

// Read the server file
const content = fs.readFileSync('server.js', 'utf8');

// Find and fix the SQL statement
const lines = content.split('\n');
const fixedLines = lines.map(line => {
  // Fix the specific INSERT statement that has 8 placeholders
  if (line.includes('INSERT INTO users') && line.includes('VALUES (?, ?, ?, ?, ?, ?, ?, ?)')) {
    return "        db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',";
  }
  return line;
});

// Write the fixed content
fs.writeFileSync('server.js', fixedLines.join('\n'));
console.log('✅ Fixed SQL placeholder count from 8 to 7');
