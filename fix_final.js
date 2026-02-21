// Working server with minimal fixes
const fs = require('fs');

// Read current server.js
let content = fs.readFileSync('server.js', 'utf8');

// Fix the SQL placeholder issue by replacing the problematic line
const problematicLine = "db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'";
const fixedLine = "db.run('INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'";

// Replace all instances of the problematic line
content = content.replace(new RegExp(problematicLine.replace(/[.*?]/g, '\\$&'), 'g'), fixedLine);

// Write back the fixed content
fs.writeFileSync('server.js', content);
console.log('✅ Fixed SQL placeholder issue in server.js');
console.log('📝 The server should now work correctly for user registration and password addition');
