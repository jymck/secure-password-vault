// Fix for server.js - Correct SQL INSERT statement
const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

// Fix the SQL INSERT statement for users
const fixedContent = content.replace(
  "INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
  "INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
);

fs.writeFileSync('server.js', fixedContent);
console.log('Fixed SQL INSERT statement for users');
