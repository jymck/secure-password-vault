const sql = 'INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
console.log('SQL length:', sql.length);
console.log('SQL characters:');
for (let i = 0; i < sql.length; i++) {
  const char = sql[i];
  const code = char.charCodeAt(0);
  console.log(`${i}: '${char}' (${code})`);
}
