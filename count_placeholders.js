const sql = 'INSERT INTO users (username, email, password_hash, salt, recovery_key_encrypted, recovery_question, recovery_answer_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
console.log('Placeholders:', (sql.match(/\?/g) || []).length);
console.log('SQL:', sql);
