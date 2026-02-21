const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

// Test decryption with the stored data
const encryptedData = JSON.parse('{"encrypted":"a712546a97f5d9bcdadc8fedaf85765d","iv":"5110c0ac3e1b7270ae0422a83206ddd3"}');
console.log('Encrypted data:', encryptedData);

// Get the actual user salt from database
const db = new sqlite3.Database('./vault.db');
db.get('SELECT salt FROM users WHERE id = 1', (err, user) => {
  if (err) {
    console.error('Error getting user:', err);
    return;
  }
  
  console.log('User salt:', user.salt);
  
  // Try with a common password
  const testPasswords = ['password', '123456', 'test123', 'admin', 'qwerty'];
  
  testPasswords.forEach(testPassword => {
    console.log(`\nTrying password: ${testPassword}`);
    try {
      const key = crypto.pbkdf2Sync(testPassword, user.salt, 100000, 32, 'sha256');
      console.log('Generated key length:', key.length);
      
      const iv = Buffer.from(encryptedData.iv, 'hex');
      const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
      let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      console.log('Decrypted successfully:', decrypted);
    } catch (error) {
      console.error('Decryption failed:', error.message);
    }
  });
  
  db.close();
});
