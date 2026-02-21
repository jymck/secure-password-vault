const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('./vault.db');

console.log('=== USERS TABLE SCHEMA ===');
db.all('PRAGMA table_info(users)', (err, rows) => {
  if (err) {
    console.error('Error:', err);
  } else {
    rows.forEach((row, index) => {
      console.log(`${index + 1}. ${row.name} - ${row.type}`);
    });
  }
  
  console.log('\n=== PASSWORDS TABLE SCHEMA ===');
  db.all('PRAGMA table_info(passwords)', (err, rows) => {
    if (err) {
      console.error('Error:', err);
    } else {
      rows.forEach((row, index) => {
        console.log(`${index + 1}. ${row.name} - ${row.type}`);
      });
    }
    db.close();
  });
});
