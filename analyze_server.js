const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

// Find the INSERT statement for users
const lines = content.split('\n');
const insertLine = lines.find(line => line.includes('INSERT INTO users'));

console.log('Found INSERT line:');
console.log('Raw:', JSON.stringify(insertLine));
console.log('Length:', insertLine.length);

// Count placeholders manually
let placeholderCount = 0;
for (let i = 0; i < insertLine.length; i++) {
  if (insertLine[i] === '?') {
    placeholderCount++;
  }
}

console.log('Manual placeholder count:', placeholderCount);

// Check for hidden characters
console.log('Character analysis:');
for (let i = 0; i < insertLine.length; i++) {
  const char = insertLine[i];
  const code = char.charCodeAt(0);
  if (code < 32 || code > 126) {
    console.log(`Hidden character at position ${i}: code ${code}`);
  }
}
