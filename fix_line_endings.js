// Fix for server.js - Remove all carriage return characters and normalize line endings
const fs = require('fs');
let content = fs.readFileSync('server.js', 'utf8');

// Remove all carriage return characters and normalize line endings
content = content.replace(/\r\n/g, '\n').replace(/\r/g, '');

fs.writeFileSync('server.js', content);
console.log('Normalized line endings in server.js');
