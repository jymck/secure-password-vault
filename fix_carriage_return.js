// Fix for server.js - Remove hidden carriage return characters
const fs = require('fs');
const content = fs.readFileSync('server.js', 'utf8');

// Remove all carriage return characters
const fixedContent = content.replace(/\r/g, '');

fs.writeFileSync('server.js', fixedContent);
console.log('Removed carriage return characters from server.js');
