const axios = require('axios');

async function testAddPasswordDirectly() {
  try {
    console.log('Testing add password functionality...');
    
    // First, let's try to register a user using the API directly
    console.log('1. Testing user registration...');
    const registerResponse = await axios.post('http://localhost:3000/api/auth/register', {
      username: 'testuser123',
      password: 'testpass123',
      email: 'test123@example.com',
      recoveryQuestion: 'What is your favorite color?',
      recoveryAnswer: 'blue'
    }, {
      withCredentials: true
    });
    
    console.log('Registration successful:', registerResponse.data.message);
    
    // Then login
    console.log('2. Testing login...');
    const loginResponse = await axios.post('http://localhost:3000/api/auth/login', {
      username: 'testuser123',
      password: 'testpass123'
    }, {
      withCredentials: true
    });
    
    console.log('Login successful:', loginResponse.data.message);
    
    // Then test adding a password
    console.log('3. Testing add password...');
    const addPasswordResponse = await axios.post('http://localhost:3000/api/passwords', {
      title: 'Test Password API',
      username: 'testuser',
      password: 'testpass123',
      url: 'https://example.com',
      notes: 'Test notes from API',
      category: 'Other'
    }, {
      withCredentials: true
    });
    
    console.log('Add password successful:', addPasswordResponse.data.message);
    console.log('✅ All tests passed!');
    
  } catch (error) {
    console.error('❌ Test failed:', error.response?.data || error.message);
  }
}

testAddPasswordDirectly();
