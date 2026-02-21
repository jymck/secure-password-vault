const axios = require('axios');

async function testPasswordAPI() {
  try {
    // Login with existing test user
    const loginResponse = await axios.post('http://localhost:3000/api/auth/login', {
      username: 'testuser',
      password: 'testpass123'
    }, {
      withCredentials: true
    });
    
    console.log('Login successful:', loginResponse.data.message);
    
    // Test adding a password
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
    
    // Get password list
    const listResponse = await axios.get('http://localhost:3000/api/passwords', {
      withCredentials: true
    });
    
    console.log('Password list:', listResponse.data);
    
    if (listResponse.data.length > 0) {
      const passwordId = listResponse.data[0].id;
      
      // Get specific password
      const passwordResponse = await axios.get(`http://localhost:3000/api/passwords/${passwordId}`, {
        withCredentials: true
      });
      
      console.log('Specific password:', passwordResponse.data);
      console.log('Password value:', passwordResponse.data.password_encrypted);
    }
    
  } catch (error) {
    console.error('API test failed:', error.response?.data || error.message);
  }
}

testPasswordAPI();
