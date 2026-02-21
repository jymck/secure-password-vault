// Final working test - demonstrate add password functionality
const axios = require('axios');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');

// Create cookie jar and wrapped axios instance
const jar = new CookieJar();
const client = wrapper(axios.create({
  jar,
  withCredentials: true,
  baseURL: 'http://localhost:3000'
}));

async function finalTest() {
  try {
    console.log('🚀 Starting final test of add password functionality...');
    
    // Test 1: Register a user
    console.log('📝 Step 1: Registering user...');
    const registerResponse = await client.post('/api/auth/register', {
      username: 'testuser5',
      password: 'testpass123',
      email: 'test5@example.com',
      recoveryQuestion: 'What is your favorite color?',
      recoveryAnswer: 'blue'
    }, {
      withCredentials: true,
      timeout: 5000
    }).catch(err => {
      console.log('❌ Registration failed:', err.response?.data || err.message);
      return null;
    });
    
    if (!registerResponse || registerResponse.status !== 201) {
      console.log('❌ Registration step failed');
      return;
    }
    
    console.log('✅ Registration successful:', registerResponse.data.message);
    
    // Test 2: Login
    console.log('🔑 Step 2: Logging in...');
    const loginResponse = await client.post('/api/auth/login', {
      username: 'testuser5',
      password: 'testpass123'
    }).catch(err => {
      console.log('❌ Login failed:', err.response?.data || err.message);
      return null;
    });
    
    if (!loginResponse || loginResponse.status !== 200) {
      console.log('❌ Login step failed');
      return;
    }
    
    console.log('✅ Login successful:', loginResponse.data.message);
    
    // Test 3: Add Password (the main functionality we're testing)
    console.log('🔐 Step 3: Adding password...');
    const addPasswordResponse = await client.post('/api/passwords', {
      title: 'Test Password Entry',
      username: 'testuser_account',
      password: 'superSecret123!',
      url: 'https://example.com',
      notes: 'This is a test password entry',
      category: 'Social Media'
    }).catch(err => {
      console.log('❌ Add password failed:', err.response?.data || err.message);
      return null;
    });
    
    if (!addPasswordResponse || addPasswordResponse.status !== 201) {
      console.log('❌ Add password step failed');
      return;
    }
    
    console.log('✅ Add password successful:', addPasswordResponse.data.message);
    
    // Test 4: Verify password was saved
    console.log('📋 Step 4: Verifying password was saved...');
    const getPasswordsResponse = await client.get('/api/passwords').catch(err => {
      console.log('❌ Get passwords failed:', err.response?.data || err.message);
      return null;
    });
    
    if (!getPasswordsResponse || getPasswordsResponse.status !== 200) {
      console.log('❌ Get passwords step failed');
      return;
    }
    
    const passwords = getPasswordsResponse.data;
    const savedPassword = passwords.find(p => p.title === 'Test Password Entry');
    
    if (savedPassword) {
      console.log('✅ Password verification successful!');
      console.log('🎉 ALL TESTS PASSED! Add password functionality is working correctly.');
    } else {
      console.log('❌ Password verification failed - password not found in list');
    }
    
  } catch (error) {
    console.error('❌ Unexpected error:', error.message);
  }
}

console.log('🧪 Final test ready. Make sure the server is running on localhost:3000');
console.log('📋 This test will:');
console.log('   1. Register a new user');
console.log('   2. Login with that user');
console.log('   3. Add a password entry');
console.log('   4. Verify the password was saved');
console.log('');
console.log('Run: node final_test.js');

finalTest();
