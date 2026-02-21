# Secure Password Vault

A highly secure, local-first password vault with AES-256 encryption that runs entirely on your machine.

## 🔐 Security Features

- **AES-256-GCM Encryption**: Military-grade encryption for all stored passwords
- **Local-Only Storage**: Your data never leaves your machine
- **HTTPS/TLS**: Encrypted communication between browser and local server
- **Secure Authentication**: PBKDF2 key derivation with bcrypt
- **Password Recovery**: Secure recovery mechanism with recovery questions
- **Session Management**: Secure sessions with automatic timeout
- **Rate Limiting**: Protection against brute force attacks

## 🚀 Features

- **Web-Based Interface**: Access through your favorite browser
- **Password Generator**: Create strong, unique passwords
- **Password Strength Indicator**: Visual feedback on password security
- **Search & Filter**: Quickly find your passwords
- **Auto-Lock**: Automatic session timeout for security
- **Secure Recovery**: Real password recovery mechanism

## 📋 Requirements

- Node.js 14+ 
- OpenSSL (for HTTPS certificate generation)
- Modern web browser

## 🛠️ Installation

1. **Clone or download the project**
2. **Install dependencies**:
   ```bash
   npm run setup
   ```
3. **Start the application**:
   ```bash
   npm start
   ```

## 🔧 Setup Instructions

### First Time Setup

1. Navigate to the project directory:
   ```bash
   cd "secure password vault"
   ```

2. Install all dependencies:
   ```bash
   npm install
   npm run install:client
   ```

3. Start the server:
   ```bash
   npm start
   ```

4. Open your browser and go to `https://localhost:3000`
   - Note: You'll see a security warning for the self-signed certificate. This is normal and safe for local use.

### Creating Your Account

1. Click "Register" on the login page
2. Fill in your details:
   - Choose a strong username and password
   - Set up recovery questions
   - **IMPORTANT**: Save the recovery key displayed after registration

## 📁 Project Structure

```
secure password vault/
├── server.js              # Main server application
├── package.json           # Server dependencies
├── vault.db              # Encrypted SQLite database (created automatically)
├── cert.pem              # SSL certificate (generated automatically)
├── key.pem               # SSL private key (generated automatically)
└── client/               # React frontend
    ├── package.json      # Client dependencies
    ├── public/           # Static files
    └── src/              # React components
        ├── components/   # UI components
        ├── App.js        # Main application
        └── index.js      # Entry point
```

## 🔒 Security Details

### Encryption Implementation

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Salt**: Unique salt per user
- **IV**: Random initialization vector per encryption
- **Authentication Tag**: Ensures data integrity

### Data Storage

- All passwords are encrypted before database storage
- Database uses SQLite with file-level encryption
- Recovery keys are encrypted with user's master password
- No plaintext sensitive data is ever stored

### Network Security

- HTTPS with TLS 1.3 by default
- Self-signed certificates for local development
- All API endpoints require authentication
- CSRF protection with secure cookies
- Rate limiting on all endpoints

## 🚨 Important Security Notes

1. **Recovery Key**: Save your recovery key in a secure location. You cannot recover your account without it.
2. **Strong Password**: Use a strong master password. This protects all your stored passwords.
3. **Local Only**: This application is designed for local use only. Do not expose it to the internet.
4. **Backup**: Regularly backup your `vault.db` file to a secure location.
5. **Certificate**: The self-signed certificate is safe for local use only.

## 🔄 Password Recovery

If you forget your password:

1. Use the recovery link on the login page
2. Enter your username and recovery answer
3. Set a new password
4. Your encrypted passwords will be accessible with the new password

## 🛠️ Development

### Running in Development Mode

```bash
npm run dev
```

### Building for Production

```bash
npm run build
```

### Database Management

The SQLite database (`vault.db`) is created automatically. Tables include:
- `users`: User accounts and authentication data
- `passwords`: Encrypted password entries
- `session_tokens`: Active session management

## 🐛 Troubleshooting

### Common Issues

1. **Port 3000 already in use**:
   - Change the PORT environment variable: `set PORT=3001 && npm start`

2. **Certificate generation fails**:
   - Install OpenSSL or use the Node.js fallback (automatic)

3. **Database locked**:
   - Ensure only one instance of the server is running

4. **Browser security warnings**:
   - This is normal for self-signed certificates. Click "Advanced" → "Proceed to localhost"

## 📝 License

MIT License - feel free to use and modify for personal use.

## 🤝 Contributing

This is a personal security tool. For security reasons, please review the code thoroughly before making any modifications.

## ⚠️ Disclaimer

This software is provided as-is for educational and personal use. While security best practices have been implemented, users should:
- Review the code before use
- Keep backups of important data
- Use at their own risk
- Consider professional password managers for critical applications
