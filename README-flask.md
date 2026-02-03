# 🔐 Secure File Encryption REST API

A Flask-based REST API implementing AES-256 and RSA-2048 encryption for secure file operations.

## ✨ Features

- 🔒 **AES-256-GCM** symmetric encryption with authenticated encryption
- 🔑 **RSA-2048** asymmetric encryption with OAEP padding
- 🛡️ **PBKDF2-HMAC-SHA256** key derivation (480,000 iterations)
- 📁 **File upload/download** support
- 🌐 **RESTful API** design
- 📚 **Interactive documentation** UI

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements-flask.txt

# Run the server
python flask_crypto_api.py

# Open browser
http://localhost:5000
```

## 🔌 API Endpoints

### AES Encryption
```bash
# Encrypt file
curl -X POST -F "file=@document.pdf" -F "password=secret123" \
  http://localhost:5000/api/encrypt/aes

# Decrypt file
curl -X POST -F "encrypted_data=@encrypted.json" -F "password=secret123" \
  http://localhost:5000/api/decrypt/aes > decrypted.pdf
```

### RSA Encryption
```bash
# Generate key pair
curl -X POST http://localhost:5000/api/keygen/rsa

# Encrypt with public key
curl -X POST -F "file=@message.txt" -F "public_key=@public.pem" \
  http://localhost:5000/api/encrypt/rsa

# Decrypt with private key
curl -X POST -F "ciphertext=..." -F "private_key=@private.pem" \
  http://localhost:5000/api/decrypt/rsa
```

## 🛡️ Security Features

- ✅ AES-256-GCM with authenticated encryption
- ✅ Random salt and IV generation per encryption
- ✅ RSA-2048 with OAEP padding
- ✅ PBKDF2 key stretching (480,000 iterations)
- ✅ Secure key serialization (PEM format)

## 📖 Technologies

- **Flask** - Web framework
- **Python Cryptography** - Cryptographic operations
- **AES-256-GCM** - Symmetric encryption
- **RSA-2048** - Asymmetric encryption
- **PBKDF2** - Key derivation function

## ⚠️ Security Notes

This is an educational project. For production:
- Implement authentication (JWT, OAuth)
- Use HTTPS/TLS
- Add rate limiting
- Secure key management (HSM/KMS)
- Input validation and sanitization

## 👤 Author

Built with Python & Flask 🐍
