"""
Secure File Encryption API - Flask Application
Implements AES-256 (symmetric) and RSA-2048 (asymmetric) encryption
REST API endpoints for file encryption/decryption
"""

from flask import Flask, request, jsonify, send_file, render_template_string
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import io
import json

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# Store RSA keys in memory (in production, use secure key management)
RSA_KEYS = {}


def generate_aes_key(password: str, salt: bytes) -> bytes:
    """Generate AES key from password using PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file_aes(file_data: bytes, password: str) -> dict:
    """Encrypt file using AES-256-GCM"""
    # Generate salt and IV
    salt = os.urandom(16)
    iv = os.urandom(12)  # GCM mode uses 12-byte IV
    
    # Derive key
    key = generate_aes_key(password, salt)
    
    # Encrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    
    # Return encrypted data with metadata
    return {
        'salt': base64.b64encode(salt).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(encryptor.tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }


def decrypt_file_aes(encrypted_data: dict, password: str) -> bytes:
    """Decrypt file using AES-256-GCM"""
    # Decode components
    salt = base64.b64decode(encrypted_data['salt'])
    iv = base64.b64decode(encrypted_data['iv'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    # Derive key
    key = generate_aes_key(password, salt)
    
    # Decrypt
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext


def generate_rsa_keypair() -> tuple:
    """Generate RSA-2048 key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize keys to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_pem.decode(), public_pem.decode()


def encrypt_file_rsa(file_data: bytes, public_key_pem: str) -> str:
    """Encrypt small file using RSA (max 190 bytes for RSA-2048)"""
    if len(file_data) > 190:
        raise ValueError("File too large for RSA encryption. Use hybrid encryption for larger files.")
    
    # Load public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode(),
        backend=default_backend()
    )
    
    # Encrypt
    ciphertext = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(ciphertext).decode()


def decrypt_file_rsa(ciphertext_b64: str, private_key_pem: str) -> bytes:
    """Decrypt file using RSA"""
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    
    # Decrypt
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return plaintext


# HTML Template for Web UI
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Secure File Encryption API</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
        }
        h1 {
            color: #667eea;
            text-align: center;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        .subtitle {
            text-align: center;
            color: #666;
            margin-bottom: 30px;
        }
        .section {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 20px;
        }
        h2 {
            color: #764ba2;
            margin-bottom: 15px;
            font-size: 1.5em;
        }
        .endpoint {
            background: white;
            padding: 15px;
            border-left: 4px solid #667eea;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .method {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 5px;
            font-weight: bold;
            margin-right: 10px;
        }
        .post { background: #28a745; color: white; }
        .get { background: #007bff; color: white; }
        code {
            background: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        pre {
            background: #2d2d2d;
            color: #f8f8f2;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            margin-top: 10px;
        }
        .feature {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .feature::before {
            content: "✓";
            background: #28a745;
            color: white;
            width: 25px;
            height: 25px;
            border-radius: 50%;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-right: 10px;
            font-weight: bold;
        }
        .warning {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Secure File Encryption API</h1>
        <p class="subtitle">REST API for AES-256 and RSA-2048 Encryption</p>
        
        <div class="section">
            <h2>✨ Features</h2>
            <div class="feature">AES-256-GCM symmetric encryption</div>
            <div class="feature">RSA-2048 asymmetric encryption</div>
            <div class="feature">PBKDF2 key derivation (480,000 iterations)</div>
            <div class="feature">File upload/download support</div>
            <div class="feature">RESTful API design</div>
        </div>
        
        <div class="section">
            <h2>🔌 API Endpoints</h2>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/encrypt/aes</code>
                <p style="margin-top: 10px;">Encrypt file using AES-256</p>
                <pre>curl -X POST -F "file=@document.pdf" -F "password=secret123" http://localhost:5000/api/encrypt/aes</pre>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/decrypt/aes</code>
                <p style="margin-top: 10px;">Decrypt AES-encrypted file</p>
                <pre>curl -X POST -F "encrypted_data=@encrypted.json" -F "password=secret123" http://localhost:5000/api/decrypt/aes</pre>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/keygen/rsa</code>
                <p style="margin-top: 10px;">Generate RSA-2048 key pair</p>
                <pre>curl -X POST http://localhost:5000/api/keygen/rsa</pre>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/encrypt/rsa</code>
                <p style="margin-top: 10px;">Encrypt with RSA public key</p>
                <pre>curl -X POST -F "file=@small.txt" -F "public_key=@public.pem" http://localhost:5000/api/encrypt/rsa</pre>
            </div>
            
            <div class="endpoint">
                <span class="method post">POST</span>
                <code>/api/decrypt/rsa</code>
                <p style="margin-top: 10px;">Decrypt with RSA private key</p>
                <pre>curl -X POST -F "ciphertext=..." -F "private_key=@private.pem" http://localhost:5000/api/decrypt/rsa</pre>
            </div>
            
            <div class="endpoint">
                <span class="method get">GET</span>
                <code>/api/status</code>
                <p style="margin-top: 10px;">Check API status</p>
                <pre>curl http://localhost:5000/api/status</pre>
            </div>
        </div>
        
        <div class="section">
            <h2>🛡️ Security Features</h2>
            <ul style="list-style: none; padding-left: 0;">
                <li style="padding: 8px 0;">🔒 AES-256-GCM with authenticated encryption</li>
                <li style="padding: 8px 0;">🔑 PBKDF2-HMAC-SHA256 key derivation</li>
                <li style="padding: 8px 0;">🎲 Random salt and IV generation</li>
                <li style="padding: 8px 0;">🔐 RSA-2048 OAEP padding</li>
                <li style="padding: 8px 0;">📝 Secure key serialization (PEM format)</li>
            </ul>
        </div>
        
        <div class="warning">
            <strong>⚠️ Educational Purpose:</strong> This is a demonstration API. For production use:
            <ul style="margin-left: 20px; margin-top: 10px;">
                <li>Implement proper authentication (JWT, OAuth)</li>
                <li>Use HTTPS/TLS for all communications</li>
                <li>Store keys in secure key management systems (HSM, KMS)</li>
                <li>Add rate limiting and input validation</li>
                <li>Follow OWASP security guidelines</li>
            </ul>
        </div>
        
        <div style="text-align: center; margin-top: 30px; color: #666;">
            <p>Built with Flask, Python Cryptography Library</p>
            <p style="margin-top: 10px;">🔐 Stay Secure! 🔐</p>
        </div>
    </div>
</body>
</html>
"""


# API Routes

@app.route('/')
def home():
    """Render API documentation"""
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/status', methods=['GET'])
def status():
    """Check API status"""
    return jsonify({
        'status': 'online',
        'version': '1.0.0',
        'endpoints': [
            '/api/encrypt/aes',
            '/api/decrypt/aes',
            '/api/keygen/rsa',
            '/api/encrypt/rsa',
            '/api/decrypt/rsa'
        ]
    })


@app.route('/api/encrypt/aes', methods=['POST'])
def encrypt_aes():
    """Encrypt file using AES-256"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        if 'password' not in request.form:
            return jsonify({'error': 'No password provided'}), 400
        
        file = request.files['file']
        password = request.form['password']
        
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # Read file data
        file_data = file.read()
        
        # Encrypt
        encrypted = encrypt_file_aes(file_data, password)
        encrypted['original_filename'] = file.filename
        
        return jsonify({
            'success': True,
            'encrypted_data': encrypted,
            'message': 'File encrypted successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decrypt/aes', methods=['POST'])
def decrypt_aes():
    """Decrypt AES-encrypted file"""
    try:
        if 'password' not in request.form:
            return jsonify({'error': 'No password provided'}), 400
        
        password = request.form['password']
        
        # Get encrypted data (can be JSON string or file)
        if 'encrypted_data' in request.files:
            encrypted_json = request.files['encrypted_data'].read().decode()
            encrypted_data = json.loads(encrypted_json)
        elif 'encrypted_data' in request.form:
            encrypted_data = json.loads(request.form['encrypted_data'])
        else:
            return jsonify({'error': 'No encrypted data provided'}), 400
        
        # Decrypt
        #decrypted = decrypt_file_aes(encrypted_data, password)
        # Handle wrapped encrypted data
        if 'encrypted_data' in encrypted_data:
            encrypted_data = encrypted_data['encrypted_data']

        decrypted = decrypt_file_aes(encrypted_data, password)

        # Return as downloadable file
        return send_file(
            io.BytesIO(decrypted),
            download_name=encrypted_data.get('original_filename', 'decrypted_file'),
            as_attachment=True
        )
    
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400


@app.route('/api/keygen/rsa', methods=['POST'])
def keygen_rsa():
    """Generate RSA key pair"""
    try:
        private_key, public_key = generate_rsa_keypair()
        
        # Generate key ID
        key_id = base64.b64encode(os.urandom(8)).decode()
        RSA_KEYS[key_id] = {'private': private_key, 'public': public_key}
        
        return jsonify({
            'success': True,
            'key_id': key_id,
            'public_key': public_key,
            'private_key': private_key,
            'message': 'RSA key pair generated successfully'
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/encrypt/rsa', methods=['POST'])
def encrypt_rsa():
    """Encrypt file using RSA"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        if 'public_key' not in request.files and 'public_key' not in request.form:
            return jsonify({'error': 'No public key provided'}), 400
        
        file = request.files['file']
        file_data = file.read()
        
        # Get public key
        if 'public_key' in request.files:
            public_key = request.files['public_key'].read().decode()
        else:
            public_key = request.form['public_key']
        
        # Encrypt
        ciphertext = encrypt_file_rsa(file_data, public_key)
        
        return jsonify({
            'success': True,
            'ciphertext': ciphertext,
            'original_filename': file.filename,
            'message': 'File encrypted successfully with RSA'
        })
    
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decrypt/rsa', methods=['POST'])
def decrypt_rsa():
    """Decrypt file using RSA"""
    try:
        if 'ciphertext' not in request.form:
            return jsonify({'error': 'No ciphertext provided'}), 400
        
        if 'private_key' not in request.files and 'private_key' not in request.form:
            return jsonify({'error': 'No private key provided'}), 400
        
        ciphertext = request.form['ciphertext']
        
        # Get private key
        if 'private_key' in request.files:
            private_key = request.files['private_key'].read().decode()
        else:
            private_key = request.form['private_key']
        
        # Decrypt
        plaintext = decrypt_file_rsa(ciphertext, private_key)
        
        # Return as downloadable file
        return send_file(
            io.BytesIO(plaintext),
            download_name='decrypted_file',
            as_attachment=True
        )
    
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 400


if __name__ == '__main__':
    print("🔐 Secure File Encryption API")
    print("=" * 50)
    print("Server starting at http://localhost:5000")
    print("API Documentation: http://localhost:5000")
    print("=" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
