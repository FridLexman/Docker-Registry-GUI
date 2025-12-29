import os
import json
import secrets
import bcrypt
import pyotp
import qrcode
import jwt
from io import BytesIO
from base64 import b64encode
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify

# Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY_HOURS = int(os.environ.get('JWT_EXPIRY_HOURS', 24))
USERS_FILE = os.environ.get('USERS_FILE', 'users.json')
APP_NAME = 'Docker Registry GUI'

def load_users():
    """Load users from JSON file"""
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    """Save users to JSON file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_totp_secret():
    """Generate a new TOTP secret"""
    return pyotp.random_base32()

def get_totp_uri(username, secret):
    """Generate TOTP URI for QR code"""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=APP_NAME)

def generate_qr_code(uri):
    """Generate QR code as base64 image"""
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    return b64encode(buffer.getvalue()).decode('utf-8')

def verify_totp(secret, code):
    """Verify a TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def generate_backup_codes(count=10):
    """Generate backup codes for 2FA recovery"""
    return [secrets.token_hex(4).upper() for _ in range(count)]

def create_jwt_token(username, is_2fa_verified=False):
    """Create a JWT token"""
    payload = {
        'username': username,
        'is_2fa_verified': is_2fa_verified,
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS),
        'iat': datetime.now(timezone.utc)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def decode_jwt_token(token):
    """Decode and verify a JWT token"""
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def require_auth(f):
    """Decorator to require full authentication (password + 2FA)"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if not payload.get('is_2fa_verified'):
            return jsonify({'error': '2FA verification required'}), 403
        
        request.current_user = payload['username']
        return f(*args, **kwargs)
    return decorated

def create_user(username, password, is_admin=False):
    """Create a new user"""
    users = load_users()
    
    if username in users:
        return None, "User already exists"
    
    if len(username) < 3:
        return None, "Username must be at least 3 characters"
    
    if len(password) < 8:
        return None, "Password must be at least 8 characters"
    
    totp_secret = generate_totp_secret()
    backup_codes = generate_backup_codes()
    
    users[username] = {
        'password_hash': hash_password(password),
        'totp_secret': totp_secret,
        'backup_codes': [hash_password(code) for code in backup_codes],
        'is_2fa_enabled': False,
        'is_admin': is_admin,
        'created_at': datetime.now(timezone.utc).isoformat(),
        'last_login': None
    }
    
    save_users(users)
    
    return {
        'username': username,
        'totp_secret': totp_secret,
        'backup_codes': backup_codes,
        'is_admin': is_admin
    }, None

def setup_initial_admin():
    """Create initial admin user if no users exist"""
    users = load_users()
    if not users:
        admin_password = os.environ.get('ADMIN_PASSWORD', 'admin123')
        result, error = create_user('admin', admin_password, is_admin=True)
        if result:
            print(f"[AUTH] Created initial admin user")
            print(f"[AUTH] Username: admin")
            print(f"[AUTH] Password: {admin_password}")
            print(f"[AUTH] TOTP Secret: {result['totp_secret']}")
            print(f"[AUTH] Backup Codes: {', '.join(result['backup_codes'])}")
            return result
    return None

def change_password(username, old_password, new_password):
    """Change user password"""
    users = load_users()
    if username not in users:
        return False, "User not found"
    
    user = users[username]
    if not verify_password(old_password, user['password_hash']):
        return False, "Current password is incorrect"
    
    if len(new_password) < 8:
        return False, "New password must be at least 8 characters"
    
    users[username]['password_hash'] = hash_password(new_password)
    save_users(users)
    return True, "Password changed successfully"

def delete_user(username):
    """Delete a user (admin function)"""
    users = load_users()
    
    if username not in users:
        return False, "User not found"
    
    if username == 'admin':
        return False, "Cannot delete the admin account"
    
    del users[username]
    save_users(users)
    return True, "User deleted successfully"

def list_users():
    """List all users (admin function)"""
    users = load_users()
    user_list = []
    for username, data in users.items():
        user_list.append({
            'username': username,
            'is_admin': data.get('is_admin', username == 'admin'),
            'is_2fa_enabled': data.get('is_2fa_enabled', False),
            'created_at': data.get('created_at'),
            'last_login': data.get('last_login')
        })
    return user_list

def is_admin(username):
    """Check if user is admin"""
    users = load_users()
    if username not in users:
        return False
    return users[username].get('is_admin', username == 'admin')

def reset_user_2fa(username):
    """Reset 2FA for a user (admin function)"""
    users = load_users()
    
    if username not in users:
        return None, "User not found"
    
    # Generate new TOTP secret
    totp_secret = generate_totp_secret()
    
    # Generate new backup codes
    backup_codes = generate_backup_codes()
    
    users[username]['totp_secret'] = totp_secret
    users[username]['backup_codes'] = [hash_password(code) for code in backup_codes]
    users[username]['is_2fa_enabled'] = False
    
    save_users(users)
    
    return {
        'totp_secret': totp_secret,
        'backup_codes': backup_codes
    }, "2FA reset successfully"

def require_admin(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Authentication required'}), 401
        
        payload = decode_jwt_token(token)
        if not payload:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        if not payload.get('is_2fa_verified'):
            return jsonify({'error': '2FA verification required'}), 403
        
        username = payload['username']
        if not is_admin(username):
            return jsonify({'error': 'Admin privileges required'}), 403
        
        request.current_user = username
        return f(*args, **kwargs)
    return decorated
