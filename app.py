from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
import requests
import os
from datetime import datetime, timezone

from auth import (
    load_users, save_users, verify_password, verify_totp,
    create_jwt_token, decode_jwt_token, require_auth, require_admin,
    create_user, get_totp_uri, generate_qr_code,
    hash_password, setup_initial_admin, change_password,
    delete_user, list_users, is_admin, reset_user_2fa
)

app = Flask(__name__, static_folder='static')
CORS(app, supports_credentials=True)

REGISTRY_URL = os.environ.get('REGISTRY_URL', 'http://localhost:5000')

def get_registry_url():
    return request.args.get('registry_url', REGISTRY_URL).rstrip('/')

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/login')
def login_page():
    return send_from_directory('static', 'login.html')

@app.route('/settings')
def settings_page():
    return send_from_directory('static', 'settings.html')

# ============== Authentication Routes ==============

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Step 1: Verify username and password"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    users = load_users()
    user = users.get(username)
    
    if not user or not verify_password(password, user['password_hash']):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Check if 2FA is enabled
    if user.get('is_2fa_enabled'):
        # Return partial token that requires 2FA
        token = create_jwt_token(username, is_2fa_verified=False)
        return jsonify({
            'requires_2fa': True,
            'token': token,
            'message': 'Please enter your 2FA code'
        })
    else:
        # 2FA not yet set up - require setup
        token = create_jwt_token(username, is_2fa_verified=False)
        totp_uri = get_totp_uri(username, user['totp_secret'])
        qr_code = generate_qr_code(totp_uri)
        return jsonify({
            'requires_2fa_setup': True,
            'token': token,
            'qr_code': qr_code,
            'totp_secret': user['totp_secret'],
            'message': 'Please set up 2FA by scanning the QR code'
        })

@app.route('/api/auth/verify-2fa', methods=['POST'])
def verify_2fa():
    """Step 2: Verify 2FA code"""
    data = request.get_json()
    code = data.get('code', '').strip()
    token = data.get('token', '')
    
    if not code or not token:
        return jsonify({'error': 'Code and token required'}), 400
    
    payload = decode_jwt_token(token)
    if not payload:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    username = payload['username']
    users = load_users()
    user = users.get(username)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    # Try TOTP code first
    if verify_totp(user['totp_secret'], code):
        # Update last login
        user['last_login'] = datetime.now(timezone.utc).isoformat()
        save_users(users)
        
        # Return fully authenticated token
        new_token = create_jwt_token(username, is_2fa_verified=True)
        return jsonify({
            'success': True,
            'token': new_token,
            'username': username
        })
    
    # Try backup codes
    for i, hashed_code in enumerate(user.get('backup_codes', [])):
        if verify_password(code.upper(), hashed_code):
            # Remove used backup code
            user['backup_codes'].pop(i)
            user['last_login'] = datetime.now(timezone.utc).isoformat()
            save_users(users)
            
            new_token = create_jwt_token(username, is_2fa_verified=True)
            return jsonify({
                'success': True,
                'token': new_token,
                'username': username,
                'warning': f'Backup code used. {len(user["backup_codes"])} remaining.'
            })
    
    return jsonify({'error': 'Invalid 2FA code'}), 401

@app.route('/api/auth/setup-2fa', methods=['POST'])
def setup_2fa():
    """Complete 2FA setup by verifying first code"""
    data = request.get_json()
    code = data.get('code', '').strip()
    token = data.get('token', '')
    
    if not code or not token:
        return jsonify({'error': 'Code and token required'}), 400
    
    payload = decode_jwt_token(token)
    if not payload:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    username = payload['username']
    users = load_users()
    user = users.get(username)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    if verify_totp(user['totp_secret'], code):
        # Enable 2FA
        user['is_2fa_enabled'] = True
        user['last_login'] = datetime.now(timezone.utc).isoformat()
        save_users(users)
        
        # Return fully authenticated token
        new_token = create_jwt_token(username, is_2fa_verified=True)
        return jsonify({
            'success': True,
            'token': new_token,
            'username': username,
            'message': '2FA has been enabled successfully'
        })
    
    return jsonify({'error': 'Invalid 2FA code. Please try again.'}), 401

@app.route('/api/auth/verify-token', methods=['GET'])
def verify_token():
    """Verify if current token is valid and fully authenticated"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'valid': False}), 401
    
    token = auth_header.split(' ')[1]
    payload = decode_jwt_token(token)
    
    if not payload:
        return jsonify({'valid': False}), 401
    
    return jsonify({
        'valid': True,
        'username': payload['username'],
        'is_2fa_verified': payload.get('is_2fa_verified', False)
    })

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Logout (client should discard token)"""
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/api/auth/change-password', methods=['POST'])
@require_auth
def change_password():
    """Change user password"""
    data = request.get_json()
    current_password = data.get('current_password', '')
    new_password = data.get('new_password', '')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password required'}), 400
    
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    users = load_users()
    user = users.get(request.current_user)
    
    if not verify_password(current_password, user['password_hash']):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    user['password_hash'] = hash_password(new_password)
    save_users(users)
    
    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/api/auth/regenerate-backup-codes', methods=['POST'])
@require_auth
def regenerate_backup_codes():
    """Generate new backup codes"""
    from auth import generate_backup_codes
    
    users = load_users()
    user = users.get(request.current_user)
    
    new_codes = generate_backup_codes()
    user['backup_codes'] = [hash_password(code) for code in new_codes]
    save_users(users)
    
    return jsonify({
        'success': True,
        'backup_codes': new_codes,
        'message': 'New backup codes generated. Save them securely!'
    })

@app.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user info"""
    users = load_users()
    user = users.get(request.current_user)
    
    return jsonify({
        'username': request.current_user,
        'is_admin': user.get('is_admin', request.current_user == 'admin'),
        'is_2fa_enabled': user.get('is_2fa_enabled', False),
        'created_at': user.get('created_at'),
        'last_login': user.get('last_login')
    })

# ============== Admin User Management Routes ==============

@app.route('/api/admin/users', methods=['GET'])
@require_admin
def admin_list_users():
    """List all users (admin only)"""
    return jsonify({'users': list_users()})

@app.route('/api/admin/users', methods=['POST'])
@require_admin
def admin_create_user():
    """Create a new user (admin only)"""
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    make_admin = data.get('is_admin', False)
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    result, error = create_user(username, password, is_admin=make_admin)
    
    if error:
        return jsonify({'error': error}), 400
    
    return jsonify({
        'success': True,
        'message': f'User {username} created successfully',
        'user': {
            'username': result['username'],
            'totp_secret': result['totp_secret'],
            'backup_codes': result['backup_codes'],
            'is_admin': result['is_admin']
        }
    })

@app.route('/api/admin/users/<username>', methods=['DELETE'])
@require_admin
def admin_delete_user(username):
    """Delete a user (admin only)"""
    success, message = delete_user(username)
    
    if not success:
        return jsonify({'error': message}), 400
    
    return jsonify({'success': True, 'message': message})

@app.route('/api/admin/users/<username>/reset-2fa', methods=['POST'])
@require_admin
def admin_reset_user_2fa(username):
    """Reset 2FA for a user (admin only)"""
    result, message = reset_user_2fa(username)
    
    if not result:
        return jsonify({'error': message}), 400
    
    return jsonify({
        'success': True,
        'message': message,
        'totp_secret': result['totp_secret'],
        'backup_codes': result['backup_codes']
    })

# ============== Protected Registry Routes ==============

@app.route('/api/catalog')
@require_auth
def get_catalog():
    """Get list of all repositories in the registry"""
    registry_url = get_registry_url()
    try:
        response = requests.get(
            f'{registry_url}/v2/_catalog',
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            return jsonify(response.json())
        return jsonify({'error': f'Registry returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repositories/<path:repo>/tags')
@require_auth
def get_tags(repo):
    """Get all tags for a repository"""
    registry_url = get_registry_url()
    try:
        response = requests.get(
            f'{registry_url}/v2/{repo}/tags/list',
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            return jsonify(response.json())
        return jsonify({'error': f'Registry returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repositories/<path:repo>/manifests/<tag>')
@require_auth
def get_manifest(repo, tag):
    """Get manifest for a specific image tag"""
    registry_url = get_registry_url()
    try:
        headers = {
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
        }
        response = requests.get(
            f'{registry_url}/v2/{repo}/manifests/{tag}',
            headers=headers,
            timeout=10,
            verify=False
        )
        if response.status_code == 200:
            digest = response.headers.get('Docker-Content-Digest', '')
            data = response.json()
            data['digest'] = digest
            return jsonify(data)
        return jsonify({'error': f'Registry returned status {response.status_code}'}), response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/repositories/<path:repo>/manifests/<tag>', methods=['DELETE'])
@require_auth
def delete_manifest(repo, tag):
    """Delete an image by tag (requires registry to have delete enabled)"""
    registry_url = get_registry_url()
    try:
        # First get the digest
        headers = {
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json'
        }
        response = requests.get(
            f'{registry_url}/v2/{repo}/manifests/{tag}',
            headers=headers,
            timeout=10,
            verify=False
        )
        if response.status_code != 200:
            return jsonify({'error': 'Could not get manifest digest'}), 400
        
        digest = response.headers.get('Docker-Content-Digest')
        if not digest:
            return jsonify({'error': 'No digest found in response'}), 400
        
        # Delete by digest
        delete_response = requests.delete(
            f'{registry_url}/v2/{repo}/manifests/{digest}',
            timeout=10,
            verify=False
        )
        if delete_response.status_code in [200, 202]:
            return jsonify({'success': True, 'message': f'Deleted {repo}:{tag}'})
        return jsonify({'error': f'Delete failed with status {delete_response.status_code}'}), delete_response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health')
@require_auth
def health():
    """Check if registry is accessible"""
    registry_url = get_registry_url()
    try:
        response = requests.get(
            f'{registry_url}/v2/',
            timeout=5,
            verify=False
        )
        return jsonify({
            'status': 'ok' if response.status_code == 200 else 'error',
            'registry_url': registry_url,
            'registry_status': response.status_code
        })
    except requests.exceptions.RequestException as e:
        return jsonify({
            'status': 'error',
            'registry_url': registry_url,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    import warnings
    warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    # Setup initial admin user if none exists
    admin_info = setup_initial_admin()
    if admin_info:
        print("=" * 60)
        print("IMPORTANT: Save these credentials!")
        print(f"Username: admin")
        print(f"Password: {os.environ.get('ADMIN_PASSWORD', 'admin123')}")
        print(f"TOTP Secret: {admin_info['totp_secret']}")
        print(f"Backup Codes: {', '.join(admin_info['backup_codes'])}")
        print("=" * 60)
    
    app.run(host='0.0.0.0', port=12000, debug=False, threaded=True)
