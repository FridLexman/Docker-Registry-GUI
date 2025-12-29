# Docker Registry GUI

A modern, secure web-based GUI for managing Docker registries with built-in two-factor authentication (2FA).

![Docker Registry GUI](https://img.shields.io/badge/Docker-Registry%20GUI-blue?logo=docker)
![Python](https://img.shields.io/badge/Python-3.8+-green?logo=python)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

### 🔐 Security
- **Two-Factor Authentication (2FA)** - TOTP-based authentication using apps like Google Authenticator, Authy, or 1Password
- **Secure Password Hashing** - bcrypt-based password storage
- **JWT Session Management** - Secure token-based sessions with configurable expiry
- **Backup Codes** - 10 one-time recovery codes for account access

### 👥 User Management (Admin Only)
- Create and delete users
- Grant/revoke admin privileges
- Reset user 2FA credentials
- View user activity and status

### 🐳 Registry Features
- Browse repositories and tags
- View image details (size, layers, digest)
- Copy Docker pull commands
- Delete tags (with confirmation)
- Support for multiple registries

### ⚙️ Settings
- Profile information
- Change password
- Configure default registry URL
- Regenerate backup codes

## Quick Start

### Prerequisites
- Python 3.8+
- Docker (for running a local registry)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd docker-registry-gui
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the application**
   ```bash
   python app.py
   ```

4. **Access the GUI**
   Open your browser and navigate to `http://localhost:12000`

### Default Credentials
On first run, an admin account is automatically created:
- **Username:** `admin`
- **Password:** `admin123`

⚠️ **Important:** Change the default password immediately after first login!

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REGISTRY_URL` | Default Docker registry URL | `http://localhost:5000` |
| `JWT_SECRET` | Secret key for JWT tokens | Auto-generated |
| `JWT_EXPIRY_HOURS` | Token expiration time | `24` |
| `ADMIN_PASSWORD` | Initial admin password | `admin123` |
| `USERS_FILE` | Path to users database | `users.json` |

### Setting Up a Local Docker Registry

```bash
# Start Docker daemon (if not running)
sudo dockerd &

# Run a local registry
docker run -d -p 5000:5000 --name registry registry:2

# Push a test image
docker pull alpine
docker tag alpine localhost:5000/alpine
docker push localhost:5000/alpine
```

## Usage

### First Login
1. Navigate to the login page
2. Enter username and password
3. Scan the QR code with your authenticator app (first time only)
4. Enter the 6-digit TOTP code
5. Save your backup codes securely

### Managing Users (Admin)
1. Go to **Settings** → **User Management**
2. Click **Add User** to create new accounts
3. Share the generated credentials securely with the user
4. Users will set up their own 2FA on first login

### Changing Registry
1. Go to **Settings** → **Registry**
2. Enter the new registry URL
3. Click **Save Registry URL**
4. Return to the main page and click **Refresh**

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login with username/password |
| POST | `/api/auth/verify-2fa` | Verify TOTP code |
| POST | `/api/auth/logout` | Logout |
| GET | `/api/auth/verify-token` | Verify JWT token |
| POST | `/api/auth/change-password` | Change password |
| POST | `/api/auth/regenerate-backup-codes` | Generate new backup codes |
| GET | `/api/auth/me` | Get current user info |

### Admin (Requires Admin Role)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/users` | List all users |
| POST | `/api/admin/users` | Create new user |
| DELETE | `/api/admin/users/<username>` | Delete user |
| POST | `/api/admin/users/<username>/reset-2fa` | Reset user's 2FA |

### Registry (Requires Authentication)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Check registry connection |
| GET | `/api/catalog` | List repositories |
| GET | `/api/repositories/<repo>/tags` | List tags for repository |
| GET | `/api/repositories/<repo>/manifests/<tag>` | Get manifest details |
| DELETE | `/api/repositories/<repo>/manifests/<tag>` | Delete a tag |

## File Structure

```
docker-registry-gui/
├── app.py              # Flask application
├── auth.py             # Authentication module
├── requirements.txt    # Python dependencies
├── users.json          # User database (auto-created)
├── static/
│   ├── index.html      # Main registry browser
│   ├── login.html      # Login page with 2FA
│   └── settings.html   # Settings page
└── README.md           # This file
```

## Security Considerations

1. **Change default credentials** - Always change the default admin password
2. **Use HTTPS in production** - Deploy behind a reverse proxy with SSL
3. **Secure the users.json file** - Contains hashed passwords and TOTP secrets
4. **Regular backups** - Backup the users.json file regularly
5. **JWT Secret** - Set a strong `JWT_SECRET` environment variable in production

## Troubleshooting

### "Registry connection failed"
- Ensure the Docker registry is running
- Check the registry URL in Settings
- Verify network connectivity

### "Invalid 2FA code"
- Ensure your device time is synchronized
- Try the next code (codes change every 30 seconds)
- Use a backup code if needed

### "Authentication required"
- Your session may have expired
- Log in again to get a new token

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
