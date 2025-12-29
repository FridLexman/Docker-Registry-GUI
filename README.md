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

### Local dev (Python)
```bash
git clone https://github.com/FridLexman/Docker-Registry-GUI.git
cd Docker-Registry-GUI
pip install -r requirements.txt
export REGISTRY_URL=http://localhost:5000
export JWT_SECRET=$(openssl rand -hex 32)
export ADMIN_PASSWORD='choose-a-strong-password'
python app.py
```
Open `http://localhost:12000`. On first run, an admin user is created with the password you set in `ADMIN_PASSWORD`.

### Docker
```bash
docker build -t docker-registry-gui:latest .
docker run -d \
  -p 12000:12000 \
  -e REGISTRY_URL=http://your-registry:5000 \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  -e ADMIN_PASSWORD='choose-a-strong-password' \
  -v $(pwd)/data/users.json:/app/users.json \
  --name registry-gui \
  docker-registry-gui:latest
```
- `users.json` is created on first run; mount it to persist accounts/2FA.

### Kubernetes (example)
Create a Secret with your credentials:
```bash
kubectl create secret generic registry-gui-secrets -n registry \
  --from-literal=jwtSecret=$(openssl rand -hex 32) \
  --from-literal=adminPassword='choose-a-strong-password'
```
Deployment snippet:
```yaml
containers:
- name: registry-gui
  image: 192.168.1.60:5000/docker-registry-gui:v6
  env:
  - name: REGISTRY_URL
    value: http://docker-registry.registry.svc.cluster.local:5000
  - name: JWT_SECRET
    valueFrom:
      secretKeyRef:
        name: registry-gui-secrets
        key: jwtSecret
  - name: ADMIN_PASSWORD
    valueFrom:
      secretKeyRef:
        name: registry-gui-secrets
        key: adminPassword
  volumeMounts:
  - name: users
    mountPath: /app/users.json
    subPath: users.json
volumes:
- name: users
  persistentVolumeClaim:
    claimName: registry-gui-users
```
Pair this with a Service/Ingress (see `cluster-export/registry-gui.yaml`). Use `/` for readiness/liveness; `/api/health` requires auth.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REGISTRY_URL` | Default Docker registry URL | `http://localhost:5000` |
| `JWT_SECRET` | Secret key for JWT tokens | Auto-generated |
| `JWT_EXPIRY_HOURS` | Token expiration time | `24` |
| `ADMIN_PASSWORD` | Initial admin password | `admin123` |
| `USERS_FILE` | Path to users database | `users.json` |

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
