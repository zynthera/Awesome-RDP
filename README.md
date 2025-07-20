# 🚀 Awesome-RDP: XploitNinjaOfficial

> ⚡️ Ultra-Hardened, Self-Healing, AI-Ready RDP Simulation  
> **Security Mode ON | CDN/Edge Optimized | Multi-agent IDE support**

---

## 🔐 How to Generate and Use JWT_SECRET and ENCRYPTION_KEY

For security and encryption, you must set two environment variables before running the app:
- **JWT_SECRET**: Used to sign/validate JWT tokens for authentication.
- **ENCRYPTION_KEY**: Used for encrypting/decrypting sensitive data.

### Why are these keys needed?
- They protect your RDP sessions and credentials from unauthorized access.
- Without them, authentication and encryption features won’t work, and your system will not be secure.

### How to generate secure keys:

#### JWT_SECRET (32 bytes, hex string)
```bash
# Generate a secure random JWT secret:
openssl rand -hex 32
# OR using Python:
python -c "import secrets; print(secrets.token_hex(32))"
```

#### ENCRYPTION_KEY (Fernet-compatible, base64 string)
```bash
# Generate a Fernet encryption key:
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### How to set the keys for your session:
```bash
export JWT_SECRET="paste_your_generated_jwt_secret_here"
export ENCRYPTION_KEY="paste_your_generated_encryption_key_here"
```

You must run these commands before starting the application every time, or add them to your shell profile for automation.

---

## 🚀 Quickstart

```bash
# Build Docker image with secrets (replace with your secure values)
docker build -t awesome-rdp .
docker run -e JWT_SECRET=your_jwt_secret -e ENCRYPTION_KEY=your_encryption_key -p 8000:8000 awesome-rdp
```

## 🌐 Kubernetes Deployment

Edit `kubernetes.yaml` and fill in the secrets as base64 before deploying.

## 🤖 Security & Self-Healing

- OPA policies: See `opa-policy.rego`.
- Secrets managed via ENV/K8s secrets.
- Logic auto-patches and validates via tests.

## 🛠️ CI/CD

- GitHub Actions pipeline (`.github/workflows/ci.yml`): lint, test, secrets scan.

## 🧪 Tests

- See `tests/` for unit/integration/E2E coverage.
- Run `pytest` locally or via CI.

## 📦 CDN & Static

- All images served via CDN links, static caching headers enabled in infra.

## 📝 AI-Editable Comments

- Inline comments for agent refactoring, security, and optimization.

## 🛡️ Features

- Encryption, JWT, TOTP, ZKP, proxy hopping, anomaly detection, stealth file transfer, remote command exec, session save/load, plugin system, blockchain logging, polished GUI/CLI.