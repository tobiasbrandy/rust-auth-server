## Setup & Building
```bash
cargo install cargo-watch
cd app-service
cargo build
cd ..
cd auth-service
cargo build
cd ..
```

## Run servers locally (Manually)

> **Note**: Manual mode runs services on different ports than Docker mode

#### App service
```bash
cd app-service
cargo watch -q -c -w src/ -w assets/ -w templates/ -x run
```
Visit http://localhost:8000

#### Auth service
```bash
cd auth-service
cargo watch -q -c -w src/ -w assets/ -x run
```
Visit http://localhost:3000

## Run servers locally (Docker with nginx)
```bash
docker compose build
docker compose up
```

**Local development uses `nginx.dev.conf` for HTTP-only configuration.**

**Access through nginx reverse proxy:**
- Main app: http://localhost:8080/
- Auth service: http://localhost:8080/auth/

**Direct service access (also available):**
- Auth service: http://localhost:3000 (bypasses nginx)
- App service: http://localhost:8000 (bypasses nginx)

**Configuration Files:**
- `nginx.dev.conf` - Local development (HTTP-only, no SSL)
- `nginx.conf` - Production (HTTPS with SSL termination)

## SSL/HTTPS Setup (Production)

### Prerequisites
1. Domain configured in Cloudflare with proxy enabled (orange cloud)
2. Cloudflare Origin Certificate generated

### One-Time SSL Setup

#### Step 1: Generate Cloudflare Origin Certificate
1. Go to Cloudflare Dashboard → SSL/TLS → Origin Server
2. Click "Create Certificate"
3. Select "Let Cloudflare generate a private key and a CSR"
4. Set validity to 15 years
5. Add hostnames: `rust-auth.tobiasbrandy.com` and `*.rust-auth.tobiasbrandy.com`
6. Download both files:
   - Origin Certificate → Save as `cloudflare-origin.pem`
   - Private Key → Save as `cloudflare-origin.key`

#### Step 2: Deploy Certificate to Server
```bash
# Create SSL directory on server
ssh root@rust-auth.tobiasbrandy.com 'mkdir -p /etc/ssl/cloudflare'

# Copy certificate files to server
scp cloudflare-origin.pem root@rust-auth.tobiasbrandy.com:/etc/ssl/cloudflare/
scp cloudflare-origin.key root@rust-auth.tobiasbrandy.com:/etc/ssl/cloudflare/

# Set proper permissions
ssh root@rust-auth.tobiasbrandy.com 'chmod 644 /etc/ssl/cloudflare/cloudflare-origin.pem'
ssh root@rust-auth.tobiasbrandy.com 'chmod 600 /etc/ssl/cloudflare/cloudflare-origin.key'
```

#### Step 3: Configure Cloudflare SSL Settings
1. Go to SSL/TLS → Overview
2. Set encryption mode to **"Full (strict)"**
3. Go to SSL/TLS → Edge Certificates
4. Enable **"Always Use HTTPS"** 
5. Enable **"HTTP Strict Transport Security (HSTS)"**

#### Step 4: Deploy Updated Configuration
```bash
# Deploy via GitHub Actions (push to main branch)
git push origin main

# Or deploy manually
docker compose down
docker compose pull  
docker compose up -d
```

### Verification
After setup, verify HTTPS is working:
- Visit https://rust-auth.tobiasbrandy.com
- HTTP requests should redirect to HTTPS
- Browser should show secure connection
- Test: `curl -I https://rust-auth.tobiasbrandy.com/`

### Certificate Renewal
Cloudflare Origin Certificates are valid for 15 years - no renewal needed until 2040!

## Production Deployment

The application is deployed to `https://rust-auth.tobiasbrandy.com` using GitHub Actions CI/CD pipeline with nginx reverse proxy providing HTTPS termination.

**Production Configuration:**
- **SSL/TLS**: Cloudflare Origin Certificates with nginx SSL termination
- **Ports**: 80 (HTTP → HTTPS redirect) + 443 (HTTPS)
- **Configuration**: `nginx.conf` with SSL, security headers, and HTTPS proxy headers
- **Certificate Path**: `/etc/ssl/cert/` (manually deployed, persists across deployments)
- **Cloudflare**: Full (strict) mode for end-to-end encryption