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

**Access through nginx reverse proxy:**
- Main app: http://localhost:8080/
- Auth service: http://localhost:8080/auth/

**Direct service access (also available):**
- Auth service: http://localhost:3000 (bypasses nginx)
- App service: http://localhost:8000 (bypasses nginx)

## Production Deployment

The application is deployed to `https://rust-auth.tobiasbrandy.com` using GitHub Actions CI/CD pipeline with nginx reverse proxy on port 80.