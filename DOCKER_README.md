# Docker Deployment Guide for Real PR Status App

This guide explains how to build and run the Real PR Status App using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose (optional, for easier deployment)
- GitHub Personal Access Token

## Quick Start

### 1. Clone the repository
```bash
git clone <your-repo-url>
cd real-pr-status-app
```

### 2. Set up environment variables
```bash
# Copy the Docker environment template
cp .env.docker .env

# Edit .env and add your configuration
# Required: GITHUB_TOKEN
# Required for production: JWT_SECRET_KEY
```

### 3. Build and run with Docker Compose (Recommended)
```bash
# Build and start the container
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the container
docker-compose down
```

### 4. Or build and run with Docker directly
```bash
# Build the image
docker build -t real-pr-status-api .

# Run the container
docker run -d \
  --name real-pr-status-api \
  -p 8000:8000 \
  -e GITHUB_TOKEN=your_github_token_here \
  -e JWT_SECRET_KEY=your_secret_key_here \
  -e ENABLE_MOCK_AUTH=false \
  real-pr-status-api

# View logs
docker logs -f real-pr-status-api

# Stop the container
docker stop real-pr-status-api
docker rm real-pr-status-api
```

## Production Deployment

### Using the production Dockerfile
```bash
# Build production image (multi-stage, optimized)
docker build -f Dockerfile.prod -t real-pr-status-api:prod .

# Run with production settings
docker run -d \
  --name real-pr-status-api \
  -p 8000:8000 \
  --restart unless-stopped \
  --memory="512m" \
  --cpus="1.0" \
  -e GITHUB_TOKEN=${GITHUB_TOKEN} \
  -e JWT_SECRET_KEY=${JWT_SECRET_KEY} \
  -e ENABLE_MOCK_AUTH=false \
  real-pr-status-api:prod
```

### Using Docker Compose in production
```bash
# Start with production compose file
docker-compose -f docker-compose.yml up -d

# Scale if needed
docker-compose up -d --scale api=3
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `GITHUB_TOKEN` | GitHub Personal Access Token | Yes | - |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Yes | `your-secret-key-here` |
| `ENABLE_MOCK_AUTH` | Enable mock authentication | No | `false` |
| `KEYMAKER_API_KEY` | Keymaker API key (if using) | No | - |
| `PORT` | Port to run the application | No | `8000` |

## Health Check

The container includes a health check that verifies the API is responding:

```bash
# Check container health
docker inspect real-pr-status-api --format='{{.State.Health.Status}}'

# Or with docker-compose
docker-compose ps
```

## Troubleshooting

### Container won't start
```bash
# Check logs
docker logs real-pr-status-api

# Common issues:
# - Missing GITHUB_TOKEN environment variable
# - Port 8000 already in use
# - Invalid JWT_SECRET_KEY
```

### Permission errors
```bash
# The container runs as non-root user (uid 1000)
# Ensure mounted volumes have correct permissions
chown -R 1000:1000 ./mounted-directory
```

### Memory issues
```bash
# Increase memory limit in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1G
```

## Development Mode

For development with hot reload:

```bash
# Uncomment the volume mount in docker-compose.yml
volumes:
  - ./app:/app/app

# Run with development mode
docker-compose up
```

## Security Best Practices

1. **Never commit `.env` files** to version control
2. **Use strong JWT secret keys** in production
3. **Rotate GitHub tokens** regularly
4. **Use HTTPS** when exposing to internet (use reverse proxy)
5. **Keep Docker images updated** with security patches

## Updating the Application

```bash
# Pull latest code
git pull

# Rebuild the image
docker-compose build

# Restart with new image
docker-compose up -d
```

## Monitoring

### View real-time logs
```bash
docker-compose logs -f api
```

### Check resource usage
```bash
docker stats real-pr-status-api
```

### Export logs
```bash
docker logs real-pr-status-api > app.log 2>&1
```

## Backup and Restore

Since the app uses in-memory caching and no persistent storage, there's no data to backup. Configuration is managed through environment variables.

## Integration with CI/CD

### GitHub Actions example
```yaml
- name: Build and push Docker image
  run: |
    docker build -t ${{ secrets.DOCKER_REGISTRY }}/real-pr-status-api:${{ github.sha }} .
    docker push ${{ secrets.DOCKER_REGISTRY }}/real-pr-status-api:${{ github.sha }}
```

### GitLab CI example
```yaml
build:
  stage: build
  script:
    - docker build -t $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
```

## Support

For issues related to:
- Docker setup: Check Docker logs and this guide
- Application bugs: Check application logs
- GitHub API: Verify token permissions and rate limits