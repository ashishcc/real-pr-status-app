# Makefile for Real PR Status App Docker operations

.PHONY: help build run stop clean logs shell test prod-build prod-run

# Default target
help:
	@echo "Available commands:"
	@echo "  make build       - Build the Docker image"
	@echo "  make run         - Run the container with docker-compose"
	@echo "  make stop        - Stop the container"
	@echo "  make clean       - Remove container and image"
	@echo "  make logs        - View container logs"
	@echo "  make shell       - Open shell in container"
	@echo "  make test        - Run tests in container"
	@echo "  make prod-build  - Build production image"
	@echo "  make prod-run    - Run production container"

# Build the Docker image
build:
	docker-compose build

# Run the container
run:
	docker-compose up -d
	@echo "Application running at http://localhost:8000"
	@echo "View logs with: make logs"

# Stop the container
stop:
	docker-compose down

# Clean up containers and images
clean:
	docker-compose down -v
	docker rmi real-pr-status-app_api || true

# View logs
logs:
	docker-compose logs -f

# Open shell in container
shell:
	docker-compose exec api /bin/bash

# Run tests
test:
	docker-compose run --rm api python -m pytest app/test_cache.py -v

# Build production image
prod-build:
	docker build -f Dockerfile.prod -t real-pr-status-api:prod .

# Run production container
prod-run:
	docker run -d \
		--name real-pr-status-api-prod \
		-p 8000:8000 \
		--env-file .env \
		--restart unless-stopped \
		real-pr-status-api:prod

# Development mode with hot reload
dev:
	docker-compose -f docker-compose.yml up

# Check container health
health:
	@docker inspect real-pr-status-api --format='Container: {{.Name}}, Health: {{.State.Health.Status}}'

# Quick restart
restart: stop run