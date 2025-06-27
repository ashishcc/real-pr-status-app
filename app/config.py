"""Configuration file for GitHub PR Tracker"""
import os

# GitHub organization to search for PRs
GITHUB_ORGANIZATION = os.getenv("GITHUB_ORGANIZATION", "Realtyka")

# Developer groups mapping
DEVELOPER_GROUPS = {
    "brokerage": ["ankushchoubey-realbrokerage", "ronak-real"],
    "marketing-legal": ["vikas-bhosale", "mohit-chandak-onereal", "ashishreal"],
    "leo": ["Shailendra-Singh-OneReal"]
}

# All developers (generated from groups)
DEVELOPERS = []
for group_developers in DEVELOPER_GROUPS.values():
    DEVELOPERS.extend(group_developers)

# Remove duplicates while preserving order
DEVELOPERS = list(dict.fromkeys(DEVELOPERS))

# CORS settings - can be overridden by environment variable
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:8100",  # Ionic dev server
    "http://localhost:3000",  # Alternative dev server
    "http://localhost:4200",  # Angular dev server
    "https://real-pr-status-web.vercel.app",  # Vercel production
    "https://real-pr-status-1z50zxxvt-ashish-cs-projects.vercel.app",  # Vercel preview
]

# Get additional origins from environment variable (comma-separated)
ADDITIONAL_ORIGINS = os.getenv("ALLOWED_ORIGINS", "").split(",")
ADDITIONAL_ORIGINS = [origin.strip() for origin in ADDITIONAL_ORIGINS if origin.strip()]

# Combine default and additional origins
ALLOWED_ORIGINS = DEFAULT_ALLOWED_ORIGINS + ADDITIONAL_ORIGINS