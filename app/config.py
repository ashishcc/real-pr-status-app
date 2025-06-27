"""Configuration file for GitHub PR Tracker"""

# GitHub organization to search for PRs
GITHUB_ORGANIZATION = "Realtyka"

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

# CORS settings
ALLOWED_ORIGINS = [
    "http://localhost:8100",  # Ionic dev server
    "http://localhost:3000",  # Alternative dev server
    "http://localhost:4200",  # Angular dev server
]