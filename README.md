# Real PR Status App

A real-time GitHub Pull Request tracking dashboard that bridges the visibility gap between development teams and project stakeholders.

## 🎯 Problem Statement

Product Managers and Project Managers (PMs) often lack direct access to GitHub, creating a communication bottleneck where PR status updates are only shared during standup meetings. This limited visibility can lead to:
- Delayed feedback cycles
- Missed blockers on critical PRs
- Inefficient resource allocation
- Reduced transparency in the development process

## 💡 Solution

Real PR Status App provides a secure, web-based dashboard that gives PMs real-time visibility into:
- Open pull requests across development teams
- PR review status and comment activity
- Reviewer assignments and response times
- Team-based PR organization

This enables PMs to:
- **Monitor Progress**: Track PR status without needing GitHub access
- **Identify Bottlenecks**: See which PRs are awaiting review or have unresolved comments
- **Facilitate Communication**: Follow up with developers or reviewers proactively
- **Improve Planning**: Make informed decisions based on real-time development status

## ✨ Key Features

### For Project Managers
- **No GitHub Access Required**: Secure authentication via Google SSO
- **Real-time Updates**: See PR status as it changes, not just during standups
- **Team Organization**: View PRs grouped by teams (e.g., Backend, Frontend, QA)
- **Review Insights**: Track comment activity and reviewer engagement
- **Progress Tracking**: Monitor individual developer workload and PR velocity

### For Development Teams
- **Reduced Meeting Overhead**: Less time explaining PR status in meetings
- **Automated Transparency**: PR status is automatically visible to stakeholders
- **Focus on Development**: Fewer interruptions for status updates
- **Clear Accountability**: Review assignments and timelines are visible

### Technical Features
- **Caching**: 30-minute cache to reduce GitHub API calls
- **Rate Limit Management**: Automatic handling of GitHub API limits
- **Responsive Design**: Works on desktop and mobile devices
- **Secure Authentication**: JWT-based auth with Google SSO integration
- **Docker Support**: Easy deployment with containerization

## 🚀 Quick Start

### Prerequisites
- GitHub Personal Access Token (PAT)
- Google OAuth credentials (for production)
- Docker and Docker Compose (recommended)

### Using Docker (Recommended)

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd real-pr-status-app
   ```

2. **Configure environment**
   ```bash
   cp .env.docker .env
   # Edit .env and add your GITHUB_TOKEN
   ```

3. **Start the application**
   ```bash
   docker-compose up -d
   ```

4. **Access the dashboard**
   ```
   http://localhost:8000
   ```

### Manual Installation

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Set environment variables**
   ```bash
   export GITHUB_TOKEN=your_github_pat_here
   export JWT_SECRET_KEY=your_secret_key_here
   ```

3. **Run the application**
   ```bash
   uvicorn app.main:app --reload
   ```

## 📊 Usage

### For Project Managers

1. **Login**: Use your company email to authenticate via Google SSO
2. **Select Team**: Click on your team's button (e.g., "Brokerage", "Marketing-Legal")
3. **View PRs**: See all open PRs for developers in that team
4. **Track Progress**: Monitor:
   - How long PRs have been open
   - Who last commented and when
   - Number of resolved vs unresolved comments
   - Assigned reviewers

### For Administrators

1. **Configure Teams**: Edit `app/config.py` to define team structures
   ```python
   DEVELOPER_GROUPS = {
       "backend": ["dev1", "dev2"],
       "frontend": ["dev3", "dev4"],
       "qa": ["dev5", "dev6"]
   }
   ```

2. **Monitor Usage**: Check cache statistics and API rate limits
3. **Manage Access**: Configure authentication settings

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_TOKEN` | GitHub Personal Access Token | Yes |
| `JWT_SECRET_KEY` | Secret key for JWT tokens | Yes |
| `ENABLE_MOCK_AUTH` | Enable mock auth for testing | No |
| `GITHUB_ORGANIZATION` | Your GitHub organization | Yes |

### Team Configuration

Edit `app/config.py` to customize:
- Developer groups and team assignments
- GitHub organization name
- CORS allowed origins

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend  │────▶│   Backend   │────▶│  GitHub API │
│  (Angular)  │◀────│  (FastAPI)  │◀────│             │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │    Cache    │
                    │ (In-Memory) │
                    └─────────────┘
```

### Technology Stack
- **Backend**: Python, FastAPI, PyGithub
- **Frontend**: Angular, Ionic Framework
- **Authentication**: Google SSO, JWT
- **Deployment**: Docker, Docker Compose

## 📈 Benefits

### Improved Transparency
- PMs have 24/7 visibility into development progress
- No more waiting for standup meetings to get updates
- Clear view of bottlenecks and blockers

### Enhanced Productivity
- Developers spend less time in status meetings
- PMs can make informed decisions faster
- Reviewers are held accountable for timely reviews

### Better Collaboration
- Bridges the gap between technical and non-technical stakeholders
- Facilitates asynchronous communication
- Reduces context switching for developers

## 🔒 Security

- **Authentication**: Secure Google SSO integration
- **Authorization**: JWT-based session management
- **API Security**: GitHub token never exposed to frontend
- **CORS Protection**: Configured allowed origins
- **Non-root Docker**: Containers run as unprivileged user

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Built to solve real communication challenges in agile development teams
- Designed with both technical and non-technical users in mind
- Inspired by the need for better development transparency

---

**Made with ❤️ to bridge the gap between development and management**