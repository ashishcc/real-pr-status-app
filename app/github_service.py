"""GitHub API service for fetching PR data"""
import os
from datetime import datetime
from typing import List, Dict, Any
from github import Github, GithubException
from github.PullRequest import PullRequest as GithubPR
from dotenv import load_dotenv
import logging

from app.models import PullRequest, ReviewComments, DeveloperPRs
from app.config import GITHUB_ORGANIZATION
from app.cache import cache

load_dotenv()

logger = logging.getLogger(__name__)


class GitHubService:
    def __init__(self):
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ValueError("GITHUB_TOKEN environment variable is not set")
        
        self.github = Github(token)
        
    def get_rate_limit_info(self) -> Dict[str, int]:
        """Get current rate limit status"""
        rate_limit = self.github.get_rate_limit()
        return {
            "remaining": rate_limit.core.remaining,
            "limit": rate_limit.core.limit,
            "reset_time": rate_limit.core.reset.timestamp()
        }
    
    def _process_pr_comments(self, pr: GithubPR) -> Dict[str, Any]:
        """Process PR review comments to get counts and dates"""
        resolved = 0
        unresolved = 0
        reviewers = set()
        first_comment = None
        last_comment = None
        last_comment_by = None
        
        try:
            # Get review comments
            for comment in pr.get_review_comments():
                reviewers.add(comment.user.login)
                
                # Track first and last comment dates
                if not first_comment or comment.created_at < first_comment:
                    first_comment = comment.created_at
                if not last_comment or comment.created_at > last_comment:
                    last_comment = comment.created_at
                    last_comment_by = comment.user.login
                
                # Check if comment is resolved (simplified logic)
                # In real implementation, you'd check for reactions, replies, etc.
                if comment.position is None:  # Outdated comments are marked as resolved
                    resolved += 1
                else:
                    unresolved += 1
            
            # Also get issue comments (general PR comments)
            for comment in pr.get_issue_comments():
                reviewers.add(comment.user.login)
                if not first_comment or comment.created_at < first_comment:
                    first_comment = comment.created_at
                if not last_comment or comment.created_at > last_comment:
                    last_comment = comment.created_at
                    last_comment_by = comment.user.login
                
        except Exception as e:
            logger.error(f"Error processing comments for PR {pr.number}: {e}")
        
        return {
            "total": resolved + unresolved,
            "resolved": resolved,
            "unresolved": unresolved,
            "reviewers": list(reviewers),
            "first_comment_date": first_comment,
            "last_comment_date": last_comment,
            "last_comment_by": last_comment_by
        }
    
    def fetch_developer_prs(self, username: str) -> List[PullRequest]:
        """Fetch open PRs for a specific developer in the configured organization"""
        # Check cache first
        cache_key = f"prs:{username}"
        cached_prs = cache.get(cache_key)
        if cached_prs is not None:
            logger.info(f"Returning cached PRs for {username}")
            return cached_prs
        
        prs = []
        
        try:
            # Search for open PRs authored by the user in the configured organization
            query = f"is:pr is:open author:{username} org:{GITHUB_ORGANIZATION}"
            logger.info(f"Searching with query: {query}")
            issues = self.github.search_issues(query=query)
            
            for issue in issues:
                # Get the actual PR object
                pr = issue.as_pull_request()
                
                # Process comments
                comment_data = self._process_pr_comments(pr)
                
                # Create PR model
                pr_model = PullRequest(
                    id=pr.id,
                    number=pr.number,
                    title=pr.title,
                    repository=pr.base.repo.full_name,
                    created_at=pr.created_at,
                    url=pr.html_url,
                    state=pr.state,
                    review_comments=ReviewComments(
                        total=comment_data["total"],
                        resolved=comment_data["resolved"],
                        unresolved=comment_data["unresolved"]
                    ),
                    reviewers=comment_data["reviewers"],
                    first_comment_date=comment_data["first_comment_date"],
                    last_comment_date=comment_data["last_comment_date"],
                    last_comment_by=comment_data["last_comment_by"]
                )
                
                prs.append(pr_model)
                
        except GithubException as e:
            logger.error(f"GitHub API error for user {username}: {e}")
            if e.status == 403 and "rate limit" in str(e):
                raise Exception("GitHub API rate limit exceeded")
        except Exception as e:
            logger.error(f"Error fetching PRs for {username}: {e}")
        
        # Cache the results for 30 minutes
        cache.set(cache_key, prs, ttl_seconds=1800)
        logger.info(f"Cached {len(prs)} PRs for {username}")
        
        return prs
    
    def fetch_all_developer_prs(self, developers: List[str]) -> List[DeveloperPRs]:
        """Fetch PRs for all configured developers"""
        # Generate cache key from developers list
        cache_key = f"all_prs:{','.join(sorted(developers))}"
        cached_result = cache.get(cache_key)
        if cached_result is not None:
            logger.info("Returning cached results for all developers")
            return cached_result
        
        all_developer_prs = []
        
        for developer in developers:
            logger.info(f"Fetching PRs for {developer}")
            prs = self.fetch_developer_prs(developer)
            
            developer_prs = DeveloperPRs(
                username=developer,
                pull_requests=prs
            )
            all_developer_prs.append(developer_prs)
        
        # Cache the aggregated results
        cache.set(cache_key, all_developer_prs, ttl_seconds=1800)
        logger.info(f"Cached results for {len(developers)} developers")
        
        return all_developer_prs