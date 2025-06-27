"""Pydantic models for API responses"""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel


class ReviewComments(BaseModel):
    total: int
    resolved: int
    unresolved: int


class PullRequest(BaseModel):
    id: int
    number: int
    title: str
    repository: str
    created_at: datetime
    url: str
    state: str
    review_comments: ReviewComments
    reviewers: List[str]
    first_comment_date: Optional[datetime] = None
    last_comment_date: Optional[datetime] = None
    last_comment_by: Optional[str] = None


class DeveloperPRs(BaseModel):
    username: str
    pull_requests: List[PullRequest]


class PRResponse(BaseModel):
    developers: List[DeveloperPRs]
    fetched_at: datetime
    rate_limit_remaining: int