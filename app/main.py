"""Main FastAPI application"""
import os
import asyncio
from datetime import datetime
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import logging
from dotenv import load_dotenv

from app.models import PRResponse, DeveloperPRs
from app.github_service import GitHubService
from app.config import DEVELOPERS, DEVELOPER_GROUPS, ALLOWED_ORIGINS
from app.auth import (
    GoogleAuthRequest, AuthResponse, UserInfo, 
    get_current_user, create_access_token, keymaker_client
)
from app.google_auth import GoogleAuthService, MockAuthService
from app.keymaker_auth import keymaker_auth_service, GoogleSSOInfo
from app.cache import cache, cleanup_cache_periodically

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="GitHub PR Tracker API",
    description="API for tracking open pull requests across multiple developers",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Handle OPTIONS requests globally
@app.middleware("http")
async def handle_options(request: Request, call_next):
    if request.method == "OPTIONS":
        response = Response()
        response.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Credentials"] = "true"
        return response
    
    response = await call_next(request)
    return response

# Initialize GitHub service
github_service = None

@app.on_event("startup")
async def startup_event():
    """Initialize services on startup"""
    global github_service
    try:
        github_service = GitHubService()
        logger.info("GitHub service initialized successfully")
        
        # Start periodic cache cleanup task
        asyncio.create_task(cleanup_cache_periodically())
        logger.info("Cache cleanup task started")
        
    except Exception as e:
        logger.error(f"Failed to initialize GitHub service: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    await keymaker_client.close()
    await keymaker_auth_service.close()


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "GitHub PR Tracker API",
        "version": "1.0.0"
    }


# Authentication endpoints

@app.get("/api/auth/check-google-sso", response_model=GoogleSSOInfo)
async def check_google_sso(email: str):
    """
    Step 1: Check if email is enabled for Google SSO
    
    Args:
        email: User's email address
        
    Returns:
        GoogleSSOInfo with googleSsoEnabled and forceGoogleSso flags
    """
    return await keymaker_auth_service.check_google_sso_by_email(email)


@app.post("/api/auth/google", response_model=AuthResponse)
async def google_auth(request: GoogleAuthRequest):
    """
    Authenticate user via Google SSO
    
    Args:
        request: Contains Google access token
        
    Returns:
        AuthResponse with JWT token and user info
    """
    try:
        # Check if mock auth is enabled
        if os.getenv("ENABLE_MOCK_AUTH", "false").lower() == "true":
            # Use mock authentication for testing
            user_data = await MockAuthService.mock_google_login(request.access_token)
            
            # Extract user info from mock data
            user_info = UserInfo(
                username=user_data.get("username"),
                email=user_data.get("email"),
                full_name=user_data.get("fullName"),
                picture=user_data.get("picture")
            )
        else:
            # Use Keymaker authentication (Step 5 of the flow)
            keymaker_response = await keymaker_auth_service.signin_by_google(request.access_token)
            
            # For now, we'll create a simplified user from the Keymaker response
            # In production, you might need to fetch additional user details
            user_info = UserInfo(
                username=keymaker_response.userId,  # Use userId as username for now
                email=request.access_token,  # You may need to decode the Google token to get email
                full_name=None,
                picture=None
            )
            
            # If 2FA is required, include that info in the response
            if keymaker_response.forceMfa:
                # In a real implementation, you would handle 2FA flow
                logger.info(f"User {keymaker_response.userId} requires 2FA")
                # For now, we'll proceed without 2FA
        
        # Create JWT token
        access_token = create_access_token(
            data={
                "username": user_info.username,
                "email": user_info.email
            }
        )
        
        return AuthResponse(
            access_token=access_token,
            user_info=user_info
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Google authentication error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Authentication failed"
        )


@app.get("/api/auth/me", response_model=UserInfo)
async def get_me(current_user: UserInfo = Depends(get_current_user)):
    """Get current authenticated user info"""
    return current_user


@app.post("/api/auth/logout")
async def logout():
    """Logout endpoint (client should remove token)"""
    return {"message": "Logged out successfully"}


@app.get("/api/pull-requests", response_model=PRResponse)
async def get_pull_requests(current_user: UserInfo = Depends(get_current_user)):
    """
    Fetch open pull requests for all configured developers
    
    Returns:
        PRResponse: List of developers with their open PRs
    """
    try:
        if not github_service:
            raise HTTPException(
                status_code=500,
                detail="GitHub service not initialized"
            )
        
        logger.info("Fetching PRs for all developers")
        
        # Fetch PRs for all developers
        developer_prs = github_service.fetch_all_developer_prs(DEVELOPERS)
        
        # Get rate limit info
        rate_limit_info = github_service.get_rate_limit_info()
        
        response = PRResponse(
            developers=developer_prs,
            fetched_at=datetime.now(),
            rate_limit_remaining=rate_limit_info["remaining"]
        )
        
        logger.info(f"Successfully fetched PRs. Rate limit remaining: {rate_limit_info['remaining']}")
        
        return response
        
    except Exception as e:
        logger.error(f"Error fetching pull requests: {e}")
        
        if "rate limit" in str(e).lower():
            raise HTTPException(
                status_code=429,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch pull requests: {str(e)}"
        )


@app.get("/api/developers")
async def get_developers(current_user: UserInfo = Depends(get_current_user)):
    """Get list of configured developers"""
    return {
        "developers": DEVELOPERS,
        "count": len(DEVELOPERS)
    }


@app.get("/api/groups")
async def get_groups(current_user: UserInfo = Depends(get_current_user)):
    """Get list of developer groups"""
    return {
        "groups": DEVELOPER_GROUPS,
        "count": len(DEVELOPER_GROUPS)
    }


@app.get("/api/groups/{group_name}/pull-requests", response_model=PRResponse)
async def get_group_pull_requests(
    group_name: str,
    current_user: UserInfo = Depends(get_current_user)
):
    """
    Fetch open pull requests for all developers in a specific group
    
    Args:
        group_name: Name of the developer group
        
    Returns:
        PRResponse: List of developers in the group with their open PRs
    """
    try:
        if not github_service:
            raise HTTPException(
                status_code=500,
                detail="GitHub service not initialized"
            )
        
        # Check if group exists
        if group_name not in DEVELOPER_GROUPS:
            raise HTTPException(
                status_code=404,
                detail=f"Group '{group_name}' not found"
            )
        
        # Get developers in the group
        group_developers = DEVELOPER_GROUPS[group_name]
        
        logger.info(f"Fetching PRs for group '{group_name}' with {len(group_developers)} developers")
        
        # Fetch PRs for group developers
        developer_prs = github_service.fetch_all_developer_prs(group_developers)
        
        # Get rate limit info
        rate_limit_info = github_service.get_rate_limit_info()
        
        response = PRResponse(
            developers=developer_prs,
            fetched_at=datetime.now(),
            rate_limit_remaining=rate_limit_info["remaining"]
        )
        
        logger.info(f"Successfully fetched PRs for group '{group_name}'. Rate limit remaining: {rate_limit_info['remaining']}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching pull requests for group '{group_name}': {e}")
        
        if "rate limit" in str(e).lower():
            raise HTTPException(
                status_code=429,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch pull requests: {str(e)}"
        )


@app.get("/api/developers/{username}/pull-requests")
async def get_developer_pull_requests(
    username: str,
    current_user: UserInfo = Depends(get_current_user)
):
    """
    Fetch open pull requests for a specific developer
    
    Args:
        username: GitHub username of the developer
        
    Returns:
        DeveloperPRs: Developer with their open PRs
    """
    try:
        if not github_service:
            raise HTTPException(
                status_code=500,
                detail="GitHub service not initialized"
            )
        
        logger.info(f"Fetching PRs for developer '{username}'")
        
        # Fetch PRs for the developer
        prs = github_service.fetch_developer_prs(username)
        
        developer_prs = DeveloperPRs(
            username=username,
            pull_requests=prs
        )
        
        logger.info(f"Successfully fetched {len(prs)} PRs for developer '{username}'")
        
        return developer_prs
        
    except Exception as e:
        logger.error(f"Error fetching pull requests for developer '{username}': {e}")
        
        if "rate limit" in str(e).lower():
            raise HTTPException(
                status_code=429,
                detail="GitHub API rate limit exceeded. Please try again later."
            )
        
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch pull requests: {str(e)}"
        )


@app.get("/api/rate-limit")
async def get_rate_limit(current_user: UserInfo = Depends(get_current_user)):
    """Get current GitHub API rate limit status"""
    try:
        if not github_service:
            raise HTTPException(
                status_code=500,
                detail="GitHub service not initialized"
            )
        
        rate_limit_info = github_service.get_rate_limit_info()
        return rate_limit_info
        
    except Exception as e:
        logger.error(f"Error fetching rate limit: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to fetch rate limit: {str(e)}"
        )


@app.get("/api/cache/stats")
async def get_cache_stats(current_user: UserInfo = Depends(get_current_user)):
    """Get cache statistics"""
    return cache.get_stats()


@app.post("/api/cache/clear")
async def clear_cache(current_user: UserInfo = Depends(get_current_user)):
    """Clear all cache entries"""
    cache.clear()
    return {"message": "Cache cleared successfully"}