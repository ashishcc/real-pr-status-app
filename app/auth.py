"""Authentication module for SSO integration with Keymaker"""

import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours
KEYMAKER_BASE_URL = "https://keymaker.team1realbrokerage.com"

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()


class TokenData(BaseModel):
    username: str
    email: str
    exp: datetime


class UserInfo(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    picture: Optional[str] = None


class GoogleAuthRequest(BaseModel):
    access_token: str


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_info: UserInfo


class KeymakerClient:
    """Client for interacting with Keymaker SSO service"""
    
    def __init__(self):
        self.base_url = KEYMAKER_BASE_URL
        self.client = httpx.AsyncClient()
    
    async def get_google_sso_info(self, email_or_username: str) -> Dict[str, Any]:
        """Get SSO info by email or username from Keymaker"""
        try:
            response = await self.client.get(
                f"{self.base_url}/api/v1/google-sso-info-by-email-or-username",
                params={"identifier": email_or_username}
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Failed to connect to Keymaker service: {str(e)}"
            )
    
    async def signin_by_google(self, google_token: str) -> Dict[str, Any]:
        """Sign in using Google token via Keymaker"""
        # For development/testing, we'll simulate a successful response
        # In production, you would need to:
        # 1. Add proper API keys/headers if required by Keymaker
        # 2. Or implement direct Google OAuth validation
        
        if os.getenv("ENABLE_MOCK_AUTH", "true").lower() == "true":
            # Mock response for testing
            return {
                "username": "testuser",
                "email": "testuser@realbrokerage.com",
                "fullName": "Test User",
                "picture": None,
                "token": "mock-keymaker-token"
            }
        
        try:
            # Add headers if required by Keymaker API
            headers = {
                "Content-Type": "application/json",
                # Add API key if required: "X-API-Key": os.getenv("KEYMAKER_API_KEY", "")
            }
            
            response = await self.client.post(
                f"{self.base_url}/api/v1/signin-by-google",
                json={"googleToken": google_token},
                headers=headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            # Log the full error for debugging
            print(f"Keymaker API error: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Response status: {e.response.status_code}")
                print(f"Response body: {e.response.text}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Google authentication failed: {str(e)}"
            )
    
    async def signin_with_mfa(self, username: str, mfa_code: str, session_token: str) -> Dict[str, Any]:
        """Complete sign in with MFA via Keymaker"""
        try:
            response = await self.client.post(
                f"{self.base_url}/api/v1/signin-with-mfa",
                json={
                    "username": username,
                    "mfaCode": mfa_code,
                    "sessionToken": session_token
                }
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"MFA authentication failed: {str(e)}"
            )
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    """Verify and decode JWT token"""
    token = credentials.credentials
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        email: str = payload.get("email")
        exp: datetime = datetime.fromtimestamp(payload.get("exp"))
        
        if username is None or email is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        token_data = TokenData(username=username, email=email, exp=exp)
        return token_data
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(token_data: TokenData = Depends(verify_token)) -> UserInfo:
    """Get current authenticated user"""
    return UserInfo(
        username=token_data.username,
        email=token_data.email
    )


# Initialize Keymaker client
keymaker_client = KeymakerClient()