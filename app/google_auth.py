"""Direct Google OAuth implementation as an alternative to Keymaker"""

import os
import httpx
from typing import Dict, Any, Optional
from fastapi import HTTPException, status
from google.oauth2 import id_token
from google.auth.transport import requests

# Google OAuth configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")


class GoogleAuthService:
    """Service for direct Google OAuth authentication"""
    
    @staticmethod
    async def verify_google_token(token: str) -> Dict[str, Any]:
        """
        Verify Google ID token and extract user information
        
        Args:
            token: Google ID token or access token
            
        Returns:
            User information dictionary
        """
        try:
            # For ID tokens (recommended approach)
            if GOOGLE_CLIENT_ID:
                idinfo = id_token.verify_oauth2_token(
                    token, 
                    requests.Request(), 
                    GOOGLE_CLIENT_ID
                )
                
                # Verify the token is from our app
                if idinfo['aud'] != GOOGLE_CLIENT_ID:
                    raise ValueError('Invalid audience')
                
                return {
                    "username": idinfo.get('email', '').split('@')[0],
                    "email": idinfo.get('email'),
                    "fullName": idinfo.get('name'),
                    "picture": idinfo.get('picture'),
                    "googleId": idinfo.get('sub')
                }
            
            # For access tokens (alternative approach)
            else:
                return await GoogleAuthService._verify_access_token(token)
                
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid Google token: {str(e)}"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to verify Google token: {str(e)}"
            )
    
    @staticmethod
    async def _verify_access_token(access_token: str) -> Dict[str, Any]:
        """
        Verify Google access token by calling Google's userinfo endpoint
        
        Args:
            access_token: Google OAuth access token
            
        Returns:
            User information dictionary
        """
        async with httpx.AsyncClient() as client:
            try:
                # Call Google's userinfo endpoint
                response = await client.get(
                    "https://www.googleapis.com/oauth2/v2/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                response.raise_for_status()
                
                userinfo = response.json()
                
                return {
                    "username": userinfo.get('email', '').split('@')[0],
                    "email": userinfo.get('email'),
                    "fullName": userinfo.get('name'),
                    "picture": userinfo.get('picture'),
                    "googleId": userinfo.get('id')
                }
                
            except httpx.HTTPError as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Failed to verify Google access token: {str(e)}"
                )


class MockAuthService:
    """Mock authentication service for development/testing"""
    
    @staticmethod
    async def mock_google_login(token: str) -> Dict[str, Any]:
        """
        Return mock user data for testing
        
        Args:
            token: Any token string (ignored in mock mode)
            
        Returns:
            Mock user information
        """
        # Check if this is the hardcoded user token
        if token == "mock-real-user-token":
            return {
                "username": "real-user",
                "email": "real-user@realbrokerage.com",
                "fullName": "Real User",
                "picture": None,
                "googleId": "real123456789"
            }
        
        # Different mock users based on token for testing
        mock_users = {
            "mock-google-access-token": {
                "username": "testuser",
                "email": "testuser@realbrokerage.com",
                "fullName": "Test User",
                "picture": None,
                "googleId": "123456789"
            },
            "mock-admin-token": {
                "username": "admin",
                "email": "admin@realbrokerage.com",
                "fullName": "Admin User",
                "picture": None,
                "googleId": "987654321"
            }
        }
        
        return mock_users.get(token, {
            "username": "defaultuser",
            "email": "default@realbrokerage.com",
            "fullName": "Default User",
            "picture": None,
            "googleId": "000000000"
        })