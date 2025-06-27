"""Keymaker authentication service following the exact SSO flow"""

import os
from typing import Dict, Any, Optional
from fastapi import HTTPException, status
import httpx
from pydantic import BaseModel


# Configuration
KEYMAKER_BASE_URL = "https://keymaker.team1realbrokerage.com"
BOLT_BASE_URL = "https://bolt.team1realbrokerage.com"


class GoogleSSOInfo(BaseModel):
    googleSsoEnabled: bool
    forceGoogleSso: bool


class KeymakerSignInResponse(BaseModel):
    errorMessage: Optional[str] = None
    accessToken: str
    userId: str
    tokenType: str = "Bearer"
    mfaType: Optional[str] = None
    forceMfa: Optional[bool] = False
    forceGoogleSso: Optional[bool] = False
    userBlockedUntilEmailVerified: Optional[bool] = False
    phoneNumber: Optional[str] = None


class KeymakerAuthService:
    """Service for Keymaker authentication following the exact flow"""
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def check_google_sso_by_email(self, email: str) -> GoogleSSOInfo:
        """
        Step 1: Check if email address exists and is enabled for forceGoogleSso
        
        Args:
            email: User's email address
            
        Returns:
            GoogleSSOInfo with googleSsoEnabled and forceGoogleSso flags
        """
        try:
            response = await self.client.get(
                f"{KEYMAKER_BASE_URL}/api/v1/auth/google-sso-info-by-email-or-username",
                params={"email": email}
            )
            
            if response.status_code == 404:
                # User not found, return default
                return GoogleSSOInfo(googleSsoEnabled=False, forceGoogleSso=False)
            
            response.raise_for_status()
            data = response.json()
            
            return GoogleSSOInfo(
                googleSsoEnabled=data.get("googleSsoEnabled", False),
                forceGoogleSso=data.get("forceGoogleSso", False)
            )
            
        except httpx.HTTPError as e:
            print(f"Error checking Google SSO info: {e}")
            # Default to allowing Google SSO on error
            return GoogleSSOInfo(googleSsoEnabled=True, forceGoogleSso=False)
    
    async def signin_by_google(self, google_token: str) -> KeymakerSignInResponse:
        """
        Step 5: Sign in using Google token
        
        Args:
            google_token: Google OAuth token received from Google OAuth popup
            
        Returns:
            KeymakerSignInResponse with access token and user info
        """
        try:
            response = await self.client.post(
                f"{KEYMAKER_BASE_URL}/api/v1/auth/signin-by-google",
                json={"googleToken": google_token},
                headers={"Content-Type": "application/json"}
            )
            
            response.raise_for_status()
            data = response.json()
            
            if data.get("errorMessage"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=data["errorMessage"]
                )
            
            return KeymakerSignInResponse(**data)
            
        except httpx.HTTPError as e:
            print(f"Keymaker signin error: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Response status: {e.response.status_code}")
                print(f"Response body: {e.response.text}")
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Failed to sign in with Google: {str(e)}"
            )
    
    async def handle_2fa_redirect(self, keymaker_token: str) -> Dict[str, Any]:
        """
        Step 7: Handle 2FA redirect to Bolt
        
        Args:
            keymaker_token: Access token from Keymaker
            
        Returns:
            Dict with redirect URL and token info
        """
        # In a real implementation, you would redirect to Bolt's 2FA page
        # For API integration, we return the necessary information
        return {
            "redirect_url": f"{BOLT_BASE_URL}/login/2fa",
            "keymaker_token": keymaker_token,
            "requires_2fa": True
        }
    
    async def close(self):
        """Close the HTTP client"""
        await self.client.aclose()


# Singleton instance
keymaker_auth_service = KeymakerAuthService()