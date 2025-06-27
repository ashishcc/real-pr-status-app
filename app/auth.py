"""Authentication module for JWT token management"""

import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24  # 24 hours

# Security
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


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_info: UserInfo


def create_access_token(data: dict):
    """Create a JWT token with expiration"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    """Verify and decode JWT token"""
    token = credentials.credentials
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        email: str = payload.get("email")
        exp = payload.get("exp")
        
        if username is None or email is None:
            raise credentials_exception
            
        token_data = TokenData(
            username=username, 
            email=email,
            exp=datetime.fromtimestamp(exp)
        )
        return token_data
        
    except JWTError:
        raise credentials_exception


async def get_current_user(token_data: TokenData = Depends(verify_token)) -> UserInfo:
    """Get current user from token"""
    return UserInfo(
        username=token_data.username,
        email=token_data.email,
        full_name=None,
        picture=None
    )