"""_summary_"""
from pydantic import BaseModel, EmailStr


class UserCreate(BaseModel):
    """Schema for creating a new user."""
    email: EmailStr
    password: str
    role: str


class TokenPair(BaseModel):
    """Schema for access and refresh tokens."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class LoginData(BaseModel):
    """Schema for user login data."""
    email: EmailStr
    password: str
