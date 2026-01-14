"""
Docstring for SGCI.authentification.backend.app.settings
"""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Configuration settings for the application."""
    DATABASE_URL: str
    JWT_SECRET: str
    JWT_ALG: str
    ACCESS_TOKEN_MINUTES: int
    REFRESH_TOKEN_DAYS: int

    class Config:
        """
        Docstring for Config
        """
        env_file = ".env"


settings = Settings()
