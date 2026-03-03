import json
import os
from pydantic_settings import BaseSettings
from typing import List, Union


def _get_ml_api_key() -> str:
    """
    Get ML_API_KEY with fallback to legacy API_KEY environment variable.
    Raises an error if no valid API key is found.
    """
    # Try ML_API_KEY first, then fall back to legacy API_KEY
    api_key = os.environ.get("ML_API_KEY") or os.environ.get("API_KEY")
    if not api_key:
        raise ValueError(
            "ML_API_KEY environment variable is required. "
            "Set ML_API_KEY (or legacy API_KEY) to configure the ML service API key."
        )
    return api_key


class Settings(BaseSettings):
    SERVICE_NAME: str = "ML Service"
    SERVICE_VERSION: str = "1.0.0"

    ML_SERVICE_HOST: str = "0.0.0.0"
    ML_SERVICE_PORT: int = 8001
    BACKEND_API_URL: str = "http://localhost:8000"

    HOST: str = "0.0.0.0"
    PORT: int = 8001

    ML_MODEL: str = "hog"
    NUM_JITTERS: int = 5
    MIN_FACE_AREA_RATIO: float = 0.04

    CORS_ORIGINS: Union[str, List[str]] = [
        "https://studentcheck.vercel.app",
        "http://localhost:5173",
    ]

    LOG_LEVEL: str = "info"

    class Config:
        env_file = ".env"
        case_sensitive = True

    @property
    def ML_API_KEY(self) -> str:
        """Get ML API key with fallback to legacy API_KEY"""
        return _get_ml_api_key()

    @property
    def API_KEY(self) -> str:
        """Backward compatibility property"""
        return self.ML_API_KEY

    @property
    def cors_origins_list(self) -> List[str]:
        if isinstance(self.CORS_ORIGINS, str):
            try:
                return json.loads(self.CORS_ORIGINS)
            except Exception:
                return [self.CORS_ORIGINS]
        return self.CORS_ORIGINS


settings = Settings()
