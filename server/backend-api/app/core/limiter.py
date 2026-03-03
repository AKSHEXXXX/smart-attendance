import os
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import TRUSTED_PROXIES

logger = logging.getLogger(__name__)


def _get_rate_limit_key_func():
    """
    Get the appropriate key function for rate limiting.
    
    Uses X-Forwarded-For header only if the immediate peer is a trusted proxy,
    otherwise falls back to remote address to prevent IP spoofing.
    """
    # Parse trusted proxies set
    trusted_proxies = set()
    if TRUSTED_PROXIES:
        trusted_proxies = {p.strip() for p in TRUSTED_PROXIES.split(",") if p.strip()}

    def key_func(request):
        # Get the immediate peer address (the direct client/proxy connecting to us)
        client_host = request.client.host if request.client else None
        
        # Only trust X-Forwarded-For if the immediate peer is a trusted proxy
        if client_host and trusted_proxies and client_host in trusted_proxies:
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                # Take the first IP (original client)
                return forwarded_for.split(",")[0].strip()
        
        # Otherwise, use the direct remote address
        return get_remote_address(request)
    
    return key_func


# Get Redis URL from environment
REDIS_URL = os.getenv("REDIS_URL", "")

# Configure limiter with dynamic key function and Redis storage if available
if REDIS_URL:
    limiter = Limiter(
        key_func=_get_rate_limit_key_func(),
        storage_uri=REDIS_URL
    )
    logger.info("Rate limiter configured with Redis backend")
else:
    limiter = Limiter(key_func=_get_rate_limit_key_func())
    logger.info(
        "REDIS_URL not configured. Using in-memory rate limiting. "
        "Note: In-memory rate limiting does not work with multiple workers."
    )
