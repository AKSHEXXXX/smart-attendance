import os
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import TRUSTED_PROXIES

logger = logging.getLogger(__name__)


def _get_rate_limit_key_func():
    """
    Get the appropriate key function for rate limiting.
    
    For authenticated attendance endpoints, prefers user_id over IP to avoid
    shared rate limit buckets. Falls back to client IP for unauthenticated requests.
    
    Uses X-Forwarded-For header only if the immediate peer is a trusted proxy,
    otherwise falls back to remote address to prevent IP spoofing.
    """
    # Parse trusted proxies set
    trusted_proxies = set()
    if TRUSTED_PROXIES:
        trusted_proxies = {p.strip() for p in TRUSTED_PROXIES.split(",") if p.strip()}

    def _get_client_ip(request):
        """Get client IP address, respecting trusted proxies."""
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

    def key_func(request):
        """
        Rate limit key function that prefers user_id for authenticated requests.
        
        Checks for user_id in:
        1. request.state.user_id - set by get_current_user dependency
        2. Authorization header - decode JWT to extract user_id for manual auth
        
        Falls back to client IP for unauthenticated requests.
        """
        # Priority 1: Check if user_id is already set in request.state (by get_current_user)
        if hasattr(request.state, "user_id") and request.state.user_id:
            return f"user_id:{request.state.user_id}"
        
        # Priority 2: Try to extract user_id from Authorization header (for manual JWT decoding)
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            try:
                from app.utils.jwt_token import decode_jwt
                token = auth_header.split(" ")[1]
                decoded = decode_jwt(token)
                user_id = decoded.get("user_id")
                if user_id:
                    return f"user_id:{user_id}"
            except Exception:
                # If JWT decode fails, fall through to IP-based limiting
                pass
        
        # Priority 3: Fall back to client IP address
        return _get_client_ip(request)
    
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
