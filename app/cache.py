"""Simple in-memory cache with TTL support"""

import time
from typing import Any, Dict, Optional, Callable
from functools import wraps
import hashlib
import json
import logging

logger = logging.getLogger(__name__)


class Cache:
    """Simple in-memory cache with TTL support"""
    
    def __init__(self):
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "evictions": 0
        }
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        if key in self._cache:
            entry = self._cache[key]
            if time.time() < entry["expires_at"]:
                self._stats["hits"] += 1
                logger.debug(f"Cache hit for key: {key}")
                return entry["value"]
            else:
                # Expired, remove from cache
                del self._cache[key]
                self._stats["evictions"] += 1
                logger.debug(f"Cache expired for key: {key}")
        
        self._stats["misses"] += 1
        return None
    
    def set(self, key: str, value: Any, ttl_seconds: int):
        """Set value in cache with TTL"""
        self._cache[key] = {
            "value": value,
            "expires_at": time.time() + ttl_seconds,
            "created_at": time.time()
        }
        self._stats["sets"] += 1
        logger.debug(f"Cache set for key: {key}, TTL: {ttl_seconds}s")
    
    def clear(self):
        """Clear all cache entries"""
        self._cache.clear()
        logger.info("Cache cleared")
    
    def cleanup_expired(self):
        """Remove expired entries from cache"""
        current_time = time.time()
        expired_keys = [
            key for key, entry in self._cache.items()
            if current_time >= entry["expires_at"]
        ]
        
        for key in expired_keys:
            del self._cache[key]
            self._stats["evictions"] += 1
        
        if expired_keys:
            logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = (self._stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self._stats,
            "size": len(self._cache),
            "hit_rate": f"{hit_rate:.1f}%"
        }


# Global cache instance
cache = Cache()


def cache_key(*args, **kwargs) -> str:
    """Generate a cache key from function arguments"""
    # Create a string representation of all arguments
    key_data = {
        "args": args,
        "kwargs": kwargs
    }
    
    # Use JSON serialization and MD5 for consistent key generation
    key_str = json.dumps(key_data, sort_keys=True, default=str)
    return hashlib.md5(key_str.encode()).hexdigest()


def cached(ttl_seconds: int = 1800):  # Default 30 minutes
    """
    Decorator to cache function results with TTL
    
    Args:
        ttl_seconds: Time to live in seconds (default 30 minutes)
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from function name and arguments
            key = f"{func.__name__}:{cache_key(*args, **kwargs)}"
            
            # Try to get from cache
            cached_value = cache.get(key)
            if cached_value is not None:
                return cached_value
            
            # Cache miss, call the function
            result = func(*args, **kwargs)
            
            # Store in cache
            cache.set(key, result, ttl_seconds)
            
            return result
        
        # Add cache control methods to the wrapper
        wrapper.cache_clear = lambda: cache.clear()
        wrapper.cache_stats = lambda: cache.get_stats()
        
        return wrapper
    return decorator


# Periodic cleanup task (optional - can be called periodically)
async def cleanup_cache_periodically():
    """Clean up expired cache entries periodically"""
    while True:
        cache.cleanup_expired()
        # Sleep for 5 minutes
        await asyncio.sleep(300)


# Import asyncio only if needed for cleanup task
try:
    import asyncio
except ImportError:
    pass