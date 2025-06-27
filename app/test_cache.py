"""Tests for cache module"""
import time
import pytest
from app.cache import Cache, cached, cache_key


def test_cache_basic():
    """Test basic cache operations"""
    c = Cache()
    
    # Test set and get
    c.set("key1", "value1", ttl_seconds=60)
    assert c.get("key1") == "value1"
    
    # Test cache miss
    assert c.get("nonexistent") is None
    
    # Test stats
    stats = c.get_stats()
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["sets"] == 1
    assert stats["size"] == 1


def test_cache_expiration():
    """Test cache TTL expiration"""
    c = Cache()
    
    # Set with very short TTL
    c.set("key1", "value1", ttl_seconds=0.1)
    assert c.get("key1") == "value1"
    
    # Wait for expiration
    time.sleep(0.2)
    assert c.get("key1") is None
    
    # Check eviction count
    stats = c.get_stats()
    assert stats["evictions"] == 1


def test_cache_clear():
    """Test cache clearing"""
    c = Cache()
    
    # Add multiple items
    c.set("key1", "value1", ttl_seconds=60)
    c.set("key2", "value2", ttl_seconds=60)
    c.set("key3", "value3", ttl_seconds=60)
    
    assert c.get_stats()["size"] == 3
    
    # Clear cache
    c.clear()
    assert c.get_stats()["size"] == 0
    assert c.get("key1") is None
    assert c.get("key2") is None
    assert c.get("key3") is None


def test_cache_cleanup():
    """Test expired entry cleanup"""
    c = Cache()
    
    # Add items with different TTLs
    c.set("key1", "value1", ttl_seconds=0.1)
    c.set("key2", "value2", ttl_seconds=60)
    c.set("key3", "value3", ttl_seconds=0.1)
    
    # Wait for some to expire
    time.sleep(0.2)
    
    # Cleanup expired
    c.cleanup_expired()
    
    # Only key2 should remain
    assert c.get_stats()["size"] == 1
    assert c.get("key2") == "value2"
    assert c.get_stats()["evictions"] == 2


def test_cached_decorator():
    """Test @cached decorator"""
    call_count = 0
    
    @cached(ttl_seconds=60)
    def expensive_function(x, y):
        nonlocal call_count
        call_count += 1
        return x + y
    
    # First call - cache miss
    result1 = expensive_function(1, 2)
    assert result1 == 3
    assert call_count == 1
    
    # Second call - cache hit
    result2 = expensive_function(1, 2)
    assert result2 == 3
    assert call_count == 1  # Function not called again
    
    # Different arguments - cache miss
    result3 = expensive_function(2, 3)
    assert result3 == 5
    assert call_count == 2


def test_cache_key_generation():
    """Test cache key generation"""
    # Same arguments should generate same key
    key1 = cache_key(1, 2, foo="bar")
    key2 = cache_key(1, 2, foo="bar")
    assert key1 == key2
    
    # Different arguments should generate different keys
    key3 = cache_key(1, 3, foo="bar")
    assert key1 != key3
    
    # Different kwargs should generate different keys
    key4 = cache_key(1, 2, foo="baz")
    assert key1 != key4


def test_cache_stats_hit_rate():
    """Test cache hit rate calculation"""
    c = Cache()
    
    # Initial state - no requests
    stats = c.get_stats()
    assert stats["hit_rate"] == "0.0%"
    
    # Make some cache operations
    c.set("key1", "value1", ttl_seconds=60)
    c.get("key1")  # Hit
    c.get("key1")  # Hit
    c.get("key2")  # Miss
    
    stats = c.get_stats()
    assert stats["hits"] == 2
    assert stats["misses"] == 1
    assert stats["hit_rate"] == "66.7%"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])