"""
HellSuite Utility Decorators
Common decorators for logging, validation, and caching
"""

import time
import functools
import logging
from typing import Callable, Any
from utils.error_handler import validate_url

logger = logging.getLogger(__name__)

def log_execution(log_args: bool = False, log_time: bool = True):
    """Decorator to log function execution"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            start_time = time.time()
            
            if log_args:
                logger.debug(f"Executing {func.__name__} with args={args}, kwargs={kwargs}")
            else:
                logger.debug(f"Executing {func.__name__}")
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                if log_time:
                    logger.debug(f"{func.__name__} completed in {execution_time:.3f}s")
                
                return result
            except Exception as e:
                logger.error(f"{func.__name__} failed: {e}")
                raise
        
        return wrapper
    return decorator

def validate_target_url(func: Callable) -> Callable:
    """Decorator to validate target URL before execution"""
    @functools.wraps(func)
    def wrapper(target: str, *args, **kwargs) -> Any:
        validate_url(target)  # From error_handler.py
        return func(target, *args, **kwargs)
    return wrapper

# Simple caching decorator (in-memory, for development)
def cached(ttl: int = 300):  # Time to live in seconds
    """Simple caching decorator with TTL"""
    cache = {}
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            cache_key = (func.__name__, args, frozenset(kwargs.items()))
            
            if cache_key in cache:
                timestamp, value = cache[cache_key]
                if time.time() - timestamp < ttl:
                    logger.debug(f"Cache hit for {func.__name__}")
                    return value
            
            result = func(*args, **kwargs)
            cache[cache_key] = (time.time(), result)
            return result
        
        return wrapper
    return decorator

# Alias for backward compatibility
robust_scan = log_execution(log_args=True, log_time=True)