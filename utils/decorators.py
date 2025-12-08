"""
HellSuite Utility Decorators
Reusable decorators for logging, validation, caching, and more
"""
import functools
import time
import hashlib
import json
from typing import Callable, Any, Optional, Dict, List
from collections import defaultdict

from config.logging_config import get_logger
from utils.error_handler import validate_url, ValidationError, retry

logger = get_logger('decorators')

# ============================================================================
# LOGGING DECORATORS
# ============================================================================

def log_execution(log_args: bool = True, log_result: bool = False, log_time: bool = True):
    """
    Decorator to automatically log function execution
    
    Args:
        log_args: Whether to log function arguments
        log_result: Whether to log function result (be careful with sensitive data!)
        log_time: Whether to log execution time
    
    Example:
        @log_execution(log_args=True, log_time=True)
        def scan_target(url, depth=3):
            # Your scanning code
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Prepare log message
            func_name = func.__name__
            module_name = func.__module__
            
            # Log function start
            start_msg = f"Executing {module_name}.{func_name}"
            if log_args and (args or kwargs):
                start_msg += f" with args={args}, kwargs={kwargs}"
            
            logger.info(start_msg)
            
            # Execute and time
            start_time = time.time()
            try:
                result = func(*args, **kwargs)
                elapsed = time.time() - start_time
                
                # Log success
                success_msg = f"{module_name}.{func_name} completed successfully"
                if log_time:
                    success_msg += f" in {elapsed:.2f}s"
                
                if log_result and result is not None:
                    # Truncate long results for logging
                    result_str = str(result)
                    if len(result_str) > 200:
                        result_str = result_str[:200] + "... [truncated]"
                    success_msg += f" -> result: {result_str}"
                
                logger.info(success_msg)
                
                return result
                
            except Exception as e:
                elapsed = time.time() - start_time
                logger.error(
                    f"{module_name}.{func_name} failed after {elapsed:.2f}s: {e}",
                    exc_info=True
                )
                raise
        
        return wrapper
    return decorator

def log_to_metrics(func: Callable) -> Callable:
    """
    Decorator to log function execution to metrics system
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        from config.logging_config import metrics_logger
        
        start_time = time.time()
        func_name = func.__name__
        
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            
            # Log success metric
            metrics_logger.info(
                f"function_call,name={func_name},status=success "
                f"duration={elapsed:.3f},args_count={len(args) + len(kwargs)}"
            )
            
            return result
            
        except Exception as e:
            elapsed = time.time() - start_time
            
            # Log error metric
            metrics_logger.error(
                f"function_call,name={func_name},status=error,error_type={type(e).__name__} "
                f"duration={elapsed:.3f}"
            )
            raise
    
    return wrapper

# ============================================================================
# VALIDATION DECORATORS
# ============================================================================

def validate_arguments(arg_validators: Dict[str, Callable] = None):
    """
    Decorator to validate function arguments before execution
    
    Args:
        arg_validators: Dict mapping arg name to validator function
    
    Example:
        @validate_arguments({
            'url': lambda x: x.startswith('http'),
            'port': lambda x: 1 <= x <= 65535
        })
        def scan(url, port=80):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Get function signature
            import inspect
            sig = inspect.signature(func)
            bound_args = sig.bind(*args, **kwargs)
            bound_args.apply_defaults()
            
            # Apply validators
            if arg_validators:
                for arg_name, validator in arg_validators.items():
                    if arg_name in bound_args.arguments:
                        value = bound_args.arguments[arg_name]
                        try:
                            if not validator(value):
                                raise ValidationError(
                                    f"Argument '{arg_name}' failed validation: {value}"
                                )
                        except Exception as e:
                            raise ValidationError(
                                f"Validation failed for '{arg_name}': {e}"
                            )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

def require_kwargs(**required_kwargs):
    """
    Decorator to require specific keyword arguments
    
    Example:
        @require_kwargs(project_name=str, url=str)
        def start_scan(project_name, url, **kwargs):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            for kwarg_name, kwarg_type in required_kwargs.items():
                if kwarg_name not in kwargs:
                    raise ValidationError(f"Missing required argument: {kwarg_name}")
                
                value = kwargs[kwarg_name]
                if not isinstance(value, kwarg_type):
                    raise ValidationError(
                        f"Argument '{kwarg_name}' must be {kwarg_type}, got {type(value)}"
                    )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

# ============================================================================
# CACHING DECORATORS
# ============================================================================

class SimpleCache:
    """Simple in-memory cache for function results"""
    
    _cache = {}
    _hits = defaultdict(int)
    _misses = defaultdict(int)
    
    @classmethod
    def clear(cls):
        """Clear entire cache"""
        cls._cache.clear()
        cls._hits.clear()
        cls._misses.clear()
        logger.info("Cache cleared")
    
    @classmethod
    def stats(cls):
        """Get cache statistics"""
        return {
            'total_entries': len(cls._cache),
            'hits': dict(cls._hits),
            'misses': dict(cls._misses),
            'hit_ratio': {
                k: cls._hits[k] / (cls._hits[k] + cls._misses[k]) 
                if (cls._hits[k] + cls._misses[k]) > 0 else 0
                for k in set(list(cls._hits.keys()) + list(cls._misses.keys()))
            }
        }

def cached(ttl: int = 300, maxsize: int = 1000, key_func: Callable = None):
    """
    Decorator for caching function results with TTL
    
    Args:
        ttl: Time to live in seconds
        maxsize: Maximum cache size (LRU eviction)
        key_func: Custom cache key function
    
    Example:
        @cached(ttl=3600)  # Cache for 1 hour
        def scan_target(url):
            # Expensive scanning operation
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Generate cache key
            if key_func:
                cache_key = key_func(*args, **kwargs)
            else:
                # Default: function name + repr of args/kwargs
                key_parts = [func.__module__, func.__name__, repr(args), repr(sorted(kwargs.items()))]
                cache_key = hashlib.md5(json.dumps(key_parts).encode()).hexdigest()
            
            # Check cache
            current_time = time.time()
            
            if cache_key in SimpleCache._cache:
                cached_value, expiry = SimpleCache._cache[cache_key]
                
                if current_time < expiry:
                    SimpleCache._hits[func.__name__] += 1
                    logger.debug(f"Cache HIT for {func.__name__}")
                    return cached_value
            
            # Cache miss or expired
            SimpleCache._misses[func.__name__] += 1
            logger.debug(f"Cache MISS for {func.__name__}")
            
            # Execute function
            result = func(*args, **kwargs)
            
            # Store in cache
            expiry = current_time + ttl
            
            # LRU eviction if cache too large
            if len(SimpleCache._cache) >= maxsize:
                # Remove oldest (lowest expiry)
                oldest_key = min(
                    SimpleCache._cache.keys(),
                    key=lambda k: SimpleCache._cache[k][1]
                )
                del SimpleCache._cache[oldest_key]
                logger.debug(f"Cache evicted key: {oldest_key}")
            
            SimpleCache._cache[cache_key] = (result, expiry)
            
            return result
        
        return wrapper
    return decorator

# ============================================================================
# RATE LIMITING DECORATORS
# ============================================================================

class RateLimiter:
    """Simple rate limiter"""
    
    _calls = defaultdict(list)
    
    @classmethod
    def is_allowed(cls, key: str, max_calls: int, period: float) -> bool:
        """Check if call is allowed"""
        current_time = time.time()
        calls = cls._calls[key]
        
        # Remove old calls
        calls = [t for t in calls if current_time - t < period]
        cls._calls[key] = calls
        
        if len(calls) < max_calls:
            calls.append(current_time)
            return True
        
        return False

def rate_limit(max_calls: int = 10, period: float = 1.0, key_func: Callable = None):
    """
    Decorator for rate limiting function calls
    
    Args:
        max_calls: Maximum calls per period
        period: Time period in seconds
        key_func: Function to generate rate limit key
    
    Example:
        @rate_limit(max_calls=5, period=1.0)  # Max 5 calls per second
        def api_request(url):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Generate rate limit key
            if key_func:
                limit_key = key_func(*args, **kwargs)
            else:
                limit_key = func.__name__
            
            # Check rate limit
            if not RateLimiter.is_allowed(limit_key, max_calls, period):
                wait_time = period - (time.time() - RateLimiter._calls[limit_key][0])
                logger.warning(
                    f"Rate limit exceeded for {func.__name__}. "
                    f"Waiting {wait_time:.1f}s"
                )
                time.sleep(wait_time)
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

# ============================================================================
# SPECIALIZED SCANNING DECORATORS
# ============================================================================

def validate_target_url(func: Callable) -> Callable:
    """
    Decorator to validate target URL before scanning functions
    """
    @functools.wraps(func)
    def wrapper(target: str, *args, **kwargs) -> Any:
        # Validate URL
        validate_url(target)
        
        # Log scanning attempt
        logger.info(f"Starting scan for target: {target}")
        
        # Execute scan
        return func(target, *args, **kwargs)
    
    return wrapper

def with_timeout(timeout: float = 30.0):
    """
    Decorator to add timeout to function execution
    
    Warning: Uses multiprocessing, may not work in all environments
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            import multiprocessing
            import queue
            
            # Queue for result communication
            result_queue = multiprocessing.Queue()
            
            def worker():
                try:
                    result = func(*args, **kwargs)
                    result_queue.put(('success', result))
                except Exception as e:
                    result_queue.put(('error', e))
            
            # Start worker process
            process = multiprocessing.Process(target=worker)
            process.start()
            
            # Wait with timeout
            process.join(timeout)
            
            if process.is_alive():
                # Timeout occurred
                process.terminate()
                process.join()
                raise TimeoutError(f"Function {func.__name__} timed out after {timeout}s")
            
            # Get result
            try:
                status, value = result_queue.get_nowait()
                
                if status == 'success':
                    return value
                else:
                    raise value
                    
            except queue.Empty:
                raise TimeoutError(f"Function {func.__name__} failed to return result")
        
        return wrapper
    return decorator

# ============================================================================
# COMPOSITE DECORATORS (combinations)
# ============================================================================

def robust_scan(timeout: float = 60.0, retries: int = 2):
    """
    Composite decorator for robust scanning operations
    
    Combines: timeout, retries, logging, and validation
    """
    def decorator(func: Callable) -> Callable:
        # Apply decorators in order (inner to outer)
        decorated = func
        
        # Add timeout (if supported)
        try:
            decorated = with_timeout(timeout)(decorated)
        except:
            logger.warning("Timeout decorator not available in this environment")
        
        # Add retries
        decorated = retry(max_attempts=retries, delay=2.0)(decorated)
        
        # Add URL validation if first arg is target
        decorated = validate_target_url(decorated)
        
        # Add execution logging
        decorated = log_execution(log_args=True, log_time=True)(decorated)
        
        # Add metrics logging
        decorated = log_to_metrics(decorated)
        
        return decorated
    
    return decorator

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def get_all_decorators():
    """Get all available decorators for documentation"""
    return {
        'logging': [log_execution, log_to_metrics],
        'validation': [validate_arguments, require_kwargs, validate_target_url],
        'caching': [cached],
        'rate_limiting': [rate_limit],
        'robustness': [retry, with_timeout, robust_scan],
        'composite': [robust_scan]
    }