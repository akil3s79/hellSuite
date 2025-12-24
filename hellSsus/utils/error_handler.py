"""
HellSuite Error Handling Utilities
Professional error handling with retries, validation, and logging
"""

import time
import logging
from functools import wraps
from typing import Callable, Any, Optional
import re
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Custom Exceptions
class HellSuiteError(Exception):
    """Base exception for HellSuite"""
    pass

class IntegrationError(HellSuiteError):
    """Integration-related errors"""
    pass

class TimeoutError(HellSuiteError):
    """Operation timeout"""
    pass

class NetworkError(HellSuiteError):
    """Network-related errors"""
    pass

class DatabaseError(HellSuiteError):
    """Database-related errors"""
    pass

class ValidationError(HellSuiteError):
    """Input validation errors"""
    pass

# Database connection context manager
class DatabaseConnection:
    """Context manager for database connections"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = None
        
    def __enter__(self):
        import sqlite3
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        logger.debug(f"Database connection opened: {self.db_path}")
        return self.conn
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            self.conn.close()
            logger.debug("Database connection closed")
        if exc_type:
            logger.error(f"Database error: {exc_val}", exc_info=True)
        return False

# Retry decorator
def retry(max_attempts: int = 3, delay: float = 1.0, 
          exceptions: tuple = (Exception,), 
          backoff_factor: float = 2.0):
    """
    Retry decorator with exponential backoff
    
    Args:
        max_attempts: Maximum number of retry attempts
        delay: Initial delay between retries in seconds
        exceptions: Tuple of exceptions to catch and retry
        backoff_factor: Multiplier for exponential backoff
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_attempts - 1:  # Not the last attempt
                        logger.warning(
                            f"Attempt {attempt + 1}/{max_attempts} failed for {func.__name__}: {str(e)[:100]}"
                        )
                        time.sleep(current_delay)
                        current_delay *= backoff_factor
                    else:
                        logger.error(
                            f"All {max_attempts} attempts failed for {func.__name__}: {str(e)[:100]}"
                        )
            
            # If all retries failed, raise the last exception
            raise last_exception
        return wrapper
    return decorator

# URL validation
def validate_url(url: str, require_scheme: bool = True) -> bool:
    """
    Validate URL format
    
    Args:
        url: URL to validate
        require_scheme: Whether to require http:// or https://
    
    Returns:
        bool: True if URL is valid
    
    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError("URL must be a non-empty string")
    
    url = url.strip()
    
    # Basic length check
    if len(url) > 2048:
        raise ValidationError("URL exceeds maximum length of 2048 characters")
    
    # Check for dangerous characters
    if any(char in url for char in ['\x00', '\r', '\n', '\t']):
        raise ValidationError("URL contains invalid characters")
    
    # Try to parse URL
    try:
        result = urlparse(url)
        
        if require_scheme:
            if not result.scheme:
                raise ValidationError("URL must include scheme (http:// or https://)")
            if result.scheme not in ('http', 'https'):
                raise ValidationError("URL scheme must be http:// or https://")
        
        if not result.netloc:
            raise ValidationError("URL must include a hostname")
        
        # Check for localhost/internal IPs (warning only)
        if result.netloc in ('localhost', '127.0.0.1', '0.0.0.0'):
            logger.warning(f"URL points to localhost/internal IP: {url}")
        
        return True
        
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {str(e)}")

# Error logging with context
def log_error_with_context(error: Exception, context: dict = None, 
                          level: str = 'error') -> None:
    """
    Log error with additional context
    
    Args:
        error: Exception to log
        context: Additional context dictionary
        level: Log level ('debug', 'info', 'warning', 'error', 'critical')
    """
    log_method = getattr(logger, level.lower(), logger.error)
    
    context_str = ""
    if context:
        context_str = " | Context: " + ", ".join(f"{k}={v}" for k, v in context.items())
    
    log_method(f"{error.__class__.__name__}: {str(error)}{context_str}", exc_info=True)

# Safe execution wrapper
def safe_execute(func: Callable, default_return: Any = None, 
                log_error: bool = True, **kwargs) -> Any:
    """
    Safely execute a function, returning default value on error
    
    Args:
        func: Function to execute
        default_return: Value to return on error
        log_error: Whether to log errors
        **kwargs: Arguments to pass to function
    
    Returns:
        Result of function or default_return on error
    """
    try:
        return func(**kwargs)
    except Exception as e:
        if log_error:
            logger.error(f"Safe execute failed for {func.__name__}: {e}", exc_info=True)
        return default_return

# Performance timing decorator
def time_execution(func: Callable) -> Callable:
    """Decorator to log execution time of a function"""
    @wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        
        logger.debug(f"{func.__name__} executed in {execution_time:.3f}s")
        
        if execution_time > 5.0:
            logger.warning(f"{func.__name__} took {execution_time:.1f}s (slow)")
        
        return result
    return wrapper

# Input sanitization
def sanitize_input(input_string: str, max_length: int = 1000) -> str:
    """
    Sanitize user input
    
    Args:
        input_string: String to sanitize
        max_length: Maximum allowed length
    
    Returns:
        Sanitized string
    """
    if not input_string:
        return ""
    
    # Truncate
    if len(input_string) > max_length:
        logger.warning(f"Input truncated from {len(input_string)} to {max_length} characters")
        input_string = input_string[:max_length]
    
    # Remove control characters (except tab, newline, carriage return)
    import re
    input_string = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_string)
    
    return input_string.strip()