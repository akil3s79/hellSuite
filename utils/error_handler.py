"""
HellSuite Error Handling System
Centralized error handling with retries, validation, and custom exceptions
"""
import time
import functools
import socket
from urllib.parse import urlparse
from typing import Callable, Any, Optional, Union, List

from config.logging_config import get_logger

logger = get_logger('error_handler')

# ============================================================================
# CUSTOM EXCEPTIONS
# ============================================================================

class HellSuiteError(Exception):
    """Base exception for all HellSuite errors"""
    def __init__(self, message: str, module: str = "unknown"):
        self.message = message
        self.module = module
        super().__init__(f"[{module}] {message}")

class HellScannerError(HellSuiteError):
    """Scanner-specific errors"""
    pass

class HellReconError(HellSuiteError):
    """Reconnaissance-specific errors"""
    pass

class HellFuzzerError(HellSuiteError):
    """Fuzzing-specific errors"""
    pass

class DatabaseError(HellSuiteError):
    """Database-related errors"""
    pass

class IntegrationError(HellSuiteError):
    """Integration/toolchain errors"""
    pass

class ValidationError(HellSuiteError):
    """Input validation errors"""
    pass

class TimeoutError(HellSuiteError):
    """Operation timeout errors"""
    pass

class NetworkError(HellSuiteError):
    """Network/connection errors"""
    pass

# ============================================================================
# RETRY DECORATOR
# ============================================================================

def retry(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    log_retries: bool = True
):
    """
    Decorator for retrying failed functions with exponential backoff
    
    Args:
        max_attempts: Maximum number of attempts
        delay: Initial delay between attempts in seconds
        backoff: Backoff multiplier (e.g., 2.0 = doubles each time)
        exceptions: Tuple of exceptions to catch and retry
        log_retries: Whether to log retry attempts
    
    Example:
        @retry(max_attempts=3, delay=1.0, backoff=2.0)
        def scan_target(url):
            # Your scanning code here
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            current_delay = delay
            
            for attempt in range(1, max_attempts + 1):
                try:
                    if attempt > 1 and log_retries:
                        logger.warning(
                            f"Retry attempt {attempt}/{max_attempts} for {func.__name__} "
                            f"(delay: {current_delay:.1f}s)"
                        )
                    
                    return func(*args, **kwargs)
                    
                except exceptions as e:
                    last_exception = e
                    
                    if attempt == max_attempts:
                        logger.error(
                            f"Function {func.__name__} failed after {max_attempts} attempts: {e}"
                        )
                        raise
                    
                    if log_retries:
                        logger.debug(
                            f"Attempt {attempt}/{max_attempts} failed for {func.__name__}: {e}"
                        )
                    
                    time.sleep(current_delay)
                    current_delay *= backoff
            
            # This should never be reached, but just in case
            if last_exception:
                raise last_exception
            else:
                raise HellSuiteError(f"Function {func.__name__} failed unexpectedly")
        
        return wrapper
    return decorator

# ============================================================================
# VALIDATORS
# ============================================================================

def validate_url(url: str, require_scheme: bool = True) -> bool:
    """
    Validate URL format and accessibility
    
    Args:
        url: URL to validate
        require_scheme: Whether URL must have http:// or https://
    
    Returns:
        bool: True if valid, False otherwise
    
    Raises:
        ValidationError: If URL is invalid
    """
    try:
        # Basic URL parsing
        parsed = urlparse(url)
        
        if require_scheme and not parsed.scheme:
            raise ValidationError(f"URL must include scheme (http:// or https://): {url}")
        
        if not parsed.netloc:
            raise ValidationError(f"URL must include hostname: {url}")
        
        # Check if it's a valid domain/IP (basic check)
        if parsed.hostname:
            # Try to resolve hostname
            try:
                socket.gethostbyname(parsed.hostname)
            except socket.gaierror:
                raise ValidationError(f"Could not resolve hostname: {parsed.hostname}")
        
        # Check scheme
        if parsed.scheme not in ('http', 'https'):
            raise ValidationError(f"Unsupported scheme: {parsed.scheme}. Use http:// or https://")
        
        logger.debug(f"URL validation passed: {url}")
        return True
        
    except ValidationError:
        raise
    except Exception as e:
        raise ValidationError(f"URL validation error: {e}")

def validate_port(port: Union[int, str]) -> bool:
    """Validate port number"""
    try:
        port_int = int(port)
        if 1 <= port_int <= 65535:
            return True
        raise ValidationError(f"Port out of range (1-65535): {port}")
    except ValueError:
        raise ValidationError(f"Invalid port number: {port}")

def validate_severity(severity: str) -> bool:
    """Validate vulnerability severity"""
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    if severity.lower() not in valid_severities:
        raise ValidationError(f"Invalid severity: {severity}. Must be one of: {valid_severities}")
    return True

# ============================================================================
# CONTEXT MANAGERS
# ============================================================================

class DatabaseConnection:
    """
    Context manager for database connections with automatic cleanup
    and error handling
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection = None
        self.cursor = None
    
    def __enter__(self):
        try:
            import sqlite3
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
            logger.debug(f"Database connection established: {self.db_path}")
            return self.cursor
        except Exception as e:
            raise DatabaseError(f"Failed to connect to database: {e}")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.connection:
                if exc_type is None:
                    self.connection.commit()
                    logger.debug("Database transaction committed")
                else:
                    self.connection.rollback()
                    logger.warning("Database transaction rolled back due to error")
                
                self.connection.close()
                logger.debug("Database connection closed")
        except Exception as e:
            logger.error(f"Error closing database connection: {e}")
        finally:
            self.connection = None
            self.cursor = None

class TimingContext:
    """
    Context manager for timing operations and logging performance
    """
    def __init__(self, operation_name: str, log_level: str = "info"):
        self.operation_name = operation_name
        self.log_level = log_level
        self.start_time = None
    
    def __enter__(self):
        self.start_time = time.time()
        logger.debug(f"Starting operation: {self.operation_name}")
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.time() - self.start_time
        
        log_method = getattr(logger, self.log_level)
        log_method(f"Operation '{self.operation_name}' completed in {elapsed:.2f}s")
        
        # Log to metrics logger
        from config.logging_config import metrics_logger
        metrics_logger.info(
            f"operation_duration,name={self.operation_name},status={'success' if exc_type is None else 'failed'} "
            f"duration={elapsed:.3f}"
        )

# ============================================================================
# ERROR REPORTING UTILITIES
# ============================================================================

def log_error_with_context(error: Exception, context: dict = None):
    """
    Log an error with additional context information
    
    Args:
        error: The exception that was raised
        context: Additional context dict (e.g., {'target': url, 'module': 'scanner'})
    """
    error_details = {
        'error_type': type(error).__name__,
        'error_message': str(error),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    }
    
    if context:
        error_details.update(context)
    
    logger.error(f"Error occurred: {error_details}")
    
    # Log to error-specific log
    import json
    from config.logging_config import get_logger
    error_logger = get_logger('errors')
    error_logger.error(json.dumps(error_details, indent=2))

def safe_execute(func: Callable, *args, default_return=None, **kwargs):
    """
    Safely execute a function, returning default value on error
    
    Args:
        func: Function to execute
        default_return: Value to return if function fails
        *args, **kwargs: Arguments to pass to function
    
    Returns:
        Function result or default_return on error
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        log_error_with_context(e, {'function': func.__name__})
        return default_return

# ============================================================================
# INTEGRATION WITH EXISTING CODE
# ============================================================================

def setup_error_handling():
    """
    Setup global error handling (e.g., uncaught exception handler)
    """
    import sys
    
    def global_exception_handler(exc_type, exc_value, exc_traceback):
        # Don't capture KeyboardInterrupt (Ctrl+C)
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        logger.critical(
            "Uncaught exception",
            exc_info=(exc_type, exc_value, exc_traceback)
        )
        
        # Also log to errors.log
        from config.logging_config import get_logger
        error_logger = get_logger('errors')
        error_logger.critical(
            "Uncaught exception",
            exc_info=(exc_type, exc_value, exc_traceback)
        )
    
    sys.excepthook = global_exception_handler
    logger.info("Global error handling configured")