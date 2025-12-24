#!/usr/bin/env python3
"""
HellSuite Basic Usage Examples
Demonstrates how to use the new logging and error handling features
"""
import os
import sys
import logging

# Add HellSuite to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import setup_application_logging, get_logger
from utils.error_handler import (
    retry, validate_url, DatabaseConnection, TimingContext,
    HellScannerError, NetworkError
)
from utils.decorators import (
    log_execution, cached, rate_limit, validate_target_url
)

# Setup logging
setup_application_logging()
logger = get_logger(__name__)

# Example 1: Basic logging
logger.info("=== HellSuite Usage Examples ===")

# Example 2: Using the retry decorator
@retry(max_attempts=3, delay=1.0)
def unreliable_operation():
    """Example function that might fail"""
    import random
    if random.random() < 0.7:  # 70% chance of failure
        raise Exception("Temporary failure")
    return "Success!"

# Example 3: Using log_execution decorator
@log_execution(log_args=True, log_time=True)
def process_target(target_url):
    """Example processing function"""
    logger.info(f"Processing target: {target_url}")
    
    # Validate URL
    try:
        validate_url(target_url)
        logger.info("URL validation passed")
    except Exception as e:
        logger.error(f"Invalid URL: {e}")
        return False
    
    # Simulate work
    import time
    time.sleep(0.5)
    
    return True

# Example 4: Using cached decorator
@cached(ttl=60)  # Cache for 60 seconds
def expensive_operation(data):
    """Expensive operation that benefits from caching"""
    logger.info(f"Performing expensive operation on: {data}")
    import time
    time.sleep(1)  # Simulate expensive computation
    return f"processed_{data}"

# Example 5: Using rate_limit decorator
@rate_limit(max_calls=5, period=1.0)  # 5 calls per second
def api_call(endpoint):
    """Rate-limited API call"""
    logger.debug(f"Calling API endpoint: {endpoint}")
    return f"response_from_{endpoint}"

# Example 6: Using TimingContext
def example_with_timing():
    """Example using timing context manager"""
    with TimingContext("example_operation", "info"):
        import time
        time.sleep(0.3)
        logger.info("Operation completed inside timing context")

# Example 7: Database connection with context manager
def example_database_operation():
    """Example using database connection context manager"""
    from config import DATABASE_PATH
    
    try:
        with DatabaseConnection(DATABASE_PATH) as cursor:
            cursor.execute("SELECT COUNT(*) FROM projects")
            count = cursor.fetchone()[0]
            logger.info(f"Found {count} projects in database")
    except Exception as e:
        logger.error(f"Database error: {e}")

def main():
    """Run all examples"""
    logger.info("Starting examples...")
    
    # Run examples
    try:
        # Example 1: Retry
        logger.info("\n1. Testing retry decorator:")
        for i in range(3):
            try:
                result = unreliable_operation()
                logger.info(f"  Attempt {i+1}: {result}")
                break
            except Exception as e:
                logger.warning(f"  Attempt {i+1} failed: {e}")
        
        # Example 2: Log execution
        logger.info("\n2. Testing log_execution decorator:")
        process_target("http://example.com")
        process_target("invalid-url")
        
        # Example 3: Caching
        logger.info("\n3. Testing caching decorator:")
        result1 = expensive_operation("test_data")
        logger.info(f"  First call: {result1}")
        result2 = expensive_operation("test_data")  # Should be cached
        logger.info(f"  Second call: {result2}")
        
        # Example 4: Rate limiting
        logger.info("\n4. Testing rate limiting:")
        for i in range(7):
            result = api_call(f"endpoint_{i}")
            logger.debug(f"  Call {i+1}: {result}")
        
        # Example 5: Timing context
        logger.info("\n5. Testing timing context:")
        example_with_timing()
        
        # Example 6: Database
        logger.info("\n6. Testing database operations:")
        example_database_operation()
        
        logger.info("\n=== All examples completed successfully ===")
        
    except KeyboardInterrupt:
        logger.warning("\nExamples interrupted by user")
    except Exception as e:
        logger.error(f"\nExample failed: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())