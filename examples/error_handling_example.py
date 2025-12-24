#!/usr/bin/env python3
"""
HellSuite Error Handling Examples
Demonstrates the error handling system
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.logging_config import setup_application_logging, get_logger
from utils.error_handler import (
    HellScannerError, NetworkError, ValidationError,
    DatabaseError, safe_execute, log_error_with_context
)

setup_application_logging()
logger = get_logger(__name__)

def example_validation():
    """Example of validation errors"""
    logger.info("1. Testing validation errors:")
    
    from utils.error_handler import validate_url
    
    test_urls = [
        "http://valid-url.com",
        "invalid-url",
        "ftp://invalid-scheme.com",
        "http://",
        "https://valid-https.com/path"
    ]
    
    for url in test_urls:
        try:
            validate_url(url)
            logger.info(f"  ✓ {url} - VALID")
        except ValidationError as e:
            logger.error(f"  ✗ {url} - INVALID: {e}")

def example_safe_execute():
    """Example of safe execution"""
    logger.info("\n2. Testing safe_execute:")
    
    def risky_function(should_fail=True):
        if should_fail:
            raise Exception("This function failed as expected")
        return "Success"
    
    # This will fail but not crash the program
    result = safe_execute(risky_function, True, default_return="Default value")
    logger.info(f"  Result when failed: {result}")
    
    # This will succeed
    result = safe_execute(risky_function, False, default_return="Default value")
    logger.info(f"  Result when succeeded: {result}")

def example_custom_exceptions():
    """Example of custom exceptions"""
    logger.info("\n3. Testing custom exceptions:")
    
    try:
        raise HellScannerError(
            "Simulated scanner error",
            module="example_scanner"
        )
    except HellScannerError as e:
        logger.error(f"  Caught HellScannerError: {e}")
    
    try:
        raise NetworkError(
            "Connection refused",
            module="http_client"
        )
    except NetworkError as e:
        logger.error(f"  Caught NetworkError: {e}")

def example_error_logging():
    """Example of error logging with context"""
    logger.info("\n4. Testing error logging with context:")
    
    def operation_with_context():
        try:
            # Simulate an error
            raise ValueError("Example value error")
        except Exception as e:
            # Log with context
            log_error_with_context(e, {
                'operation': 'data_processing',
                'user_id': 123,
                'data_size': 1024
            })
            raise
    
    try:
        operation_with_context()
    except:
        logger.info("  Error was logged with context (check logs folder)")

def main():
    """Run all error handling examples"""
    logger.info("=== HellSuite Error Handling Examples ===")
    
    try:
        example_validation()
        example_safe_execute()
        example_custom_exceptions()
        example_error_logging()
        
        logger.info("\n=== Error handling examples completed successfully ===")
        return 0
        
    except Exception as e:
        logger.critical(f"Examples failed: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())