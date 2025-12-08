# HellSuite Examples

This directory contains example scripts demonstrating how to use HellSuite's advanced features.

## FILES

basic_usage.py
Demonstrates the basic usage of HellSuite's logging, error handling, and decorator system.

Features shown:
- Logging configuration
- Retry decorator (@retry)
- Execution logging (@log_execution)
- Caching (@cached)
- Rate limiting (@rate_limit)
- Timing context manager

Run it:
python examples/basic_usage.py

scanning_example.py
Shows how to create robust scanning functions using composite decorators.

Features shown:
- @robust_scan composite decorator (timeout + retries + logging)
- Custom scanner implementation
- Error handling for scanning operations

Run it:
python examples/scanning_example.py

error_handling_example.py
Demonstrates the error handling system with practical examples.

Features shown:
- URL validation
- Safe execution with safe_execute()
- Custom exception classes
- Error logging with context

Run it:
python examples/error_handling_example.py

## QUICK START

1. Make sure you're in the hellSuite root directory:
cd /path/to/hellSuite

2. Run any example:
python examples/basic_usage.py

3. Check the logs:
- Output will appear in console
- Detailed logs in logs/ directory
- Metrics in logs/metrics.log

## REQUIREMENTS

- Python 3.8+
- HellSuite installed and configured
- Required packages: requests, flask, passlib (installed via HellSuite setup)

## USAGE PATTERNS

Basic Function with Logging:
from utils.decorators import log_execution

@log_execution(log_args=True, log_time=True)
def my_function(param1, param2):
    # Your code here
    pass

Function with Retry Logic:
from utils.error_handler import retry

@retry(max_attempts=3, delay=1.0)
def unreliable_operation():
    # Code that might fail
    pass

Rate-Limited API Calls:
from utils.decorators import rate_limit

@rate_limit(max_calls=5, period=1.0)
def api_request(url):
    # Make API call
    pass

## BEST PRACTICES

1. Always use @log_execution for important functions
2. Use @retry for network operations
3. Validate inputs with validate_url() and other validators
4. Use safe_execute() for operations that shouldn't crash the program
5. Check the logs in logs/ directory for debugging

## VIEWING LOGS

Logs are organized by module:
- logs/dashboard.log - Web interface logs
- logs/scanner.log - Scanner operations
- logs/orchestrate.log - Orchestrator operations
- logs/errors.log - Error-only logs
- logs/metrics.log - Performance metrics

## TROUBLESHOOTING

Import Errors
If you get ModuleNotFoundError, ensure you're running from the hellSuite root directory:
cd /path/to/hellSuite
python examples/basic_usage.py

Permission Errors
Ensure you have write permissions for the logs/ directory.

Database Errors
Make sure the database exists:
ls hellSsus/database/hellSsus.db

## NEXT STEPS

After understanding these examples, you can:
1. Create your own scanning modules
2. Extend the error handling system
3. Add custom decorators
4. Integrate with external tools

For more information, check the main HellSuite documentation.