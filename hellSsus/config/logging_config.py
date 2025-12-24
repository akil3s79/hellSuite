"""
HellSuite Logging Configuration
Professional logging with rotation, levels, and security considerations
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from datetime import datetime

# Log directory
LOG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# Security-sensitive patterns (will be redacted from logs)
SENSITIVE_PATTERNS = [
    r'password=([^&\s]+)',
    r'api[_-]?key=([^&\s]+)', 
    r'token=([^&\s]+)',
    r'secret=([^&\s]+)',
    r'auth=([^&\s]+)',
    r'Authorization: (.+)',
    r'-----BEGIN PRIVATE KEY-----',
    r'-----BEGIN RSA PRIVATE KEY-----'
]

class SecureFormatter(logging.Formatter):
    """Formatter that redacts sensitive information"""
    
    def format(self, record):
        message = super().format(record)
        
        # Redact sensitive patterns
        import re
        for pattern in SENSITIVE_PATTERNS:
            try:
                # Attempt substitution with error handling
                compiled = re.compile(pattern, re.IGNORECASE)
                
                # Check if pattern has named or numbered groups
                if compiled.groups > 0:
                    # Has capture groups
                    message = compiled.sub(r'\1=[REDACTED]', message)
                else:
                    # No capture groups
                    message = compiled.sub('[REDACTED]', message)
                    
            except (re.error, IndexError) as e:
                # Fallback: simple string replacement
                if re.search(pattern, message, re.IGNORECASE):
                    message = message.replace(pattern, '[REDACTED]')
                continue
        
        return message

def get_logger(name, level=logging.INFO, log_to_file=True):
    """
    Get a configured logger instance
    
    Args:
        name: Logger name (usually __name__)
        level: Logging level
        log_to_file: Whether to log to file
    
    Returns:
        logging.Logger: Configured logger
    """
    logger = logging.getLogger(name)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    logger.setLevel(level)
    
    # Console handler (always)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Console format
    console_format = SecureFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler (if requested)
    if log_to_file:
        # Create log file name based on module name
        module_name = name.split('.')[-1]
        log_file = os.path.join(LOG_DIR, f"{module_name}.log")
        
        # Rotating file handler (max 10MB per file, keep 5 backups)
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(level)
        
        # File format (more detailed)
        file_format = SecureFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(pathname)s:%(lineno)d - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)
    
    return logger

def setup_application_logging():
    """Setup main application logging configuration"""
    
    # Main application log (rotates daily, keeps 180 days)
    app_log_file = os.path.join(LOG_DIR, "hellsuite.log")
    
    # Daily rotating handler (keeps 180 days of logs)
    app_handler = TimedRotatingFileHandler(
        app_log_file,
        when='midnight',
        interval=1,
        backupCount=180,  # 180 days retention
        encoding='utf-8'
    )
    
    app_format = SecureFormatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    app_handler.setFormatter(app_format)
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Clear any existing handlers
    root_logger.handlers.clear()
    
    # Add our handlers
    root_logger.addHandler(app_handler)
    
    # Error-only log
    error_log_file = os.path.join(LOG_DIR, "errors.log")
    error_handler = RotatingFileHandler(
        error_log_file,
        maxBytes=5*1024*1024,  # 5MB
        backupCount=3,
        encoding='utf-8'
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(app_format)
    root_logger.addHandler(error_handler)
    
    # Suppress noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("playwright").setLevel(logging.WARNING)
    
    return root_logger

# Log levels for different modules
LOG_LEVELS = {
    'dashboard': logging.INFO,
    'orchestrate': logging.DEBUG,
    'scanner': logging.DEBUG,
    'recon': logging.DEBUG,
    'fuzzer': logging.DEBUG,
    'adapter': logging.DEBUG,
    'database': logging.WARNING,
}

# Create loggers for main modules (can be imported directly)
dashboard_logger = get_logger('dashboard', log_to_file=True)
orchestrate_logger = get_logger('orchestrate', log_to_file=True)
scanner_logger = get_logger('scanner', log_to_file=True)
recon_logger = get_logger('recon', log_to_file=True)
fuzzer_logger = get_logger('fuzzer', log_to_file=True)
adapter_logger = get_logger('adapter', log_to_file=True)
database_logger = get_logger('database', log_to_file=True)

# Metrics logger (for performance tracking)
metrics_logger = get_logger('metrics')