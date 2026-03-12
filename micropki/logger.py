"""
Logging configuration for MicroPKI
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class SensitiveDataFilter(logging.Filter):
    """Filter to prevent sensitive data from being logged"""

    def filter(self, record):
        # Ensure no passphrase-related content is logged
        message = record.getMessage().lower()
        sensitive_keywords = ['passphrase', 'password', 'secret', 'private key content']

        for keyword in sensitive_keywords:
            if keyword in message and 'file' not in message:
                record.msg = "[REDACTED: Sensitive data filtered]"
                return True
        return True


def setup_logger(log_file: Optional[Path] = None, level: int = logging.INFO) -> logging.Logger:
    """
    Configure and return a logger instance.

    Args:
        log_file: Optional path to log file. If None, logs to stderr.
        level: Logging level (default: INFO)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger('micropki')
    logger.setLevel(level)

    # Clear any existing handlers
    logger.handlers.clear()

    # Create formatter with timestamp
    formatter = logging.Formatter(
        fmt='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    # Add sensitive data filter
    sensitive_filter = SensitiveDataFilter()

    # Configure handler
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    handler.addFilter(sensitive_filter)
    logger.addHandler(handler)

    return logger