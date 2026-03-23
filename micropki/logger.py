"""Logging configuration for MicroPKI."""

import logging
import sys
from pathlib import Path
from typing import Optional


class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        message = record.getMessage().lower()
        sensitive_keywords = ['passphrase', 'password', 'secret', 'private key content']
        for keyword in sensitive_keywords:
            if keyword in message and 'file' not in message:
                record.msg = "[REDACTED: Sensitive data filtered]"
                return True
        return True


def setup_logger(log_file: Optional[Path] = None, level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger('micropki')
    logger.setLevel(level)
    logger.handlers.clear()

    formatter = logging.Formatter(
        fmt='%(asctime)s.%(msecs)03d [%(levelname)s] %(message)s',
        datefmt='%Y-%m-%dT%H:%M:%S'
    )

    sensitive_filter = SensitiveDataFilter()

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    handler.addFilter(sensitive_filter)
    logger.addHandler(handler)

    return logger