"""
Logging configuration for GlobalDetect.

Provides structured logging with rotation and proper formatting for production use.
"""

import logging
import sys
from pathlib import Path
from logging.handlers import RotatingFileHandler
from typing import Any


class StructuredFormatter(logging.Formatter):
    """Structured JSON-like formatter for easier log parsing."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with structured data."""
        # Add contextual information
        if not hasattr(record, 'module_name'):
            record.module_name = record.module
        if not hasattr(record, 'function_name'):
            record.function_name = record.funcName

        # Standard format with structured fields
        return super().format(record)


def setup_logging(
    level: str = "INFO",
    log_file: str | None = None,
    log_dir: str | None = None,
    max_bytes: int = 10485760,  # 10MB
    backup_count: int = 5,
    enable_console: bool = True,
    enable_file: bool = False,
) -> logging.Logger:
    """
    Set up logging for GlobalDetect.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Custom log file path (overrides log_dir)
        log_dir: Directory for log files (defaults to ~/.globaldetect/logs)
        max_bytes: Maximum log file size before rotation
        backup_count: Number of backup log files to keep
        enable_console: Enable console logging
        enable_file: Enable file logging

    Returns:
        Configured root logger
    """
    # Get root logger
    logger = logging.getLogger("globaldetect")
    logger.setLevel(getattr(logging, level.upper()))

    # Clear existing handlers
    logger.handlers.clear()

    # Create formatters
    console_fmt = logging.Formatter(
        fmt='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    file_fmt = StructuredFormatter(
        fmt='%(asctime)s | %(levelname)-8s | %(name)-20s | %(module_name)-15s | '
            '%(function_name)-20s | %(lineno)-4d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_fmt)
        logger.addHandler(console_handler)

    # File handler with rotation
    if enable_file:
        if log_file:
            log_path = Path(log_file)
        else:
            if log_dir:
                log_path = Path(log_dir) / "globaldetect.log"
            else:
                log_path = Path.home() / ".globaldetect" / "logs" / "globaldetect.log"

        # Create directory if it doesn't exist
        log_path.parent.mkdir(parents=True, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_fmt)
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.

    Args:
        name: Module name (e.g., 'globaldetect.services.ipinfo')

    Returns:
        Logger instance
    """
    return logging.getLogger(name)


# Convenience function for quick setup
def configure_logging(debug: bool = False, log_to_file: bool = False) -> None:
    """
    Quick logging configuration.

    Args:
        debug: Enable debug logging
        log_to_file: Enable file logging
    """
    level = "DEBUG" if debug else "INFO"
    setup_logging(
        level=level,
        enable_console=True,
        enable_file=log_to_file,
    )


# Error tracking helper
class ErrorTracker:
    """Track errors for monitoring and alerting."""

    def __init__(self):
        self.errors: dict[str, int] = {}
        self.logger = get_logger(__name__)

    def log_error(
        self,
        error_type: str,
        message: str,
        exception: Exception | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        """
        Log an error with tracking.

        Args:
            error_type: Type of error (e.g., 'api_timeout', 'connection_error')
            message: Error message
            exception: Exception object if available
            context: Additional context data
        """
        # Track error count
        self.errors[error_type] = self.errors.get(error_type, 0) + 1

        # Build log message
        log_msg = f"{error_type}: {message}"
        if context:
            log_msg += f" | Context: {context}"

        # Log with appropriate level
        if exception:
            self.logger.error(log_msg, exc_info=exception)
        else:
            self.logger.error(log_msg)

    def get_error_counts(self) -> dict[str, int]:
        """Get error counts by type."""
        return self.errors.copy()

    def reset_counts(self) -> None:
        """Reset error counters."""
        self.errors.clear()


# Global error tracker instance
_error_tracker = ErrorTracker()


def track_error(
    error_type: str,
    message: str,
    exception: Exception | None = None,
    context: dict[str, Any] | None = None,
) -> None:
    """Track an error globally."""
    _error_tracker.log_error(error_type, message, exception, context)


def get_error_stats() -> dict[str, int]:
    """Get global error statistics."""
    return _error_tracker.get_error_counts()
