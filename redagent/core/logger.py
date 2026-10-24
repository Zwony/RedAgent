"""Unified logging utility with fallback to standard library logging."""
import logging
import sys

try:
    import structlog
    def get_logger(name: str):
        return structlog.get_logger(name)
except ImportError:
    # Standard library fallback
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    class StdLoggerWrapper:
        def __init__(self, logger: logging.Logger):
            self._logger = logger

        def info(self, msg: str, **kwargs):
            extra = f" | {kwargs}" if kwargs else ""
            self._logger.info(f"{msg}{extra}")

        def warning(self, msg: str, **kwargs):
            extra = f" | {kwargs}" if kwargs else ""
            self._logger.warning(f"{msg}{extra}")

        def error(self, msg: str, **kwargs):
            extra = f" | {kwargs}" if kwargs else ""
            self._logger.error(f"{msg}{extra}")

        def debug(self, msg: str, **kwargs):
            extra = f" | {kwargs}" if kwargs else ""
            self._logger.debug(f"{msg}{extra}")

    def get_logger(name: str):
        return StdLoggerWrapper(logging.getLogger(name))
