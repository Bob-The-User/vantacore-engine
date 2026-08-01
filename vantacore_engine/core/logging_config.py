"""Logging configuration and JSON Lines file logging handler for VantaCore Engine."""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Union
from rich.logging import RichHandler


class JSONLinesFileHandler(logging.FileHandler):
    """Logging FileHandler that formats log records as JSON Lines."""

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record formatted as a JSON line.

        Args:
            record: Standard Python logging LogRecord.

        """
        try:
            self.format(record)
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "name": record.name,
                "message": record.getMessage(),
            }
            if record.exc_text:
                entry["exc_info"] = record.exc_text

            msg = json.dumps(entry) + "\n"
            if self.stream is not None:
                self.stream.write(msg)
                self.flush()
        except Exception:
            self.handleError(record)


def configure_logging(log_path: Union[str, Path], debug: bool = False) -> None:
    """Configure root logger with Rich console handler and JSON Lines file handler.

    Args:
        log_path: File path for JSON Lines log output.
        debug: If True, set console logging to DEBUG level; otherwise INFO level.

    """
    logger = logging.getLogger()
    if logger.handlers:
        return

    logger.setLevel(logging.DEBUG)

    console_handler = RichHandler(
        level=logging.DEBUG if debug else logging.INFO,
        rich_tracebacks=True,
        show_path=False,
    )
    logger.addHandler(console_handler)

    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    file_handler = JSONLinesFileHandler(str(path))
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
