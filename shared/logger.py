"""
Centralized logger for Argus.
Writes to console (colored) and rotating log file.
Handles Windows console encoding quirks (cp1252) by stripping non-encodable chars.
"""
from __future__ import annotations

import io
import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


# Force UTF-8 on Windows console if possible
if sys.platform == "win32":
    try:
        # Python 3.7+: reconfigure stdout to UTF-8 with replace fallback
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
    except Exception:
        # Wrap in TextIOWrapper as fallback
        try:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"
LOG_DIR.mkdir(exist_ok=True)


class SafeFormatter(logging.Formatter):
    """Formatter that replaces unencodable chars rather than crashing."""

    COLORS = {
        "DEBUG":    "\033[36m" if _HAS_COLOR else "",
        "INFO":     "\033[32m" if _HAS_COLOR else "",
        "WARNING":  "\033[33m" if _HAS_COLOR else "",
        "ERROR":    "\033[31m" if _HAS_COLOR else "",
        "CRITICAL": "\033[35m" if _HAS_COLOR else "",
    }
    RESET = "\033[0m" if _HAS_COLOR else ""

    def __init__(self, *args, colored: bool = True, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.colored = colored

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        if self.colored:
            color = self.COLORS.get(record.levelname, "")
            base = f"{color}{base}{self.RESET}"
        return base


class SafeStreamHandler(logging.StreamHandler):
    """StreamHandler that replaces unencodable chars instead of erroring."""

    def emit(self, record: logging.LogRecord) -> None:
        try:
            super().emit(record)
        except UnicodeEncodeError:
            try:
                msg = self.format(record)
                encoding = getattr(self.stream, "encoding", "ascii") or "ascii"
                safe = msg.encode(encoding, errors="replace").decode(encoding, errors="replace")
                self.stream.write(safe + self.terminator)
                self.flush()
            except Exception:
                self.handleError(record)


_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str = "argus", level: str = "INFO") -> logging.Logger:
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)
    logger.setLevel(level.upper())
    logger.propagate = False

    if logger.handlers:
        _loggers[name] = logger
        return logger

    # Console — uses SafeStreamHandler for encoding fallback
    console = SafeStreamHandler(sys.stdout)
    console.setFormatter(
        SafeFormatter("[%(asctime)s] %(levelname)-8s %(name)s :: %(message)s",
                      datefmt="%H:%M:%S", colored=True)
    )
    logger.addHandler(console)

    # File (rotating) — UTF-8, no color codes
    file_handler = RotatingFileHandler(
        LOG_DIR / "argus.log",
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setFormatter(
        SafeFormatter(
            "[%(asctime)s] %(levelname)-8s %(name)s :: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            colored=False,
        )
    )
    logger.addHandler(file_handler)

    _loggers[name] = logger
    return logger
