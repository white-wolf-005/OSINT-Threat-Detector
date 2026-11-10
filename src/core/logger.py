import logging
import sys
from pathlib import Path

BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
LOG_FILE_PATH: Path = BASE_DIR / "logs.txt"


class ImmediateFileHandler(logging.FileHandler):
    def __init__(self, filename: Path, mode: str = "w", encoding: str = "utf-8", delay: bool = False) -> None:
        super().__init__(filename, mode=mode, encoding=encoding, delay=delay)

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


_SHARED_FORMATTER: logging.Formatter = logging.Formatter(
    "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_SHARED_FILE_HANDLER: ImmediateFileHandler | None = None
_SHARED_CONSOLE_HANDLER: logging.StreamHandler | None = None


def _attach_shared_handlers(target_logger: logging.Logger) -> None:
    global _SHARED_FILE_HANDLER, _SHARED_CONSOLE_HANDLER

    if _SHARED_FILE_HANDLER is None:
        _SHARED_FILE_HANDLER = ImmediateFileHandler(
            LOG_FILE_PATH,
            mode="w",
            encoding="utf-8",
            delay=False,
        )
        _SHARED_FILE_HANDLER.setFormatter(_SHARED_FORMATTER)

    if _SHARED_CONSOLE_HANDLER is None:
        _SHARED_CONSOLE_HANDLER = logging.StreamHandler(sys.stdout)
        _SHARED_CONSOLE_HANDLER.setFormatter(_SHARED_FORMATTER)

    target_logger.handlers.clear()
    target_logger.addHandler(_SHARED_FILE_HANDLER)
    target_logger.addHandler(_SHARED_CONSOLE_HANDLER)
    target_logger.propagate = False


def setup_logger(name: str = "osint_analyzer") -> logging.Logger:
    logger: logging.Logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    _attach_shared_handlers(logger)

    for uvicorn_logger_name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        uv_logger: logging.Logger = logging.getLogger(uvicorn_logger_name)
        uv_logger.setLevel(logging.INFO)
        _attach_shared_handlers(uv_logger)

    return logger