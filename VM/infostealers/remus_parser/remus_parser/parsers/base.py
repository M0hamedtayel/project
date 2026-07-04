"""Abstract base parser for Remus file types."""

from __future__ import annotations

import gc
import logging
import os
import shutil
import subprocess
import threading
import zipfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Protocol

logger = logging.getLogger(__name__)


class RawLogData(Protocol):
    """Minimal interface for raw log content access."""

    def read_text(self, encoding: str = "utf-8") -> str: ...
    def read_bytes(self) -> bytes: ...
    @property
    def name(self) -> str: ...


class BaseParser(ABC):
    """Base class for all file-type parsers within a Remus log."""

    def __init__(self, log_dir: Path) -> None:
        self.log_dir = log_dir

    @abstractmethod
    def parse(self) -> dict[str, Any]:
        """Return parsed data as a dict ready for model validation."""

    def read_file(self, path: Path, encoding: str = "utf-8") -> str | None:
        """Read a text file, return None on failure."""
        try:
            return path.read_text(encoding=encoding)
        except Exception:
            logger.warning("Failed to read %s", path)
            return None

    def read_file_with_timeout(
        self, path: Path, timeout: float = 2.0, encoding: str = "utf-8",
    ) -> str | None:
        """Read a text file with a timeout to prevent hangs."""
        result: list[str | None] = [None]
        exception: list[Exception] = []

        def _read():
            try:
                result[0] = path.read_text(encoding=encoding)
            except Exception as e:
                exception.append(e)

        thread = threading.Thread(target=_read, daemon=True)
        thread.start()
        thread.join(timeout=timeout)

        if thread.is_alive():
            logger.warning("File read timed out after %.1fs: %s", timeout, path)
            return None

        if exception:
            logger.warning("Failed to read %s: %s", path, exception[0])
            return None

        return result[0]

    @staticmethod
    def safe_delete(path: Path) -> None:
        """Delete a directory tree, avoiding Windows file-lock hangs."""
        try:
            for item in path.rglob("*"):
                try:
                    item.chmod(0o777)
                except (AttributeError, OSError):
                    pass

            try:
                subprocess.run(
                    [
                        "robocopy", str(path), "NUL", "/MIR",
                        "/NFL", "/NDL", "/NJH", "/NJS", "/NDC", "/NEG",
                        "/R:0", "/W:0",
                    ],
                    timeout=10,
                    capture_output=True,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                pass

            shutil.rmtree(path, ignore_errors=True)

            gc.collect()
            try:
                os.sync()
            except AttributeError:
                pass
        except Exception:
            pass

    @staticmethod
    def extract_zip_to_temp(zip_path: Path, prefix: str = "remus_extract_") -> Path:
        """Extract a zip file to a temp directory and return the log dir."""
        import tempfile

        temp_dir = Path(tempfile.mkdtemp(prefix=prefix))

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(temp_dir)
        except Exception as e:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise ValueError(f"Failed to extract {zip_path}: {e}")

        # Find the directory containing Info.txt
        info_file = temp_dir / "Info.txt"
        if info_file.is_file():
            return temp_dir

        for child in sorted(temp_dir.iterdir()):
            if child.is_dir():
                nested_info = child / "Info.txt"
                if nested_info.is_file():
                    return child

        for child in sorted(temp_dir.iterdir()):
            if child.is_dir():
                return child

        shutil.rmtree(temp_dir, ignore_errors=True)
        raise FileNotFoundError(f"No log directory found in {zip_path}")
