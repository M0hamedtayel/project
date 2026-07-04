"""Main orchestration engine for batch processing Vidar logs."""

from __future__ import annotations

import json
import logging
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from vidar_parser.core.config import Config
from vidar_parser.core.logger import setup_logger
from vidar_parser.models import VictimRecord
from vidar_parser.parsers.base import BaseParser
from vidar_parser.parsers.vidar import VidarParser

logger = logging.getLogger(__name__)


class ParserEngine:
    """Batch processes Vidar logs using parallel execution."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = setup_logger(
            log_dir=config.output_dir / "logs",
        )

    def run(self) -> dict[str, Any]:
        """Execute the full parsing pipeline."""
        input_dir = self.config.input_dir
        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)

        self.logger.info("Scanning for Vidar logs in %s", input_dir)
        log_dirs = self._discover_logs(input_dir)
        total = len(log_dirs)
        self.logger.info("Found %d log(s) to process", total)

        if total == 0:
            return {"success": 0, "failed": 0, "errors": []}

        success = 0
        failed = 0
        errors: list[dict[str, str]] = []
        start_time = time.time()

        output_file = output_dir / "victims.jsonl"
        error_file = None
        if self.config.error_log_path:
            error_file = self.config.error_log_path
        else:
            error_file = output_dir / "errors.jsonl"

        # Bounded concurrency — max 4 workers to reduce Windows
        # filesystem contention. Each worker has a 5-minute timeout.
        max_workers = max(2, min(self.config.effective_workers, 4))

        with (
            ThreadPoolExecutor(max_workers=max_workers) as executor,
            open(output_file, "w", encoding="utf-8") as out_f,
            open(error_file, "w", encoding="utf-8") as err_f,
        ):
            futures = {
                executor.submit(self._process_single_log, log_dir, idx): idx
                for idx, log_dir in enumerate(log_dirs, 1)
            }

            for future in as_completed(futures):
                idx = futures[future]
                try:
                    result = future.result(timeout=300)
                except Exception as e:
                    failed += 1
                    error_entry = {
                        "index": idx,
                        "error": str(e),
                        "type": "timeout_or_error",
                    }
                    errors.append(error_entry)
                    err_f.write(json.dumps(error_entry, ensure_ascii=False) + "\n")
                    err_f.flush()
                    self.logger.error(
                        "Log #%d failed or timed out: %s", idx, e,
                    )
                    continue

                if result is None:
                    failed += 1
                    errors.append({"index": idx, "error": "Parsing returned None"})
                else:
                    record, source_file = result
                    out_f.write(record.to_jsonl_line() + "\n")
                    out_f.flush()
                    success += 1

                    if success % self.config.progress_interval == 0:
                        elapsed = time.time() - start_time
                        rate = success / elapsed if elapsed > 0 else 0
                        self.logger.info(
                            "Progress: %d/%d (%.1f records/sec)",
                            success, total, rate,
                        )

        elapsed = time.time() - start_time
        rate = success / elapsed if elapsed > 0 else 0

        summary = {
            "total": total,
            "success": success,
            "failed": failed,
            "errors": len(errors),
            "elapsed_seconds": round(elapsed, 2),
            "records_per_second": round(rate, 1),
        }

        self.logger.info(
            "Complete: %d/%d successful (%.1f records/sec, %.1fs)",
            success, total, rate, elapsed,
        )

        return summary

    def _discover_logs(self, input_dir: Path) -> list[Path]:
        """Discover log directories in the input directory."""
        log_dirs: list[Path] = []

        for item in sorted(input_dir.iterdir()):
            if item.is_dir() and item.name.startswith("vidar_"):
                if (item / "information.txt").is_file():
                    log_dirs.append(item)

        for zip_file in sorted(input_dir.glob("vidar_*.zip")):
            log_dirs.append(zip_file)

        return log_dirs

    def _process_single_log(
        self, log_source: Path, index: int,
    ) -> tuple[VictimRecord, str] | None:
        """Process a single log (directory or zip file)."""
        temp_dir: Path | None = None

        try:
            if log_source.is_dir():
                log_dir = log_source
                source_file = log_source.name
            elif log_source.is_file() and log_source.suffix == ".zip":
                temp_dir = self._extract_log(log_source)
                log_dir = temp_dir
                source_file = log_source.stem
            else:
                return None

            # Parse the log
            parser = VidarParser(log_dir, source_file=source_file)
            record = parser.parse()

            # Clean up extracted temp dir
            if temp_dir is not None:
                BaseParser.safe_delete(temp_dir)
                temp_dir = None

            return (record, source_file)

        except Exception as e:
            logger.error("Failed to process #%d %s: %s", index, log_source, e)
            if temp_dir is not None:
                BaseParser.safe_delete(temp_dir)
            return None

    @staticmethod
    def _extract_log(zip_path: Path) -> Path:
        """Extract a zip file to a temp directory and return the log dir."""
        return BaseParser.extract_zip_to_temp(zip_path)
