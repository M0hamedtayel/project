"""CLI entry point for the Lumma parser."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from lumma_parser.core.config import Config
from lumma_parser.core.engine import ParserEngine


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Lumma info stealer log parser",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m lumma_parser --input-dir ./lumma_logs\n"
            "  python -m lumma_parser --input-dir ./lumma_logs --output-dir ./lumma_results --workers 16\n"
        ),
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing Lumma logs (extracted dirs or zip files)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("lumma_results"),
        help="Output directory for JSONL files (default: ./lumma_results)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=0,
        help="Number of parallel workers (0 = auto-detect, default: 0)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="JSONL write buffer size (default: 100)",
    )
    parser.add_argument(
        "--progress-interval",
        type=int,
        default=500,
        help="Progress report every N records (default: 500)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level (default: INFO)",
    )

    args = parser.parse_args()

    # Validate input directory
    if not args.input_dir.is_dir():
        print(f"Error: Input directory does not exist: {args.input_dir}", file=sys.stderr)
        sys.exit(1)

    # Create config
    config = Config(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        max_workers=args.workers,
        batch_size=args.batch_size,
        progress_interval=args.progress_interval,
    )

    # Run engine
    engine = ParserEngine(config)
    summary = engine.run()

    # Print summary
    print("\n" + "=" * 60)
    print("PARSING SUMMARY")
    print("=" * 60)
    print(f"Total logs:      {summary['total']}")
    print(f"Successful:      {summary['success']}")
    print(f"Failed:          {summary['failed']}")
    print(f"Errors:          {summary['errors']}")
    print(f"Elapsed:         {summary['elapsed_seconds']}s")
    print(f"Rate:            {summary['records_per_second']} records/sec")
    print("=" * 60)

    if summary["failed"] > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
