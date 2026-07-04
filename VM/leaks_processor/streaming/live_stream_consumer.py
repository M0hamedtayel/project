"""
Live stream consumer — tails files or consumes message bus streams for
real-time record ingestion.

Two modes:
  1. **File Tail Mode** — Uses ``inotify_simple`` on Linux to watch a file
     being actively written to, yielding each new line as it appears.
  2. **Stream Source Mode** — Consumes from RabbitMQ stream queue (future-proofing).

Backpressure:
  - Internal deque buffer with maxlen = STREAM_BUFFER_SIZE
  - Flush triggers: buffer full OR time interval elapsed
  - Never drops records — blocks producer until buffer has space
"""

import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Generator

from config.settings import (
    STREAM_BUFFER_SIZE, STREAM_FLUSH_INTERVAL_SECS,
    ELASTICSEARCH_URL,
)

logger = logging.getLogger(__name__)


# ======================================================================
# File Tail Watcher (inotify-based)
# ======================================================================

class FileTailWatcher:
    """
    Watches a file for new content using inotify (Linux) and yields each
    new line as it is appended.

    Seeks to the end of the file on start to skip already-processed content.
    """

    def __init__(self, file_path: str, chunk_size: int = 8192):
        self.file_path = file_path
        self.chunk_size = chunk_size
        self._inotify = None
        self._watch_descriptor = None
        self._init_inotify()

    def _init_inotify(self):
        """Initialize inotify watcher (Linux only). Falls back to polling."""
        try:
            import inotify_simple
            self._inotify = inotify_simple.INotify()
            self._watch_descriptor = self._inotify.add_watch(
                os.path.dirname(self.file_path),
                inotify_simple.flags.MODIFY | inotify_simple.flags.CLOSE_WRITE,
            )
            logger.info("inotify watcher initialized for %s", self.file_path)
        except ImportError:
            logger.warning(
                "inotify_simple not available — falling back to polling for %s",
                self.file_path,
            )
            self._inotify = None
        except Exception as exc:
            logger.warning("inotify init failed: %s — using polling fallback", exc)
            self._inotify = None

    def tail(self) -> Generator[str, None, None]:
        """
        Generator: yields each new line appended to the file.

        Starts by seeking to the end (skips historical content).
        Blocks when no new data is available.
        """
        try:
            with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(0, 2)  # Seek to end — skip already-processed content
                logger.info("Tail mode started: %s (positioned at EOF)", self.file_path)

                while True:
                    line = f.readline()
                    if line:
                        yield line.rstrip("\n")
                    else:
                        # Wait for new data
                        if self._inotify:
                            # inotify mode — wait for MODIFY event
                            events = self._inotify.read(timeout=5000)
                            if not events:
                                continue
                            # Check for CLOSE_WRITE → stream ended
                            import inotify_simple
                            for event in events:
                                if event.mask & inotify_simple.flags.CLOSE_WRITE:
                                    # Check if the closed file is our target
                                    event_name = event.name if event.name else ""
                                    if event_name == os.path.basename(self.file_path):
                                        logger.info("File closed for writing: %s", self.file_path)
                                        return
                        else:
                            # Polling fallback — sleep and retry
                            time.sleep(0.5)

                    # Check if file still exists
                    if not os.path.exists(self.file_path):
                        logger.info("File removed: %s — stopping tail", self.file_path)
                        return

        except Exception as exc:
            logger.error("File tail error for %s: %s", self.file_path, exc)

    def close(self):
        """Clean up inotify resources."""
        if self._inotify:
            try:
                import inotify_simple
                if self._watch_descriptor is not None:
                    self._inotify.rm_watch(self._watch_descriptor)
                self._inotify.close()
            except Exception:
                pass


# ======================================================================
# Stream Consumer — orchestrates tail/normalizer/uploader pipeline
# ======================================================================

def consume_stream(
    file_path: str,
    breach_name: str,
    index_name: str,
    delimiter: str = ",",
    stream_uploader_callback: Callable = None,
    stream_normalizer_callback: Callable = None,
) -> dict:
    """
    Consume a live stream (file tail) and process each record through
    the normalizer and uploader pipelines.

    Args:
        file_path: Path to the file being actively written.
        breach_name: Breach source name.
        index_name: Target ES index.
        delimiter: CSV delimiter for parsing each line.
        stream_uploader_callback: Function to call with buffered records.
        stream_normalizer_callback: Function to call per raw line.

    Returns:
        Stats dict with records_processed, records_uploaded, errors.
    """
    from streaming.stream_uploader import StreamUploader
    from streaming.stream_normalizer import StreamNormalizer

    stats = {
        "records_processed": 0,
        "records_uploaded": 0,
        "records_failed": 0,
        "errors": 0,
        "start_time": datetime.now(timezone.utc).isoformat(),
    }

    # Initialize components
    uploader = StreamUploader(index_name)
    normalizer = StreamNormalizer(
        file_path=file_path,
        breach_name=breach_name,
        delimiter=delimiter,
    )

    # Override callbacks if provided
    if stream_uploader_callback:
        uploader.add_upload_callback(stream_uploader_callback)

    logger.info(
        "Live stream consumer started: %s → %s",
        file_path, index_name,
    )

    watcher = FileTailWatcher(file_path)

    try:
        for line in watcher.tail():
            if not line.strip():
                continue

            stats["records_processed"] += 1

            try:
                # Normalize the raw line
                doc = normalizer.normalize_line(line)

                if doc:
                    # Add to uploader buffer (uploader handles flushing)
                    uploader.add(doc)
                    stats["records_uploaded"] += 1
                else:
                    stats["errors"] += 1

            except Exception as exc:
                stats["errors"] += 1
                logger.warning(
                    "Stream record error (line %d): %s",
                    stats["records_processed"], exc,
                )

    except KeyboardInterrupt:
        logger.info("Stream consumer interrupted — final flush")
    finally:
        # Final flush
        uploader.flush()
        stats["records_uploaded"] = uploader.stats["total_uploaded"]
        stats["records_failed"] = uploader.stats["total_failed"]
        stats["end_time"] = datetime.now(timezone.utc).isoformat()
        watcher.close()
        logger.info("Stream consumer stopped: %s", stats)

    return stats


# ======================================================================
# RabbitMQ Stream Source Mode (future-proofing)
# ======================================================================

def consume_rabbitmq_stream(
    queue_name: str,
    breach_name: str,
    index_name: str,
) -> dict:
    """
    Consume records from a RabbitMQ stream queue.

    Each message is a single JSON record (one transaction row).
    Uses prefetch_count=1 for backpressure.

    On successful upload → ACK
    On failure → NACK with requeue
    """
    import pika
    import json

    from streaming.stream_uploader import StreamUploader
    from streaming.stream_normalizer import StreamNormalizer

    stats = {
        "records_processed": 0,
        "records_uploaded": 0,
        "records_failed": 0,
        "errors": 0,
    }

    uploader = StreamUploader(index_name)
    normalizer = StreamNormalizer(
        file_path=None,
        breach_name=breach_name,
        source="rabbitmq",
    )

    connection = pika.BlockingConnection(
        pika.URLParameters(f"amqp://guest:guest@localhost:5672/")
    )
    channel = connection.channel()
    channel.basic_qos(prefetch_count=1)

    def on_message(ch, method, properties, body):
        try:
            payload = json.loads(body)
            doc = normalizer.normalize_dict(payload)

            if doc:
                uploader.add(doc)
                stats["records_uploaded"] += 1

            ch.basic_ack(delivery_tag=method.delivery_tag)
            stats["records_processed"] += 1

        except Exception as exc:
            stats["errors"] += 1
            logger.warning("RabbitMQ stream error: %s — NACK requeue", exc)
            ch.basic_nack(delivery_tag=method.delivery_tag, requeue=True)

    channel.basic_consume(queue=queue_name, on_message_callback=on_message)

    try:
        logger.info("RabbitMQ stream consumer started on queue: %s", queue_name)
        channel.start_consuming()
    except KeyboardInterrupt:
        logger.info("RabbitMQ stream consumer interrupted — final flush")
        uploader.flush()
    finally:
        connection.close()

    stats["records_uploaded"] = uploader.stats["total_uploaded"]
    stats["records_failed"] = uploader.stats["total_failed"]
    return stats
