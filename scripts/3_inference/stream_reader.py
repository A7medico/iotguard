"""
scripts/3_inference/stream_reader.py
-----------------------------------------------------------------------------
IoTGuard Enterprise — O(1) Byte-Offset CSV Stream Tailer & Async SIEM Queue
Eliminates O(N^2) full-CSV re-reads in decision_loop.py and provides
non-blocking asynchronous CEF / RFC 5424 Syslog streaming.
-----------------------------------------------------------------------------
"""

from __future__ import annotations

import io
import os
import queue
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import pandas as pd

logger = logging.getLogger("iotguard.stream_reader")


class FastCSVStreamReader:
    """
    O(1) incremental CSV reader using OS file byte offsets.
    Reads only newly appended lines from data/features.csv without parsing
    historical rows.
    """

    def __init__(self, csv_path: Path | str, expected_features: Optional[List[str]] = None) -> None:
        self.csv_path = Path(csv_path)
        self.expected_features = list(expected_features) if expected_features else []
        self.columns: List[str] = []
        self.byte_offset: int = 0
        self.row_offset: int = 0
        self.last_inode: Optional[int] = None

    def read_new_rows(
        self, saved_row_offset: int = 0, saved_byte_offset: int = 0
    ) -> Tuple[pd.DataFrame, int, int]:
        """
        Read only newly appended rows since saved_byte_offset.

        Returns:
            (new_rows_df, updated_row_offset, updated_byte_offset)
        """
        if not self.csv_path.exists():
            return pd.DataFrame(), 0, 0

        try:
            stat = self.csv_path.stat()
        except OSError:
            return pd.DataFrame(), saved_row_offset, saved_byte_offset

        file_size = stat.st_size
        current_inode = getattr(stat, "st_ino", None)

        # Detect file truncation, shrinkage, or log rotation
        if (
            file_size < saved_byte_offset
            or (self.last_inode is not None and current_inode != self.last_inode)
            or (saved_row_offset == 0 and saved_byte_offset > 0)
        ):
            saved_byte_offset = 0
            saved_row_offset = 0
            self.columns = []

        self.last_inode = current_inode

        if file_size == 0 or file_size == saved_byte_offset:
            return pd.DataFrame(), saved_row_offset, saved_byte_offset

        with self.csv_path.open("rb") as f:
            # Always read header line if columns are not cached yet
            if not self.columns or saved_byte_offset == 0:
                header_line = f.readline().decode("utf-8", errors="replace").strip()
                if not header_line:
                    return pd.DataFrame(), 0, 0
                self.columns = [c.strip() for c in header_line.split(",")]
                if saved_byte_offset == 0:
                    saved_byte_offset = f.tell()

            # If recovering from a legacy state.json that only stored row_offset
            if saved_row_offset > 0 and saved_byte_offset <= (len(",".join(self.columns)) + 5):
                f.seek(0)
                try:
                    df_full = pd.read_csv(f)
                except Exception:
                    return pd.DataFrame(), saved_row_offset, saved_byte_offset
                new_byte_pos = f.tell()
                if saved_row_offset >= len(df_full):
                    return pd.DataFrame(), len(df_full), new_byte_pos
                batch = df_full.iloc[saved_row_offset:].copy()
                return batch, len(df_full), new_byte_pos

            # Fast O(1) seek to exact byte offset
            f.seek(saved_byte_offset)
            raw_chunk = f.read()
            new_byte_offset = f.tell()

        if not raw_chunk:
            return pd.DataFrame(), saved_row_offset, saved_byte_offset

        text_chunk = raw_chunk.decode("utf-8", errors="replace")
        # Ensure we only process complete newline-terminated lines
        if not text_chunk.endswith("\n"):
            last_nl = text_chunk.rfind("\n")
            if last_nl == -1:
                # Partial line write in progress; wait for next tick
                return pd.DataFrame(), saved_row_offset, saved_byte_offset
            complete_bytes = text_chunk[: last_nl + 1].encode("utf-8")
            new_byte_offset = saved_byte_offset + len(complete_bytes)
            text_chunk = text_chunk[: last_nl + 1]

        if not text_chunk.strip():
            return pd.DataFrame(), saved_row_offset, new_byte_offset

        try:
            df_new = pd.read_csv(io.StringIO(text_chunk), names=self.columns, header=None)
        except Exception:
            return pd.DataFrame(), saved_row_offset, saved_byte_offset

        df_new.index = range(saved_row_offset, saved_row_offset + len(df_new))
        new_row_offset = saved_row_offset + len(df_new)
        return df_new, new_row_offset, new_byte_offset


class AsyncSIEMDispatcher:
    """
    Non-blocking background worker that streams real-time CEF / RFC 5424 Syslog
    events to enterprise SIEMs (Splunk, Sentinel, QRadar) without slowing down
    the inference loop.
    """

    def __init__(self, max_queue: int = 2000) -> None:
        self.syslog_host = os.getenv("IOTGUARD_SYSLOG_HOST", "").strip()
        self.syslog_port = int(os.getenv("IOTGUARD_SYSLOG_PORT", "514"))
        self.syslog_proto = os.getenv("IOTGUARD_SYSLOG_PROTO", "udp").lower()
        self.enabled = bool(self.syslog_host)
        self._queue: queue.Queue[Dict[str, Any]] = queue.Queue(maxsize=max_queue)
        self._stop_event = threading.Event()
        self._worker: Optional[threading.Thread] = None

        if self.enabled:
            self._worker = threading.Thread(
                target=self._run_loop, name="iotguard-siem-worker", daemon=True
            )
            self._worker.start()

    def enqueue(self, event: Dict[str, Any]) -> bool:
        """
        Enqueue a security event for non-blocking SIEM transmission.
        Returns True if enqueued, False if dropped or disabled.
        """
        if not self.enabled:
            return False
        try:
            self._queue.put_nowait(event)
            return True
        except queue.Full:
            # Never block packet scoring if SIEM collector is unreachable or backlogged
            logger.warning("SIEM dispatch queue full, dropping event to maintain edge inference rate")
            return False

    def stop(self, timeout: float = 2.0) -> None:
        """Stop background worker cleanly."""
        self._stop_event.set()
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=timeout)

    def _run_loop(self) -> None:
        try:
            from siem_exporter import send_syslog
        except ImportError:
            try:
                import importlib
                _mod = importlib.import_module("scripts.4_response.siem_exporter")
                send_syslog = _mod.send_syslog
            except Exception:
                logger.error("Failed to import send_syslog from siem_exporter")
                return

        while not self._stop_event.is_set():
            try:
                evt = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                send_syslog(
                    evt,
                    host=self.syslog_host,
                    port=self.syslog_port,
                    protocol=self.syslog_proto,
                    payload_format="cef",
                )
            except Exception as e:
                logger.debug(f"SIEM transmission error: {e}")
            finally:
                self._queue.task_done()

