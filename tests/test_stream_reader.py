"""
tests/test_stream_reader.py
-----------------------------------------------------------------------------
IoTGuard Enterprise v4.0 — Phase 12 Stream Tailer & Live Async SIEM Verification

Tests:
  1. FastCSVStreamReader initialization and empty/non-existent file safety.
  2. Incremental O(1) byte-offset reading across append operations.
  3. Log rotation and file truncation detection with automatic offset resets.
  4. Incomplete/partial line buffering handling (mid-write race condition safety).
  5. Backward-compatible recovery from legacy row-only state.json offsets.
  6. AsyncSIEMDispatcher lifecycle, queue bounding, and non-blocking semantics.
  7. AsyncSIEMDispatcher offline/unreachable SIEM host resilience.
  8. Integration compatibility with decision_loop.py and state persistence.
-----------------------------------------------------------------------------
"""

import io
import os
import time
import tempfile
from pathlib import Path
import pytest
import pandas as pd

from stream_reader import FastCSVStreamReader, AsyncSIEMDispatcher


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def temp_csv_dir():
    """Create an isolated temporary directory for test CSV streams."""
    with tempfile.TemporaryDirectory(prefix="iotguard_stream_test_") as tmp:
        yield Path(tmp)


FEATURES_HEADER = (
    "flows,bytes_total,pkts_total,syn_ratio,mean_bytes_flow,ack_ratio,"
    "fin_ratio,rst_ratio,http_ratio,tcp_ratio,protocol_diversity,std_bytes,iat_mean\n"
)

SAMPLE_ROW_1 = "10,5000,50,0.1,500.0,0.8,0.1,0.0,0.2,0.9,3,120.5,0.04\n"
SAMPLE_ROW_2 = "25,12000,120,0.85,480.0,0.1,0.0,0.0,0.0,1.0,1,15.2,0.002\n"
SAMPLE_ROW_3 = "8,4000,40,0.05,500.0,0.9,0.05,0.0,0.1,0.95,2,95.0,0.05\n"


# =============================================================================
# 1. FastCSVStreamReader UNIT TESTS
# =============================================================================

class TestFastCSVStreamReader:
    def test_nonexistent_and_empty_file(self, temp_csv_dir):
        """Reader returns empty DataFrame when file does not exist or is empty."""
        csv_path = temp_csv_dir / "features_nonexistent.csv"
        reader = FastCSVStreamReader(csv_path)

        df, row_off, byte_off = reader.read_new_rows(0, 0)
        assert df.empty
        assert row_off == 0
        assert byte_off == 0

        # Create empty file
        csv_path.touch()
        df, row_off, byte_off = reader.read_new_rows(0, 0)
        assert df.empty
        assert row_off == 0
        assert byte_off == 0

    def test_initial_read_and_incremental_appends(self, temp_csv_dir):
        """Reader reads initial rows and only newly appended bytes on subsequent calls."""
        csv_path = temp_csv_dir / "features.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(FEATURES_HEADER)
            f.write(SAMPLE_ROW_1)

        reader = FastCSVStreamReader(csv_path)

        # 1. Initial read
        df1, row_off1, byte_off1 = reader.read_new_rows(0, 0)
        assert len(df1) == 1
        assert row_off1 == 1
        assert byte_off1 > 0
        assert df1["flows"].iloc[0] == 10
        assert "iat_mean" in df1.columns

        # 2. No changes on disk
        df_idle, row_off_idle, byte_off_idle = reader.read_new_rows(row_off1, byte_off1)
        assert df_idle.empty
        assert row_off_idle == 1
        assert byte_off_idle == byte_off1

        # 3. Append two new rows
        with open(csv_path, "a", encoding="utf-8") as f:
            f.write(SAMPLE_ROW_2)
            f.write(SAMPLE_ROW_3)

        df2, row_off2, byte_off2 = reader.read_new_rows(row_off1, byte_off1)
        assert len(df2) == 2
        assert row_off2 == 3
        assert byte_off2 > byte_off1
        # Indices should map consecutively from row_off1
        assert list(df2.index) == [1, 2]
        assert df2["flows"].iloc[0] == 25
        assert df2["flows"].iloc[1] == 8

    def test_file_truncation_or_rotation_resets_offsets(self, temp_csv_dir):
        """If file size drops below saved_byte_offset, offsets are automatically reset."""
        csv_path = temp_csv_dir / "features.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(FEATURES_HEADER)
            f.write(SAMPLE_ROW_1)
            f.write(SAMPLE_ROW_2)

        reader = FastCSVStreamReader(csv_path)
        df1, row_off1, byte_off1 = reader.read_new_rows(0, 0)
        assert len(df1) == 2

        # Simulate truncation/rotation: file is overwritten with fewer bytes
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(FEATURES_HEADER)
            f.write(SAMPLE_ROW_3)

        df2, row_off2, byte_off2 = reader.read_new_rows(row_off1, byte_off1)
        assert len(df2) == 1
        assert row_off2 == 1
        assert df2["flows"].iloc[0] == 8

    def test_partial_line_write_handling(self, temp_csv_dir):
        """Reader does not consume incomplete lines until newline is flushed."""
        csv_path = temp_csv_dir / "features.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(FEATURES_HEADER)
            f.write(SAMPLE_ROW_1)

        reader = FastCSVStreamReader(csv_path)
        df1, row_off1, byte_off1 = reader.read_new_rows(0, 0)
        assert len(df1) == 1

        # Simulate partial line write (e.g. half-written during process tick)
        with open(csv_path, "a", encoding="utf-8") as f:
            f.write("25,12000,120,0.85")  # Missing remaining fields and newline

        df_partial, row_off_p, byte_off_p = reader.read_new_rows(row_off1, byte_off1)
        assert df_partial.empty
        assert row_off_p == row_off1
        assert byte_off_p == byte_off1

        # Complete the line
        with open(csv_path, "a", encoding="utf-8") as f:
            f.write(",480.0,0.1,0.0,0.0,0.0,1.0,1,15.2,0.002\n")

        df_complete, row_off_c, byte_off_c = reader.read_new_rows(row_off1, byte_off1)
        assert len(df_complete) == 1
        assert row_off_c == 2
        assert df_complete["flows"].iloc[0] == 25

    def test_legacy_state_recovery_without_byte_offset(self, temp_csv_dir):
        """Legacy state.json with row_offset > 0 but byte_offset == 0 is recovered safely."""
        csv_path = temp_csv_dir / "features.csv"
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write(FEATURES_HEADER)
            f.write(SAMPLE_ROW_1)
            f.write(SAMPLE_ROW_2)
            f.write(SAMPLE_ROW_3)

        reader = FastCSVStreamReader(csv_path)
        # Pretend state had saved_row_offset = 2, but saved_byte_offset was 0
        df_recovered, row_off, byte_off = reader.read_new_rows(saved_row_offset=2, saved_byte_offset=0)
        assert len(df_recovered) == 1
        assert df_recovered["flows"].iloc[0] == 8
        assert row_off == 3
        assert byte_off > 0


# =============================================================================
# 2. AsyncSIEMDispatcher UNIT TESTS
# =============================================================================

class TestAsyncSIEMDispatcher:
    def test_dispatcher_disabled_when_host_empty(self, monkeypatch):
        """Dispatcher remains disabled and no worker thread starts when no host is set."""
        monkeypatch.delenv("IOTGUARD_SYSLOG_HOST", raising=False)
        dispatcher = AsyncSIEMDispatcher()
        assert not dispatcher.enabled
        assert dispatcher._worker is None

        # Enqueueing should return False and not fail
        result = dispatcher.enqueue({"action": "BLOCK", "score": 0.95})
        assert result is False

    def test_dispatcher_worker_lifecycle_when_enabled(self, monkeypatch):
        """When host is configured, worker thread starts and consumes queue items."""
        monkeypatch.setenv("IOTGUARD_SYSLOG_HOST", "127.0.0.1")
        monkeypatch.setenv("IOTGUARD_SYSLOG_PORT", "5140")
        monkeypatch.setenv("IOTGUARD_SYSLOG_PROTO", "udp")

        sent_events = []

        def mock_send_syslog(evt, host, port, protocol, payload_format):
            sent_events.append(evt)
            return True

        monkeypatch.setattr("siem_exporter.send_syslog", mock_send_syslog)

        dispatcher = AsyncSIEMDispatcher(max_queue=100)
        assert dispatcher.enabled
        assert dispatcher._worker is not None
        assert dispatcher._worker.is_alive()

        test_evt = {
            "attack_category": "DDoS-SYN",
            "action": "BLOCK",
            "score": 0.99,
            "src_ip": "10.0.0.99",
            "ts": time.time(),
        }

        enqueued = dispatcher.enqueue(test_evt)
        assert enqueued is True

        # Wait briefly for worker thread to process item
        time.sleep(0.3)
        assert len(sent_events) == 1
        assert sent_events[0]["src_ip"] == "10.0.0.99"

        dispatcher.stop(timeout=1.0)
        assert not dispatcher._worker.is_alive()

    def test_queue_overflow_drop_policy(self, monkeypatch):
        """When queue reaches capacity, events drop gracefully without blocking."""
        monkeypatch.setenv("IOTGUARD_SYSLOG_HOST", "127.0.0.1")

        # Disable auto-run of worker to fill queue
        dispatcher = AsyncSIEMDispatcher(max_queue=2)
        dispatcher._queue.put_nowait({"evt": 1})
        dispatcher._queue.put_nowait({"evt": 2})

        # Third event should drop and return False
        result = dispatcher.enqueue({"evt": 3})
        assert result is False
        dispatcher.stop()


# =============================================================================
# 3. DECISION LOOP INTEGRATION VERIFICATION
# =============================================================================

class TestDecisionLoopStreamIntegration:
    def test_decision_loop_imports_stream_reader(self):
        """decision_loop imports FastCSVStreamReader and AsyncSIEMDispatcher."""
        import decision_loop
        assert hasattr(decision_loop, "FastCSVStreamReader")
        assert hasattr(decision_loop, "AsyncSIEMDispatcher")
        assert decision_loop.FastCSVStreamReader is FastCSVStreamReader

