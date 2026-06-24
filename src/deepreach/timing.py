"""Lightweight scan instrumentation using stdlib only."""

from __future__ import annotations

import time
import tracemalloc
from types import TracebackType

from .models import ScanMetrics


class Timer:
    """Context manager that captures wall-clock time and peak RSS."""

    def __init__(self) -> None:
        self._t0 = 0.0
        self.metrics = ScanMetrics()

    def __enter__(self) -> Timer:
        tracemalloc.start()
        self._t0 = time.perf_counter()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        elapsed_ms = (time.perf_counter() - self._t0) * 1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        self.metrics = ScanMetrics(
            duration_ms=round(elapsed_ms, 2),
            peak_rss_bytes=peak,
        )
