"""In-memory sliding-window tracking for repeated suspicious requests."""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass
from threading import Lock
from typing import Callable

from .models import RuleFinding


DEFAULT_FREQUENCY_WINDOW_SECONDS = 60
DEFAULT_FREQUENCY_LIMIT = 5


@dataclass(frozen=True, slots=True)
class FrequencyDecision:
    """Observed suspicious-request count for one logical client and route."""

    count: int
    limit: int
    window_seconds: int
    exceeded: bool


class RequestFrequencyTracker:
    """Track suspicious requests in a bounded, thread-safe time window."""

    def __init__(
        self,
        *,
        window_seconds: int = DEFAULT_FREQUENCY_WINDOW_SECONDS,
        limit: int = DEFAULT_FREQUENCY_LIMIT,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if limit <= 0:
            raise ValueError("limit must be positive")

        self.window_seconds = window_seconds
        self.limit = limit
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = Lock()

    def record(self, key: str) -> FrequencyDecision:
        """Record one suspicious request and return its window decision."""

        now = self._clock()
        cutoff = now - self.window_seconds

        with self._lock:
            events = self._events.setdefault(key, deque(maxlen=self.limit))
            while events and events[0] <= cutoff:
                events.popleft()
            events.append(now)

            for stale_key, stale_events in tuple(self._events.items()):
                if not stale_events or stale_events[-1] <= cutoff:
                    del self._events[stale_key]

            count = len(events)
            return FrequencyDecision(
                count=count,
                limit=self.limit,
                window_seconds=self.window_seconds,
                exceeded=count >= self.limit,
            )

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


def build_frequency_finding(decision: FrequencyDecision) -> RuleFinding:
    """Create a sanitized finding when the suspicious-request limit is reached."""

    return RuleFinding(
        rule_code="REQUEST_FREQUENCY",
        rule_name="请求频率异常",
        category="frequency",
        parameter_name="request",
        parameter_path="request",
        message="短时间内的可疑请求次数超过阈值",
        evidence=(
            f"{decision.window_seconds} 秒窗口内达到 "
            f"{decision.limit} 次可疑请求"
        ),
    )
