"""Append-only audit trail: one JSON line per monitor event, one file per day."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any, Callable

log = logging.getLogger(__name__)

_FILE = re.compile(r"^audit-(\d{4}-\d{2}-\d{2})\.jsonl$")


class AuditLog:
    def __init__(self, directory: Path, enabled: Callable[[], bool], retention_days: Callable[[], int]) -> None:
        self.directory = directory
        self._enabled = enabled
        self._retention = retention_days
        self._lock = threading.Lock()
        self._pruned_on: date | None = None

    def _path(self, day: date) -> Path:
        return self.directory / f"audit-{day.isoformat()}.jsonl"

    def write(self, event: dict[str, Any]) -> None:
        if not self._enabled():
            return
        day = datetime.fromtimestamp(event.get("time", time.time())).date()
        line = json.dumps(event, default=str, ensure_ascii=False)
        with self._lock:
            try:
                self.directory.mkdir(parents=True, exist_ok=True)
                with open(self._path(day), "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError as e:
                log.error("Audit log write failed: %s", e)
                return
            if self._pruned_on != day:
                self._pruned_on = day
                self._prune(day)

    def _prune(self, today: date) -> None:
        keep = self._retention()
        if keep <= 0:
            return  # 0 = keep forever
        cutoff = today - timedelta(days=keep)
        for day in self.days():
            if date.fromisoformat(day) < cutoff:
                try:
                    self._path(date.fromisoformat(day)).unlink()
                except OSError:
                    pass

    def days(self) -> list[str]:
        if not self.directory.is_dir():
            return []
        return sorted((m.group(1) for p in self.directory.iterdir() if (m := _FILE.match(p.name))), reverse=True)

    def read(self, day: str, limit: int = 2000) -> list[dict[str, Any]]:
        try:
            path = self._path(date.fromisoformat(day))
        except ValueError:
            return []
        if not path.exists():
            return []
        events = []
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    continue
        return events[-limit:]
