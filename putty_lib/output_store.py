"""Keeps the full text of long tool output so the AI can read it in parts.

Output sent to the AI is capped (max_output_chars). When a result is cut,
its full text is stored here under an id; output_read pages through it or
searches it.
"""

from __future__ import annotations

import itertools
import re
import threading
from collections import OrderedDict
from typing import Any

MAX_ITEMS = 30
MAX_CHARS_PER_ITEM = 5_000_000


class OutputStore:
    def __init__(self, max_items: int = MAX_ITEMS) -> None:
        self._items: OrderedDict[str, tuple[str, str]] = OrderedDict()
        self._ids = itertools.count(1)
        self._lock = threading.Lock()
        self._max_items = max_items

    def put(self, text: str, label: str) -> str:
        with self._lock:
            output_id = f"o{next(self._ids)}"
            self._items[output_id] = (text[:MAX_CHARS_PER_ITEM], label)
            while len(self._items) > self._max_items:
                self._items.popitem(last=False)
            return output_id

    def get(self, output_id: str) -> tuple[str, str]:
        with self._lock:
            if output_id not in self._items:
                known = ", ".join(self._items) or "none"
                raise KeyError(f"Output '{output_id}' not found (kept: {known}). Only the last "
                               f"{self._max_items} long outputs of this server process are kept.")
            return self._items[output_id]


def read_slice(text: str, offset: int, length: int) -> dict[str, Any]:
    offset = max(0, min(offset, len(text)))
    end = min(len(text), offset + length)
    return {"offset": offset, "end": end, "total_chars": len(text), "more": end < len(text),
            "text": text[offset:end]}


def grep(text: str, pattern: str, context_lines: int, max_matches: int, max_chars: int) -> dict[str, Any]:
    """Matching lines with context, numbered from 1, plus their character offsets."""
    regex = re.compile(pattern, re.I)
    lines = text.splitlines(keepends=True)
    starts = list(itertools.accumulate((len(line) for line in lines), initial=0))
    hits = [i for i, line in enumerate(lines) if regex.search(line)]
    blocks: list[dict[str, Any]] = []
    used = 0
    for i in hits[:max_matches]:
        lo, hi = max(0, i - context_lines), min(len(lines), i + context_lines + 1)
        snippet = "".join(f"{n + 1:>6}: {lines[n]}" for n in range(lo, hi))
        if used + len(snippet) > max_chars:
            break
        used += len(snippet)
        blocks.append({"line": i + 1, "offset": starts[i], "text": snippet})
    return {"pattern": pattern, "total_lines": len(lines), "total_chars": len(text),
            "matches": len(hits), "shown": len(blocks), "results": blocks}
