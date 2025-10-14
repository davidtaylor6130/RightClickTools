"""Data model for the Video Review & Log plugin."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Literal, Optional

StatusLiteral = Literal["pending", "approved", "rejected"]


@dataclass
class VideoItem:
    """Represents a discovered video file."""

    index: int
    abs_path: str
    rel_path: str
    filename: str
    size_bytes: int
    mtime: float
    duration_seconds: Optional[int]
    status: StatusLiteral
    note: str

    @property
    def path(self) -> Path:
        return Path(self.abs_path)


class VideoReviewStore:
    """In-memory store for :class:`VideoItem` entries."""

    def __init__(self) -> None:
        self._items: Dict[str, VideoItem] = {}
        self._order: List[str] = []
        self._sort_key: str = "index"
        self._sort_reverse: bool = False

    # ---------------------------- basic operations -------------------------
    def reset(self, items: Iterable[VideoItem]) -> None:
        self._items.clear()
        self._order.clear()
        for item in items:
            self._items[item.abs_path] = item
            self._order.append(item.abs_path)
        self._sort_key = "index"
        self._sort_reverse = False

    def items(self) -> List[VideoItem]:
        return [self._items[i] for i in self._order]

    def get(self, abs_path: str) -> Optional[VideoItem]:
        return self._items.get(abs_path)

    def values(self) -> Iterable[VideoItem]:
        return self._items.values()

    # ------------------------------- sorting -------------------------------
    def sorted_items(self) -> List[VideoItem]:
        key = self._sort_key
        reverse = self._sort_reverse

        def sort_key(item: VideoItem):
            if key == "filename":
                return item.filename.lower()
            if key == "rel_path":
                return item.rel_path.lower()
            if key == "duration":
                return item.duration_seconds or -1
            if key == "status":
                order = {"approved": 1, "rejected": 2, "pending": 3}
                return order.get(item.status, 99)
            if key == "notes":
                return item.note.lower()
            return item.index

        return sorted(self.values(), key=sort_key, reverse=reverse)

    def toggle_sort(self, key: str) -> None:
        if self._sort_key == key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False

        # Update order to the new sorted arrangement
        sorted_paths = [item.abs_path for item in self.sorted_items()]
        self._order = sorted_paths

    # ------------------------------- status --------------------------------
    def update_status(self, abs_path: str, status: StatusLiteral, note: str = "") -> Optional[VideoItem]:
        item = self._items.get(abs_path)
        if not item:
            return None
        item.status = status
        item.note = note if status == "rejected" else ""
        return item

    def update_note(self, abs_path: str, note: str) -> Optional[VideoItem]:
        item = self._items.get(abs_path)
        if not item:
            return None
        item.note = note
        return item

    # ------------------------------- counts --------------------------------
    def counts(self) -> Dict[str, int]:
        total = len(self._items)
        approved = sum(1 for i in self._items.values() if i.status == "approved")
        rejected = sum(1 for i in self._items.values() if i.status == "rejected")
        pending = total - approved - rejected
        return {
            "total": total,
            "approved": approved,
            "rejected": rejected,
            "pending": pending,
        }

    # ------------------------------- helpers -------------------------------
    @property
    def sort_state(self) -> tuple[str, bool]:
        return self._sort_key, self._sort_reverse

    def set_order(self, ordered_paths: List[str]) -> None:
        """Persist the order after a custom sort."""
        self._order = ordered_paths[:]
