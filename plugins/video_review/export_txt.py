"""Writing helpers for rejected video lists."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .model import VideoItem


def write_rejected_list(path: Path, items: Iterable[VideoItem]) -> None:
    path = Path(path)
    rejected = [item.rel_path for item in items if item.status == "rejected"]
    if not rejected:
        content = "# No rejected videos\n"
    else:
        rejected.sort()
        content = "\n".join(rejected) + "\n"
    path.write_text(content, encoding="utf-8")
