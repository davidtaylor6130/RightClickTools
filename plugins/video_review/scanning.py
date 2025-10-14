"""Directory scanning utilities for the Video Review & Log plugin."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, List, Optional

from .model import VideoItem

VIDEO_EXTENSIONS = {
    ".mp4", ".mov", ".m4v", ".avi", ".mkv", ".wmv", ".flv", ".webm",
    ".mts", ".m2ts", ".mpeg", ".mpg", ".3gp"
}
MIN_BYTES = 50 * 1024

ProgressCallback = Callable[[int, Optional[str]], None]
ShouldStop = Callable[[], bool]


def _format_rel_path(base: Path, file_path: Path) -> str:
    try:
        return str(file_path.relative_to(base))
    except Exception:
        return file_path.name


def scan_directory(
    directory: Path,
    progress: Optional[ProgressCallback] = None,
    should_stop: Optional[ShouldStop] = None,
) -> List[VideoItem]:
    """Scan ``directory`` for video files recursively."""

    directory = directory.resolve()
    items: List[VideoItem] = []
    index = 1
    stop = should_stop or (lambda: False)

    for root, _, files in os.walk(directory):
        if stop():
            break
        root_path = Path(root)
        for fname in files:
            if stop():
                break
            fpath = root_path / fname
            ext = fpath.suffix.lower()
            if ext not in VIDEO_EXTENSIONS:
                continue
            try:
                stat = fpath.stat()
            except OSError:
                continue
            if stat.st_size < MIN_BYTES:
                continue

            item = VideoItem(
                index=index,
                abs_path=str(fpath),
                rel_path=_format_rel_path(directory, fpath),
                filename=fpath.name,
                size_bytes=stat.st_size,
                mtime=stat.st_mtime,
                duration_seconds=None,
                status="pending",
                note="",
            )
            items.append(item)
            index += 1

            if progress:
                progress(len(items), item.rel_path)
        if progress:
            progress(len(items), None)

    return items
