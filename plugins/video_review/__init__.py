"""Video Review & Log plugin package."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Optional

import tkinter as tk

from .ui import VideoReviewFrame


class _ToolkitPlugin:
    key = "video_review"
    title = "Video Review & Log"
    description = "Review video files, approve/reject them, and export audit logs."

    def __init__(self) -> None:
        self._frame: Optional[VideoReviewFrame] = None

    def make_panel(self, master, context) -> tk.Frame:
        self._frame = VideoReviewFrame(master, app=context)
        return self._frame

    def start(self, _context, _targets, _argv) -> None:
        # No special startup behaviour required.
        return None

    def cleanup(self) -> None:
        if self._frame:
            self._frame.on_close()


PLUGIN = _ToolkitPlugin()


def register_plugin(app: Optional[object] = None, master: Optional[tk.Misc] = None):
    """Return a simple plugin descriptor for standalone usage."""
    if master is None:
        root = getattr(app, "root", None)
        if isinstance(root, tk.Misc):
            master = root
        else:
            master = tk.Tk()
    frame = VideoReviewFrame(master, app=app)
    plugin = SimpleNamespace(name="Video Review & Log", frame=frame, on_close=frame.on_close)
    return plugin


if __name__ == "__main__":  # pragma: no cover - manual harness
    root = tk.Tk()
    root.title("Video Review & Log – Standalone")
    root.geometry("1100x720")
    plugin = register_plugin(master=root)
    plugin.frame.pack(fill="both", expand=True)
    root.protocol("WM_DELETE_WINDOW", lambda: (plugin.on_close(), root.destroy()))
    root.mainloop()

# Packaging hint (PyInstaller):
#   pyinstaller --noconfirm --onefile --name "RightClickToolkit" main.py
# Ensure ``openpyxl`` is included in the bundle for this plugin.

__all__ = ["VideoReviewFrame", "register_plugin", "PLUGIN"]
