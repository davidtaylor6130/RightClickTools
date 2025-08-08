from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List, Protocol, Optional, Any

class ToolPlugin(Protocol):
    key: str
    title: str
    description: str

    def make_panel(self, master, context: "AppContext") -> Any:
        """Build and return a GUI panel for this tool."""

    def start(self, context: "AppContext", targets: List[Path], argv: List[str]) -> None:
        """Invoked on app start with any CLI targets."""

    def cleanup(self) -> None:
        """Called on shutdown."""

    # Optional, but recommended for mode-aware tools
    def on_mode_changed(self, ui_mode: str) -> None:
        """Called when the launcher switches between 'standard' and 'pro'."""

@dataclass
class AppContext:
    app_name: str
    version: str
    platform: str
    resource_dir: Path
    ui_mode: str = "standard"  # 'standard' or 'pro'