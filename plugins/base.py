from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import List, Protocol, Optional, Any, Tuple


def _parse_standalone_argv(argv: List[str]) -> Tuple[List[Path], List[str], bool]:
    """Split CLI arguments into targets, passthrough extras and mode flags.

    The launcher historically accepts ``--target`` arguments as well as raw
    positional paths. To keep standalone builds familiar we mirror that
    behaviour here and additionally recognise ``--pro`` to immediately enable
    Pro mode when desired.
    """

    targets: List[Path] = []
    extra: List[str] = []
    pro_mode = False
    it = iter(argv)
    for arg in it:
        if arg == "--target":
            value = next(it, None)
            if value:
                targets.append(Path(value).expanduser())
        elif arg == "--action":
            # The full launcher uses --action to pick a tool. Standalone builds
            # only run a single tool, so the flag is effectively ignored but we
            # consume the following token to remain compatible with shortcuts.
            next(it, None)
        elif arg == "--pro":
            pro_mode = True
        elif arg.startswith("--"):
            extra.append(arg)
        else:
            targets.append(Path(arg).expanduser())
    return targets, extra, pro_mode

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


def run_plugin_standalone(plugin: "ToolPlugin", argv: Optional[List[str]] = None) -> None:
    """Launch a tool plugin in isolation with a minimal host window.

    This enables packaging individual tools (for example via PyInstaller)
    without bundling the entire multi-tool launcher. The helper mirrors the
    behaviour of :class:`rightclick_toolkit.ToolHostWindow` closely enough for
    every built-in plugin to function while keeping dependencies local.
    """

    import platform
    import sys

    try:
        import ttkbootstrap as tb
        from ttkbootstrap.dialogs import Messagebox
    except ImportError as exc:  # pragma: no cover - import error propagated
        raise RuntimeError(
            "Install dependencies: pip install ttkbootstrap send2trash"
        ) from exc

    argv = list(sys.argv[1:] if argv is None else argv)
    targets, extra, pro_mode = _parse_standalone_argv(argv)

    resource_root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    ctx = AppContext(
        app_name=getattr(plugin, "title", getattr(plugin, "key", "Tool")),
        version=getattr(plugin, "version", "standalone"),
        platform=platform.system(),
        resource_dir=resource_root,
        ui_mode="pro" if pro_mode else "standard",
    )

    window = tb.Window(title=f"{ctx.app_name} – Standalone", themename="darkly")
    window.geometry("1000x700")
    window.resizable(True, True)

    container = tb.Frame(window, padding=8)
    container.pack(fill="both", expand=True)

    panel = plugin.make_panel(container, ctx)
    if hasattr(panel, "pack"):
        panel.pack(fill="both", expand=True)

    def _start_tool():
        try:
            plugin.start(ctx, targets, extra)
            if hasattr(plugin, "on_mode_changed"):
                plugin.on_mode_changed(ctx.ui_mode)
        except Exception as exc:  # pragma: no cover - GUI error path
            Messagebox.show_error(message=str(exc), title="Tool start error")

    def _on_close():
        try:
            plugin.cleanup()
        except Exception:
            pass
        window.destroy()

    window.after(50, _start_tool)
    window.protocol("WM_DELETE_WINDOW", _on_close)
    window.mainloop()
