from __future__ import annotations
import sys, os
from pathlib import Path
from typing import List, Dict, Optional
import platform

# GUI
try:
    import ttkbootstrap as tb
    from ttkbootstrap.dialogs import Messagebox
except ImportError:
    print("Install deps: pip install ttkbootstrap send2trash pyinstaller")
    sys.exit(1)

from plugins.base import AppContext
from plugins import discover_plugins

APP_NAME = "RightClickToolkit"
VERSION = "2.0.0"

def parse_cli(argv: List[str]):
    action: Optional[str] = None
    extra: List[str] = []
    targets: List[Path] = []
    it = iter(argv)
    for a in it:
        if a == "--action":
            action = next(it, None)
        elif a == "--target":
            v = next(it, None)
            if v: targets.append(Path(v))
        elif a.startswith("-"):
            extra.append(a)
        else:
            targets.append(Path(a))
    targets = [t.resolve() for t in targets if str(t).strip()]
    return action, targets, extra

class MainWindow(tb.Window):
    def __init__(self, plugins: Dict[str, object], default_action: Optional[str], targets: List[Path], extra: List[str]):
        super().__init__(title=f"{APP_NAME} {VERSION}", themename="darkly")
        self.geometry("1060x720")
        self.resizable(True, True)

        self.plugins = plugins
        self.targets = targets
        self.extra = extra

        resource_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
        self.ctx = AppContext(app_name=APP_NAME, version=VERSION, platform=platform.system(), resource_dir=resource_dir)

        top = tb.Frame(self, padding=10)
        top.pack(fill="x")
        tb.Label(top, text="Tool:").pack(side="left")
        self.tool_var = tb.StringVar(value=default_action or (list(plugins)[0] if plugins else ""))
        self.tool_combo = tb.Combobox(top, textvariable=self.tool_var, values=list(plugins), state="readonly")
        self.tool_combo.pack(side="left", padx=6)
        self.tool_combo.bind("<<ComboboxSelected>>", lambda e: self._switch())

        self.content = tb.Frame(self, padding=8)
        self.content.pack(fill="both", expand=True)

        self.current_plugin = None
        self._switch()

        if default_action and default_action in plugins:
            try:
                plugins[default_action].start(self.ctx, self.targets, self.extra)
            except Exception as e:
                Messagebox.show_error(message=str(e), title="Startup error")

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _switch(self):
        for w in self.content.winfo_children(): w.destroy()
        key = self.tool_var.get()
        self.current_plugin = self.plugins.get(key)
        if not self.current_plugin:
            tb.Label(self.content, text=f"Unknown tool: {key}", bootstyle="danger").pack(pady=40)
            return
        panel = self.current_plugin.make_panel(self.content, self.ctx)
        if hasattr(panel, "pack"):
            panel.pack(fill="both", expand=True)

    def _on_close(self):
        for p in self.plugins.values():
            try: p.cleanup()
            except Exception: pass
        self.destroy()

def main():
    action, targets, extra = parse_cli(sys.argv[1:])
    base = Path(__file__).parent
    plugins = discover_plugins(base)
    if not plugins:
        print("No plugins discovered in tools/.")
        sys.exit(2)
    app = MainWindow(plugins, action, targets, extra)
    app.mainloop()

if __name__ == "__main__":
    main()