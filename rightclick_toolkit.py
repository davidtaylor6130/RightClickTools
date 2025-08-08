from __future__ import annotations
import sys, os
from pathlib import Path
from typing import List, Dict, Optional
import platform
import tkinter as tk
from tkinter.scrolledtext import ScrolledText as TkScrolledText

# GUI
try:
    import ttkbootstrap as tb
    from ttkbootstrap.dialogs import Messagebox
    # macOS/Tk PNG icon quirk workaround: swap to a tiny GIF if needed
    try:
        import ttkbootstrap.window as tb_window
        tb_window.Icon.icon = ("R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==")  # 1x1 GIF (base64)
    except Exception:
        pass
except ImportError:
    print("Install deps: pip install ttkbootstrap send2trash pyinstaller")
    sys.exit(1)

from plugins.base import AppContext
from plugins import discover_plugins

APP_NAME = "RightClickToolkit"
VERSION = "2.2.0"

# ----------------- CLI -----------------
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
            if v:
                targets.append(Path(v))
        elif a.startswith("-"):
            extra.append(a)
        else:
            targets.append(Path(a))
    targets = [t.resolve() for t in targets if str(t).strip()]
    return action, targets, extra

# ----------------- Tool Host Window -----------------
class ToolHostWindow(tb.Toplevel):
    """Hosts a single tool's GUI panel in its own window and runs its lifecycle."""
    def __init__(self, master, plugin, ctx: AppContext, targets: List[Path], extra: List[str]):
        super().__init__(master=master)
        self.plugin = plugin
        self.ctx = ctx
        self.targets = targets
        self.extra = extra

        self.title(f"{APP_NAME} – {getattr(plugin, 'title', getattr(plugin, 'key', 'Tool'))}")
        self.geometry("1000x700")
        self.resizable(True, True)

        container = tb.Frame(self, padding=8)
        container.pack(fill="both", expand=True)

        # Build tool UI
        panel = self.plugin.make_panel(container, self.ctx)
        if hasattr(panel, "pack"):
            panel.pack(fill="both", expand=True)

        # Start after the panel exists
        self.after(50, self._start_tool)

        # Ensure cleanup
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _start_tool(self):
        try:
            self.plugin.start(self.ctx, self.targets, self.extra)
            # Immediately let the tool know which mode we're in (for fresh windows)
            if hasattr(self.plugin, "on_mode_changed"):
                self.plugin.on_mode_changed(self.ctx.ui_mode)
        except Exception as e:
            Messagebox.show_error(message=str(e), title="Tool start error")

    def _on_close(self):
        try:
            self.plugin.cleanup()
        except Exception:
            pass
        self.destroy()

# ----------------- Main Window (Launcher) -----------------
class MainWindow(tb.Window):
    def __init__(self, plugins: Dict[str, object], default_action: Optional[str],
                 targets: List[Path], extra: List[str]):
        super().__init__(title=f"{APP_NAME} {VERSION}", themename="darkly")
        self.geometry("1100x760")
        self.resizable(True, True)

        self.plugins = plugins                    # key -> plugin singleton
        self.targets_from_cli = targets[:]        # initial targets from context menu
        self.extra_from_cli = extra[:]            # extra args for the tool
        self.open_windows: Dict[str, ToolHostWindow] = {}

        # Context for tools (PyInstaller-friendly resource dir)
        resource_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))
        self.ctx = AppContext(
            app_name=APP_NAME,
            version=VERSION,
            platform=platform.system(),
            resource_dir=resource_dir,
            ui_mode="standard"
        )

        # ---- Top bar (branding + actions) ----
        top = tb.Frame(self, padding=10); top.pack(fill="x")
        tb.Label(top, text=f"{APP_NAME}", font="-size 16 -weight bold").pack(side="left")
        tb.Label(top, text=f"v{VERSION}", bootstyle="secondary").pack(side="left", padx=(8, 12))

        # Mode toggle
        self.pro_var = tk.BooleanVar(value=False)
        tb.Checkbutton(top, text="Pro mode", variable=self.pro_var, command=self._apply_mode,
                       bootstyle="round-toggle").pack(side="left")
        tb.Button(top, text="Refresh", command=self._refresh_tools, bootstyle="secondary").pack(side="right", padx=6)
        tb.Button(top, text="About", command=self._about, bootstyle="info").pack(side="right")

        # ---- Main split: left list (tools), right details/targets ----
        self.main_split = tb.Panedwindow(self, orient="horizontal")
        self.main_split.pack(fill="both", expand=True, padx=10, pady=(0,10))

        # Left: Tools list + search
        self.left = tb.LabelFrame(self.main_split, text="Available Tools", padding=8)
        search_row = tb.Frame(self.left); search_row.pack(fill="x", pady=(0,6))
        tb.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = tb.Entry(search_row, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=6)
        search_entry.bind("<KeyRelease>", lambda e: self._filter_tools())

        self.tools_tv = tb.Treeview(self.left, columns=("title","desc"), show="headings", height=20)
        self.tools_tv.heading("title", text="Tool")
        self.tools_tv.heading("desc", text="Description")
        self.tools_tv.column("title", width=220, anchor="w")
        self.tools_tv.column("desc", width=380, anchor="w")
        self.tools_tv.pack(fill="both", expand=True)
        self.tools_tv.bind("<<TreeviewSelect>>", lambda e: self._update_details())
        self.tools_tv.bind("<Double-1>", lambda e: self._open_selected_tool())
        self.main_split.add(self.left, weight=1)

        # Left quick actions (shown in Standard mode)
        self.left_actions = tb.Frame(self.left)
        tb.Button(self.left_actions, text="Open Tool Window", command=self._open_selected_tool,
                  bootstyle="success").pack(side="left", padx=4)
        tb.Button(self.left_actions, text="Focus If Open", command=self._focus_selected_tool,
                  bootstyle="secondary").pack(side="left", padx=4)

        # Right: details + targets + actions
        self.right = tb.LabelFrame(self.main_split, text="Details & Launch", padding=8)
        self.main_split.add(self.right, weight=2)

        # Selected tool info
        self.sel_key_var = tk.StringVar(value="")
        self.sel_title_var = tk.StringVar(value="")
        info_grid = tb.Frame(self.right); info_grid.pack(fill="x")
        tb.Label(info_grid, text="Key:", bootstyle="secondary").grid(row=0, column=0, sticky="w")
        tb.Label(info_grid, textvariable=self.sel_key_var).grid(row=0, column=1, sticky="w", padx=6)
        tb.Label(info_grid, text="Title:", bootstyle="secondary").grid(row=1, column=0, sticky="w")
        tb.Label(info_grid, textvariable=self.sel_title_var).grid(row=1, column=1, sticky="w", padx=6)

        tb.Label(self.right, text="Description:", bootstyle="secondary").pack(anchor="w", pady=(8,0))
        self.desc_text = TkScrolledText(self.right, height=8, wrap="word")
        self.desc_text.pack(fill="both", expand=False, pady=(2,8))

        # Targets manager (Pro mode)
        targets_frame = tb.LabelFrame(self.right, text="Targets (optional)", padding=8)
        targets_frame.pack(fill="both", expand=True, pady=(6,8))
        self.targets_tv = tb.Treeview(targets_frame, columns=("path",), show="headings", height=10)
        self.targets_tv.heading("path", text="Path")
        self.targets_tv.column("path", anchor="w", stretch=True, width=500)
        self.targets_tv.pack(fill="both", expand=True)

        tbar = tb.Frame(targets_frame); tbar.pack(fill="x", pady=(6,0))
        tb.Button(tbar, text="Add File(s)", command=self._add_files, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(tbar, text="Add Folder", command=self._add_folder, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(tbar, text="Remove Selected", command=self._remove_selected, bootstyle="warning").pack(side="left", padx=4)
        tb.Button(tbar, text="Clear", command=self._clear_targets, bootstyle="danger").pack(side="left", padx=4)

        # Right-side launch buttons (Pro mode)
        actions = tb.Frame(self.right); actions.pack(fill="x", pady=(8,0))
        tb.Button(actions, text="Open Tool Window", command=self._open_selected_tool,
                  bootstyle="success").pack(side="left", padx=6)
        tb.Button(actions, text="Focus If Open", command=self._focus_selected_tool,
                  bootstyle="secondary").pack(side="left", padx=6)

        # Populate list
        self._all_tools: List[str] = []
        self._refresh_tools()

        # If launched via context menu with a specific action, auto-open it
        if default_action and default_action in self.plugins:
            self._select_tool_key(default_action)
            cli_targets = self.targets_from_cli or []
            self._open_tool(default_action, cli_targets, self.extra_from_cli, give_focus=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = tb.Frame(self, padding=6); status.pack(fill="x")
        tb.Label(status, textvariable=self.status_var, bootstyle="secondary").pack(side="left")

        # Apply initial mode (Standard)
        self._apply_mode()

    # ---------- PanedWindow helper ----------
    def _pane_has(self, child) -> bool:
        """Return True if 'child' is already managed by the PanedWindow."""
        try:
            return str(child) in self.main_split.panes()
        except Exception:
            return False

    # ---------- Mode handling ----------
    def _apply_mode(self):
        mode = "pro" if self.pro_var.get() else "standard"
        self.ctx.ui_mode = mode

        right_in = self._pane_has(self.right)

        if mode == "standard":
            # Hide the right pane if it's present
            if right_in:
                self.main_split.forget(self.right)
            # Compact left table + show quick actions
            self.tools_tv.column("title", width=320)
            self.tools_tv.column("desc", width=1)
            self.left_actions.pack(fill="x", pady=(8, 0))
        else:
            # Show the right pane if it's not already added
            if not right_in:
                try:
                    self.main_split.add(self.right, weight=2)
                except Exception:
                    # If Tk still thinks it's added, ignore
                    pass
            # Restore columns + hide quick actions
            self.tools_tv.column("title", width=220)
            self.tools_tv.column("desc", width=380)
            self.left_actions.pack_forget()

        # Notify any open tool windows
        for key, win in list(self.open_windows.items()):
            plugin = self.plugins.get(key)
            if plugin and hasattr(plugin, "on_mode_changed") and win.winfo_exists():
                try:
                    plugin.on_mode_changed(mode)
                except Exception:
                    pass

        self.status_var.set(f"Mode: {mode.capitalize()}")

    # ---------- Tool listing & filtering ----------
    def _refresh_tools(self):
        self.tools_tv.delete(*self.tools_tv.get_children())
        self._all_tools = []
        for key, plugin in self.plugins.items():
            title = getattr(plugin, "title", key)
            desc = getattr(plugin, "description", "")
            iid = self.tools_tv.insert("", "end", values=(f"{key} — {title}", desc), tags=(key,))
            self._all_tools.append((iid, key, title, desc))
        # Select first entry by default
        first = self.tools_tv.get_children()
        if first:
            self.tools_tv.selection_set(first[0])
            self._update_details()

    def _filter_tools(self):
        q = self.search_var.get().strip().lower()
        self.tools_tv.delete(*self.tools_tv.get_children())
        for _, key, title, desc in self._all_tools:
            text = f"{key} {title} {desc}".lower()
            if q in text:
                self.tools_tv.insert("", "end", values=(f"{key} — {title}", desc), tags=(key,))

    def _selected_key(self) -> Optional[str]:
        sel = self.tools_tv.selection()
        if not sel:
            return None
        tags = self.tools_tv.item(sel[0], "tags")
        return tags[0] if tags else None

    def _select_tool_key(self, key: str):
        for iid in self.tools_tv.get_children():
            tags = self.tools_tv.item(iid, "tags")
            if tags and tags[0] == key:
                self.tools_tv.selection_set(iid)
                self.tools_tv.see(iid)
                self._update_details()
                return

    def _update_details(self):
        key = self._selected_key()
        if not key:
            self.sel_key_var.set(""); self.sel_title_var.set(""); self.desc_text.delete("1.0","end"); return
        plugin = self.plugins.get(key)
        self.sel_key_var.set(key)
        self.sel_title_var.set(getattr(plugin, "title", key))
        self.desc_text.delete("1.0", "end")
        self.desc_text.insert("end", getattr(plugin, "description", ""))

    # ---------- Targets management ----------
    def _current_targets(self) -> List[Path]:
        items = []
        for iid in self.targets_tv.get_children():
            p = self.targets_tv.set(iid, "path")
            if p:
                items.append(Path(p))
        return items

    def _already_listed(self, p: str) -> bool:
        for iid in self.targets_tv.get_children():
            if self.targets_tv.set(iid, "path") == p:
                return True
        return False

    def _add_path_row(self, p: str):
        if p and not self._already_listed(p):
            self.targets_tv.insert("", "end", values=(p,))

    def _add_files(self):
        from tkinter import filedialog
        paths = filedialog.askopenfilenames(title="Select file(s)")
        for p in paths or []:
            self._add_path_row(p)

    def _add_folder(self):
        from tkinter import filedialog
        p = filedialog.askdirectory(title="Select folder")
        if p:
            self._add_path_row(p)

    def _remove_selected(self):
        for iid in self.targets_tv.selection():
            self.targets_tv.delete(iid)

    def _clear_targets(self):
        for iid in self.targets_tv.get_children():
            self.targets_tv.delete(iid)

    # ---------- Launch helpers ----------
    def _open_selected_tool(self):
        key = self._selected_key()
        if not key:
            Messagebox.show_warning(message="Select a tool first.")
            return
        targets = self._current_targets() or self.targets_from_cli
        self._open_tool(key, targets, self.extra_from_cli, give_focus=True)

    def _focus_selected_tool(self):
        key = self._selected_key()
        if not key:
            Messagebox.show_warning(message="Select a tool first.")
            return
        win = self.open_windows.get(key)
        if win and win.winfo_exists():
            try:
                win.lift(); win.focus_force()
            except Exception:
                pass
        else:
            Messagebox.show_info(message="That tool window is not open yet.")

    def _open_tool(self, key: str, targets: List[Path], extra: List[str], give_focus: bool):
        plugin = self.plugins.get(key)
        if not plugin:
            Messagebox.show_error(message=f"Unknown tool: {key}")
            return

        # Enforce single window per tool (since PLUGIN is a singleton with state)
        existing = self.open_windows.get(key)
        if existing and existing.winfo_exists():
            try:
                existing.lift(); existing.focus_force()
            except Exception:
                pass
            self.status_var.set(f"Focused existing '{key}'")
            return

        win = ToolHostWindow(self, plugin, self.ctx, targets, extra)
        self.open_windows[key] = win

        def on_destroy(_e=None, k=key):
            try:
                if self.open_windows.get(k) is win:
                    self.open_windows.pop(k, None)
            except Exception:
                pass

        win.bind("<Destroy>", on_destroy)
        if give_focus:
            try:
                win.lift(); win.focus_force()
            except Exception:
                pass
        self.status_var.set(f"Opened '{key}' with {len(targets)} target(s)")

    # ---------- Misc ----------
    def _about(self):
        Messagebox.show_info(
            message=f"{APP_NAME} v{VERSION}\nCross-platform right-click toolkit launcher.\n"
                    f"Python {platform.python_version()} on {platform.system()}",
            title="About"
        )

# ----------------- Entry -----------------
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