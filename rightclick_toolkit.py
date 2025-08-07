from __future__ import annotations
import sys, os
from pathlib import Path
from typing import List, Dict, Optional
import platform
import tkinter as tk  # for StringVar, etc.
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText as TkScrolledText  # use Tk's ScrolledText to avoid ttk style issues

from plugins.base import AppContext
from plugins import discover_plugins

APP_NAME = "RightClickToolkit"
VERSION = "2.1.1"


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
            # keep unknown switches for plugins
            extra.append(a)
        else:
            # bare paths from Explorer/Finder
            targets.append(Path(a))
    targets = [t.resolve() for t in targets if str(t).strip()]
    return action, targets, extra


# ----------------- Tool Host Window -----------------
class ToolHostWindow(tk.Toplevel):
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

        container = ttk.Frame(self, padding=8)
        container.pack(fill="both", expand=True)

        # Build the tool's panel
        panel = self.plugin.make_panel(container, self.ctx)
        if hasattr(panel, "pack"):
            panel.pack(fill="both", expand=True)

        # Defer start so the panel exists
        self.after(50, self._start_tool)

        # Ensure cleanup is called
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _start_tool(self):
        try:
            self.plugin.start(self.ctx, self.targets, self.extra)
        except Exception as e:
            messagebox.showerror("Tool start error", str(e))

    def _on_close(self):
        try:
            self.plugin.cleanup()
        except Exception:
            pass
        self.destroy()


# ----------------- Main Window (Launcher) -----------------
class MainWindow(tk.Tk):
    def __init__(self, plugins: Dict[str, object], default_action: Optional[str],
                 targets: List[Path], extra: List[str]):
        super().__init__()
        self.title(f"{APP_NAME} {VERSION}")
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
            resource_dir=resource_dir
        )

        # ---- Top bar (branding + actions) ----
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")
        ttk.Label(top, text=f"{APP_NAME}", font="-size 16 -weight bold").pack(side="left")
        ttk.Label(top, text=f"v{VERSION}").pack(side="left", padx=(8, 0))
        ttk.Button(top, text="Refresh", command=self._refresh_tools).pack(side="right", padx=6)
        ttk.Button(top, text="About", command=self._about).pack(side="right")

        # ---- Main split: left list (tools), right details/targets ----
        main_split = ttk.PanedWindow(self, orient="horizontal")
        main_split.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # Left: Tools list + search
        left = ttk.LabelFrame(main_split, text="Available Tools", padding=8)
        search_row = ttk.Frame(left)
        search_row.pack(fill="x", pady=(0, 6))
        ttk.Label(search_row, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_row, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=6)
        search_entry.bind("<KeyRelease>", lambda e: self._filter_tools())

        self.tools_tv = ttk.Treeview(left, columns=("title", "desc"), show="headings", height=20)
        self.tools_tv.heading("title", text="Tool")
        self.tools_tv.heading("desc", text="Description")
        self.tools_tv.column("title", width=220, anchor="w")
        self.tools_tv.column("desc", width=380, anchor="w")
        self.tools_tv.pack(fill="both", expand=True)
        self.tools_tv.bind("<<TreeviewSelect>>", lambda e: self._update_details())
        self.tools_tv.bind("<Double-1>", lambda e: self._open_selected_tool())
        main_split.add(left, weight=1)

        # Right: details + targets + actions
        right = ttk.LabelFrame(main_split, text="Details & Launch", padding=8)
        main_split.add(right, weight=2)

        # Selected tool info
        self.sel_key_var = tk.StringVar(value="")
        self.sel_title_var = tk.StringVar(value="")
        self.sel_desc_var = tk.StringVar(value="")

        info_grid = ttk.Frame(right)
        info_grid.pack(fill="x")
        ttk.Label(info_grid, text="Key:").grid(row=0, column=0, sticky="w")
        ttk.Label(info_grid, textvariable=self.sel_key_var).grid(row=0, column=1, sticky="w", padx=6)
        ttk.Label(info_grid, text="Title:").grid(row=1, column=0, sticky="w")
        ttk.Label(info_grid, textvariable=self.sel_title_var).grid(row=1, column=1, sticky="w", padx=6)

        ttk.Label(right, text="Description:").pack(anchor="w", pady=(8, 0))
        # Use Tk's ScrolledText to avoid ttk 'style' option error on older Tk builds (macOS)
        self.desc_text = TkScrolledText(right, height=8, wrap="word")
        self.desc_text.pack(fill="both", expand=False, pady=(2, 8))

        # Targets manager (Treeview list, themed)
        targets_frame = ttk.LabelFrame(right, text="Targets (optional)", padding=8)
        targets_frame.pack(fill="both", expand=True, pady=(6, 8))

        self.targets_tv = ttk.Treeview(targets_frame, columns=("path",), show="headings", height=10)
        self.targets_tv.heading("path", text="Path")
        self.targets_tv.column("path", anchor="w", stretch=True, width=500)
        self.targets_tv.pack(fill="both", expand=True)

        tbar = ttk.Frame(targets_frame)
        tbar.pack(fill="x", pady=(6, 0))
        ttk.Button(tbar, text="Add File(s)", command=self._add_files).pack(side="left", padx=4)
        ttk.Button(tbar, text="Add Folder", command=self._add_folder).pack(side="left", padx=4)
        ttk.Button(tbar, text="Remove Selected", command=self._remove_selected).pack(side="left", padx=4)
        ttk.Button(tbar, text="Clear", command=self._clear_targets).pack(side="left", padx=4)

        # Launch buttons
        actions = ttk.Frame(right)
        actions.pack(fill="x", pady=(8, 0))
        ttk.Button(actions, text="Open Tool Window", command=self._open_selected_tool).pack(
            side="left", padx=6
        )
        ttk.Button(actions, text="Focus If Open", command=self._focus_selected_tool).pack(
            side="left", padx=6
        )

        # Populate list
        self._all_tools: List[str] = []   # store keys for filtering
        self._refresh_tools()

        # If launched via context menu with a specific action, auto-open it
        if default_action and default_action in self.plugins:
            self._select_tool_key(default_action)
            cli_targets = self.targets_from_cli or []
            self._open_tool(default_action, cli_targets, self.extra_from_cli, give_focus=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Frame(self, padding=6)
        status.pack(fill="x")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")

    # ---- Tool listing & filtering ----
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
            self.sel_key_var.set("")
            self.sel_title_var.set("")
            self.desc_text.delete("1.0", "end")
            return
        plugin = self.plugins.get(key)
        self.sel_key_var.set(key)
        self.sel_title_var.set(getattr(plugin, "title", key))
        self.desc_text.delete("1.0", "end")
        self.desc_text.insert("end", getattr(plugin, "description", ""))

    # ---- Targets management (Treeview-backed) ----
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
        if not p:
            return
        if self._already_listed(p):
            return
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

    # ---- Launch helpers ----
    def _open_selected_tool(self):
        key = self._selected_key()
        if not key:
            messagebox.showwarning("Warning", "Select a tool first.")
            return
        # Prefer GUI-selected targets; fall back to CLI targets if none
        targets = self._current_targets() or self.targets_from_cli
        self._open_tool(key, targets, self.extra_from_cli, give_focus=True)

    def _focus_selected_tool(self):
        key = self._selected_key()
        if not key:
            messagebox.showwarning("Warning", "Select a tool first.")
            return
        win = self.open_windows.get(key)
        if win and win.winfo_exists():
            try:
                win.lift()
                win.focus_force()
            except Exception:
                pass
        else:
            messagebox.showinfo("Info", "That tool window is not open yet.")

    def _open_tool(self, key: str, targets: List[Path], extra: List[str], give_focus: bool):
        plugin = self.plugins.get(key)
        if not plugin:
            messagebox.showerror("Error", f"Unknown tool: {key}")
            return

        # Enforce single window per tool (since PLUGIN is a singleton with state)
        existing = self.open_windows.get(key)
        if existing and existing.winfo_exists():
            try:
                existing.lift()
                existing.focus_force()
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
                win.lift()
                win.focus_force()
            except Exception:
                pass
        self.status_var.set(f"Opened '{key}' with {len(targets)} target(s)")

    # ---- Misc ----
    def _about(self):
        messagebox.showinfo(
            "About",
            f"{APP_NAME} v{VERSION}\nCross-platform right-click toolkit launcher.\n"
            f"Python {platform.python_version()} on {platform.system()}"
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