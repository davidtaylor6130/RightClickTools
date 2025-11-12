from __future__ import annotations

import csv
import json
import os
import queue
import subprocess
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext
from .mirror_verifier_core import (
    IgnoreRules,
    MirrorVerifierConfig,
    MirrorVerifierCore,
    VerificationItem,
    VerificationMode,
)

_STATUS_TAGS = {
    "OK": "success",
    "MISSING": "danger",
    "MISMATCH": "warning",
    "SOURCE": "secondary",
    "IGNORED": "secondary",
}

_VERIFY_LABELS = {
    VerificationMode.SIZE_ONLY: "Size only (fastest)",
    VerificationMode.SIZE_AND_MTIME: "Size & modified time",
    VerificationMode.ADAPTIVE_HASH: "Adaptive hash fallback",
    VerificationMode.FULL_HASH: "Full SHA-256",
}


@dataclass
class _NodeKey:
    root: Path
    rel: str  # forward-slash relative path, empty for root

    def child(self, part: str) -> "_NodeKey":
        if not self.rel:
            return _NodeKey(self.root, part)
        return _NodeKey(self.root, f"{self.rel}/{part}")


class _ResultStore:
    def __init__(self) -> None:
        self.items: List[VerificationItem] = []
        self.by_node: Dict[Tuple[Path, str], List[int]] = {}

    def add(self, item: VerificationItem) -> None:
        index = len(self.items)
        self.items.append(item)
        key = (item.source_root, self._folder_rel(item.source_rel))
        self.by_node.setdefault(key, []).append(index)

    def iter_node_items(self, key: _NodeKey) -> List[VerificationItem]:
        rel = key.rel
        indices = []
        for node_key, ids in self.by_node.items():
            root, folder = node_key
            if root != key.root:
                continue
            if not rel:
                indices.extend(ids)
                continue
            if folder == rel or folder.startswith(rel + "/"):
                indices.extend(ids)
        return [self.items[i] for i in indices]

    def node_leaf_items(self, key: _NodeKey) -> List[VerificationItem]:
        rel = key.rel
        ids = self.by_node.get((key.root, rel), [])
        return [self.items[i] for i in ids]

    def summary(self) -> Dict[str, int]:
        counts = {"total": 0, "matched": 0, "missing": 0, "mismatch": 0}
        for item in self.items:
            if item.ignored:
                continue
            counts["total"] += 1
            if item.status == "OK":
                counts["matched"] += 1
            elif item.status == "MISSING":
                counts["missing"] += 1
            elif item.status == "MISMATCH":
                counts["mismatch"] += 1
        return counts

    def mark_ignored(self, key: _NodeKey) -> None:
        prefix = key.rel
        for item in self.items:
            if item.source_root != key.root:
                continue
            if not prefix or item.source_rel == prefix or item.source_rel.startswith(prefix + "/"):
                item.ignored = True

    @staticmethod
    def _folder_rel(rel: str) -> str:
        if "/" not in rel:
            return ""
        return rel.rsplit("/", 1)[0]


class MirrorVerifierTool:
    key = "mirror_verifier"
    title = "Mirror Verifier"
    description = (
        "Confirm that source directories match one or more mirror destinations."
    )

    def __init__(self) -> None:
        self.ctx: Optional[AppContext] = None
        self._ui_mode = "standard"

        self.panel: Optional[tb.Frame] = None
        self.sources_list = None
        self.mirror_list = None
        self.verify_mode_var: Optional[tb.StringVar] = None
        self.follow_symlinks_var: Optional[tb.BooleanVar] = None
        self.ignore_structure_var: Optional[tb.BooleanVar] = None
        self.summary_var: Optional[tb.StringVar] = None
        self.progress_var: Optional[tb.StringVar] = None
        self.banner_var: Optional[tb.StringVar] = None
        self.filter_var: Optional[tb.StringVar] = None
        self.search_var: Optional[tb.StringVar] = None
        self.performance_button: Optional[tb.Button] = None
        self.performance_frame: Optional[tb.Labelframe] = None
        self.performance_vars: Dict[str, tb.StringVar] = {}

        self.folder_tree = None
        self.detail_tree = None
        self._tree_nodes: Dict[Tuple[Path, str], str] = {}
        self._detail_rows: Dict[str, VerificationItem] = {}

        self.scan_button = None
        self.cancel_button = None
        self.pause_button = None

        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._paused = False
        self._last_progress_message = "Ready."

        self._ui_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._result_store = _ResultStore()
        self._disconnected: Dict[Path, str] = {}
        self._performance_visible = False

    # ------------------------------------------------------------------ UI --
    def make_panel(self, master, context: AppContext):
        import tkinter as tk
        from tkinter import filedialog

        self.ctx = context
        self._ui_mode = context.ui_mode

        root = tb.Frame(master)
        self.panel = root

        sources_frame = tb.Labelframe(root, text="Source directories", padding=8)
        sources_frame.pack(fill="both", expand=False, padx=8, pady=(10, 6))
        self.sources_list = tk.Listbox(sources_frame, height=5)
        self.sources_list.pack(fill="both", expand=True, side="left", padx=(0, 6))
        src_buttons = tb.Frame(sources_frame)
        src_buttons.pack(side="right", fill="y")
        tb.Button(src_buttons, text="Add…", command=lambda: self._add_path(self.sources_list, filedialog.askdirectory)).pack(fill="x", pady=2)
        tb.Button(src_buttons, text="Remove", command=lambda: self._remove_selected(self.sources_list)).pack(fill="x", pady=2)
        tb.Button(src_buttons, text="Clear", command=lambda: self._clear_list(self.sources_list)).pack(fill="x", pady=2)

        mirror_frame = tb.Labelframe(root, text="Mirror locations", padding=8)
        mirror_frame.pack(fill="both", expand=False, padx=8, pady=(0, 6))
        self.mirror_list = tk.Listbox(mirror_frame, height=5)
        self.mirror_list.pack(fill="both", expand=True, side="left", padx=(0, 6))
        mirror_buttons = tb.Frame(mirror_frame)
        mirror_buttons.pack(side="right", fill="y")
        tb.Button(mirror_buttons, text="Add…", command=lambda: self._add_path(self.mirror_list, filedialog.askdirectory)).pack(fill="x", pady=2)
        tb.Button(mirror_buttons, text="Remove", command=lambda: self._remove_selected(self.mirror_list)).pack(fill="x", pady=2)
        tb.Button(mirror_buttons, text="Clear", command=lambda: self._clear_list(self.mirror_list)).pack(fill="x", pady=2)

        options = tb.Labelframe(root, text="Options", padding=8)
        options.pack(fill="x", expand=False, padx=8, pady=(0, 6))
        self.verify_mode_var = tk.StringVar(value=_VERIFY_LABELS[VerificationMode.SIZE_ONLY])
        self.follow_symlinks_var = tk.BooleanVar(value=False)
        self.ignore_structure_var = tk.BooleanVar(value=False)
        tb.Label(options, text="Verification strategy:").pack(anchor="w")
        verify_combo = tb.Combobox(
            options,
            textvariable=self.verify_mode_var,
            values=tuple(_VERIFY_LABELS.values()),
            state="readonly",
        )
        verify_combo.pack(anchor="w", pady=(2, 4))
        tb.Checkbutton(options, text="Follow symbolic links", variable=self.follow_symlinks_var).pack(anchor="w", pady=(2, 0))
        tb.Checkbutton(options, text="Ignore folder structure (match by file name & size)", variable=self.ignore_structure_var).pack(anchor="w", pady=(2, 0))

        actions = tb.Frame(root)
        actions.pack(fill="x", padx=8, pady=(0, 6))
        self.scan_button = tb.Button(actions, text="Scan mirrors", bootstyle="success", command=self._start_scan)
        self.scan_button.pack(side="left")
        self.pause_button = tb.Button(actions, text="Pause", state="disabled", bootstyle="secondary", command=self._toggle_pause)
        self.pause_button.pack(side="left", padx=(6, 0))
        self.cancel_button = tb.Button(actions, text="Cancel", state="disabled", bootstyle="warning", command=self._cancel_scan)
        self.cancel_button.pack(side="left", padx=(6, 0))
        self.summary_var = tk.StringVar(value="Ready.")
        self.progress_var = tk.StringVar(value="Idle")
        self.banner_var = tk.StringVar(value="")
        summary_frame = tb.Frame(actions)
        summary_frame.pack(side="right")
        tb.Label(summary_frame, textvariable=self.summary_var, bootstyle="secondary").pack(anchor="e")
        tb.Label(summary_frame, textvariable=self.progress_var, bootstyle="info").pack(anchor="e")

        banner_label = tb.Label(root, textvariable=self.banner_var, bootstyle="danger")
        banner_label.pack(fill="x", padx=8, pady=(0, 4))

        split = tb.PanedWindow(root, orient="horizontal")
        split.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        tree_container = tb.Labelframe(split, text="Folders", padding=4)
        detail_container = tb.Labelframe(split, text="Details", padding=4)
        split.add(tree_container, weight=1)
        split.add(detail_container, weight=2)

        self.folder_tree = tb.Treeview(tree_container, show="tree")
        self.folder_tree.pack(fill="both", expand=True)
        self.folder_tree.bind("<<TreeviewSelect>>", lambda _evt: self._refresh_detail_view())
        self.folder_tree.bind("<Button-3>", self._show_tree_menu)

        filter_row = tb.Frame(detail_container)
        filter_row.pack(fill="x", pady=(0, 4))
        self.filter_var = tk.StringVar(value="All")
        filter_combo = tb.Combobox(filter_row, width=12, textvariable=self.filter_var, state="readonly", values=("All", "Missing", "Mismatch", "OK"))
        filter_combo.pack(side="left")
        filter_combo.bind("<<ComboboxSelected>>", lambda _evt: self._refresh_detail_view())
        self.search_var = tk.StringVar(value="")
        search_entry = tb.Entry(filter_row, textvariable=self.search_var)
        search_entry.pack(side="left", fill="x", expand=True, padx=(6, 0))
        self.search_var.trace_add("write", lambda *_: self._refresh_detail_view())
        save_btn = tb.Button(filter_row, text="Save report…", bootstyle="secondary", command=self._save_report)
        save_btn.pack(side="right")

        columns = ("status", "path", "detail")
        self.detail_tree = tb.Treeview(detail_container, columns=columns, show="headings")
        self.detail_tree.heading("status", text="Status")
        self.detail_tree.heading("path", text="Relative path")
        self.detail_tree.heading("detail", text="Details")
        self.detail_tree.column("status", width=110, anchor="w")
        self.detail_tree.column("path", width=280, anchor="w")
        self.detail_tree.column("detail", anchor="w")
        self.detail_tree.pack(fill="both", expand=True)
        self.detail_tree.bind("<Double-1>", self._open_detail_location)

        style_manager = tb.Style()
        for status, style in _STATUS_TAGS.items():
            try:
                self.detail_tree.tag_configure(status, bootstyle=style)
            except Exception:
                color = getattr(getattr(style_manager, "colors", None), style, None)
                if color:
                    self.detail_tree.tag_configure(status, foreground=color)

        perf_toggle = tb.Button(root, text="Performance ▸", command=self._toggle_performance)
        perf_toggle.pack(fill="x", padx=8, pady=(0, 4))
        self.performance_button = perf_toggle
        perf_frame = tb.Labelframe(root, text="Performance", padding=8)
        self.performance_frame = perf_frame
        files_var = tb.StringVar(value="Files/sec: –")
        speed_var = tb.StringVar(value="MB/sec: –")
        index_var = tb.StringVar(value="Index time: –")
        hash_var = tb.StringVar(value="Hash time: –")
        self.performance_vars = {
            "files": files_var,
            "speed": speed_var,
            "index": index_var,
            "hash": hash_var,
        }
        for var in (files_var, speed_var, index_var, hash_var):
            tb.Label(perf_frame, textvariable=var, anchor="w").pack(fill="x", anchor="w")

        return root

    # --------------------------------------------------------------- actions --
    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        if self.sources_list is None:
            return
        for target in targets or []:
            if Path(target).exists():
                self.sources_list.insert("end", str(target))
        it = iter(argv or [])
        for item in it:
            if item == "--mirror":
                value = next(it, None)
                if value:
                    self.mirror_list.insert("end", value)

    def cleanup(self):
        self._cancel_scan(wait=True)

    def on_mode_changed(self, ui_mode: str):
        self._ui_mode = ui_mode

    # ----------------------------------------------------------- UI helpers --
    def _add_path(self, listbox, chooser):
        path = chooser()
        if path:
            listbox.insert("end", path)

    def _remove_selected(self, listbox):
        for index in reversed(listbox.curselection()):
            listbox.delete(index)

    def _clear_list(self, listbox):
        listbox.delete(0, "end")

    # -------------------------------------------------------------- Scanning --
    def _start_scan(self):
        if self._worker and self._worker.is_alive():
            Messagebox.show_info(title="Mirror Verifier", message="A scan is already running.")
            return
        sources = self._listbox_values(self.sources_list)
        mirrors = self._listbox_values(self.mirror_list)
        if not sources:
            Messagebox.show_error(title="Mirror Verifier", message="Add at least one source directory.")
            return
        if not mirrors:
            Messagebox.show_error(title="Mirror Verifier", message="Add at least one mirror directory.")
            return
        missing_sources = [p for p in sources if not Path(p).exists()]
        if missing_sources:
            Messagebox.show_error(title="Mirror Verifier", message=f"Source missing: {missing_sources[0]}")
            return
        missing_mirrors = [p for p in mirrors if not Path(p).exists()]
        if missing_mirrors:
            Messagebox.show_error(title="Mirror Verifier", message=f"Mirror missing: {missing_mirrors[0]}")
            return

        self._result_store = _ResultStore()
        self._tree_nodes.clear()
        self._detail_rows.clear()
        self._disconnected.clear()
        if self.folder_tree:
            self.folder_tree.delete(*self.folder_tree.get_children())
        if self.detail_tree:
            self.detail_tree.delete(*self.detail_tree.get_children())
        self._performance_visible = False
        if self.performance_frame:
            self.performance_frame.pack_forget()
            if self.performance_button:
                self.performance_button.configure(text="Performance ▸")
        self._set_summary("Scanning…")
        self._set_progress("Preparing")
        self.banner_var.set("")
        self.scan_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.pause_button.configure(state="normal", text="Pause", bootstyle="secondary")
        self._stop_event.clear()
        self._pause_event.set()
        self._paused = False
        verify_mode = self._selected_mode()
        follow_symlinks = bool(self.follow_symlinks_var.get() if self.follow_symlinks_var else False)
        ignore_structure = bool(self.ignore_structure_var.get() if self.ignore_structure_var else False)
        config = MirrorVerifierConfig(
            sources=[Path(p) for p in sources],
            mirrors=[Path(p) for p in mirrors],
            mode=verify_mode,
            ignore_structure=ignore_structure,
            follow_symlinks=follow_symlinks,
            thread_count=None,
        )
        self._worker = threading.Thread(
            target=self._run_core,
            args=(config,),
            name="mirror-verifier",
            daemon=True,
        )
        self._worker.start()
        if self.panel:
            self.panel.after(100, self._poll_ui_queue)

    def _run_core(self, config: MirrorVerifierConfig) -> None:
        core = MirrorVerifierCore(
            config,
            self._stop_event,
            self._pause_event,
            self._enqueue_progress,
            self._enqueue_result,
            self._enqueue_status,
            self._enqueue_disconnection,
            telemetry_callback=self._enqueue_telemetry,
        )
        summary = core.run()
        self._ui_queue.put(("summary", summary.as_dict()))

    def _enqueue_result(self, item: VerificationItem) -> None:
        self._ui_queue.put(("result", item))

    def _enqueue_progress(self, message: str) -> None:
        self._ui_queue.put(("progress", message))

    def _enqueue_status(self, message: str) -> None:
        self._ui_queue.put(("status", message))

    def _enqueue_disconnection(self, root: Path, message: str, disconnected: bool) -> None:
        self._ui_queue.put(("disconnect", (root, message, disconnected)))

    def _enqueue_telemetry(self, data: Dict[str, float]) -> None:
        self._ui_queue.put(("telemetry", data))

    def _poll_ui_queue(self):
        if self.panel is None:
            return
        try:
            while True:
                event, payload = self._ui_queue.get_nowait()
                if event == "result":
                    self._handle_result(payload)
                elif event == "progress":
                    self._set_progress(payload)
                elif event == "status":
                    self._last_progress_message = payload
                elif event == "disconnect":
                    root, message, disconnected = payload
                    if disconnected:
                        self._disconnected[root] = message
                    else:
                        self._disconnected.pop(root, None)
                    self._update_banner()
                elif event == "telemetry":
                    self._update_performance(payload)
                elif event == "summary":
                    self._finish_scan(payload)
        except queue.Empty:
            pass
        if self._worker and self._worker.is_alive():
            self.panel.after(200, self._poll_ui_queue)

    def _finish_scan(self, summary: Dict[str, int]):
        message = (
            f"Completed – processed {summary['total']} files "
            f"({summary['matched']} matched, {summary['missing']} missing, {summary['mismatch']} mismatches)"
        )
        self._set_summary(message)
        self._set_progress("Idle")
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.pause_button.configure(state="disabled", text="Pause", bootstyle="secondary")
        self._paused = False
        self._pause_event.set()

    def _handle_result(self, item: VerificationItem):
        self._result_store.add(item)
        key = _NodeKey(item.source_root, _ResultStore._folder_rel(item.source_rel))
        tree_id = self._ensure_tree_node(key)
        if tree_id and self.folder_tree:
            current_text = self.folder_tree.item(tree_id, "text")
            if item.status != "OK" and "⚠" not in current_text:
                self.folder_tree.item(tree_id, text=f"⚠ {current_text}")
        if self.folder_tree and not self.folder_tree.selection():
            self.folder_tree.selection_set(tree_id)
        self._refresh_detail_view()
        summary = self._result_store.summary()
        self._set_summary(
            f"Progress – {summary['total']} files ({summary['matched']} OK, {summary['missing']} missing, {summary['mismatch']} mismatch)"
        )

    def _set_summary(self, message: str):
        if self.summary_var:
            self.summary_var.set(message)

    def _set_progress(self, message: str):
        self._last_progress_message = message
        if self.progress_var:
            self.progress_var.set(message)

    def _update_banner(self):
        if not self.banner_var:
            return
        if not self._disconnected:
            self.banner_var.set("")
            return
        parts = [f"{root}: {msg or 'disconnected'}" for root, msg in self._disconnected.items()]
        self.banner_var.set("Drive disconnected – " + "; ".join(parts))

    def _update_performance(self, data: Dict[str, float]):
        if not self.performance_vars:
            return
        total_files = data.get("total_files", 0) or 0
        hash_time = data.get("hash_time", 0.0) or 0.0
        hashed_files = data.get("hashed_files", 0) or 0
        hashed_bytes = data.get("hashed_bytes", 0) or 0
        files_per_sec = (hashed_files / hash_time) if hash_time else 0
        mb_per_sec = (hashed_bytes / (1024 * 1024)) / hash_time if hash_time else 0
        self.performance_vars["files"].set(f"Files/sec: {files_per_sec:.1f}" if files_per_sec else "Files/sec: –")
        self.performance_vars["speed"].set(f"MB/sec: {mb_per_sec:.1f}" if mb_per_sec else "MB/sec: –")
        self.performance_vars["index"].set(f"Index time: {data.get('index_time', 0.0):.2f}s")
        self.performance_vars["hash"].set(f"Hash time: {hash_time:.2f}s")

    def _toggle_performance(self):
        if not self.performance_frame or not self.performance_button:
            return
        if self._performance_visible:
            self.performance_frame.pack_forget()
            self._performance_visible = False
            self.performance_button.configure(text="Performance ▸")
        else:
            self.performance_frame.pack(fill="x", padx=8, pady=(0, 8))
            self._performance_visible = True
            self.performance_button.configure(text="Performance ▾")

    def _listbox_values(self, listbox) -> List[str]:
        if not listbox:
            return []
        return [listbox.get(idx) for idx in range(listbox.size())]

    def _selected_mode(self) -> VerificationMode:
        if not self.verify_mode_var:
            return VerificationMode.SIZE_ONLY
        selected = self.verify_mode_var.get()
        for mode, label in _VERIFY_LABELS.items():
            if selected == label or selected == mode.value:
                return mode
        return VerificationMode.SIZE_ONLY

    def _ensure_tree_node(self, key: _NodeKey) -> Optional[str]:
        if self.folder_tree is None:
            return None
        tree = self.folder_tree
        path_key = (key.root, key.rel)
        existing = self._tree_nodes.get(path_key)
        if existing:
            return existing
        if not key.rel:
            node_id = tree.insert("", "end", text=key.root.name or str(key.root), open=True)
            self._tree_nodes[path_key] = node_id
            return node_id
        parent_rel = key.rel.rsplit("/", 1)[0] if "/" in key.rel else ""
        parent_id = self._ensure_tree_node(_NodeKey(key.root, parent_rel))
        name = key.rel.split("/")[-1]
        node_id = tree.insert(parent_id, "end", text=name, open=False)
        self._tree_nodes[path_key] = node_id
        return node_id

    def _refresh_detail_view(self):
        if not self.detail_tree or not self.folder_tree:
            return
        selection = self.folder_tree.selection()
        if not selection:
            self.detail_tree.delete(*self.detail_tree.get_children())
            return
        tree_id = selection[0]
        meta = None
        for (root, rel), node in self._tree_nodes.items():
            if node == tree_id:
                meta = _NodeKey(root, rel)
                break
        if not meta:
            return
        status_filter = self.filter_var.get() if self.filter_var else "All"
        search_text = (self.search_var.get() if self.search_var else "").lower()
        items = self._result_store.iter_node_items(meta)
        self.detail_tree.delete(*self.detail_tree.get_children())
        for item in items:
            if item.ignored:
                continue
            if status_filter != "All" and item.status.lower() != status_filter.lower():
                continue
            if search_text and search_text not in item.source_rel.lower() and search_text not in item.detail.lower():
                continue
            row = self.detail_tree.insert(
                "",
                "end",
                values=(item.status, item.source_rel, item.detail if not item.ignored else f"{item.detail} (ignored)"),
                tags=(item.status,),
            )
            self._detail_rows[row] = item

    def _open_detail_location(self, event):
        region = self.detail_tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.detail_tree.identify_row(event.y)
        item = self._detail_rows.get(row_id)
        if not item:
            return
        path = item.source_root / item.source_rel
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path.parent))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path.parent)])
            else:
                subprocess.Popen(["xdg-open", str(path.parent)])
        except Exception as exc:
            Messagebox.show_error(title="Mirror Verifier", message=f"Cannot open folder: {exc}")

    def _show_tree_menu(self, event):
        import tkinter as tk

        if not self.folder_tree:
            return
        tree_id = self.folder_tree.identify_row(event.y)
        if not tree_id:
            return
        self.folder_tree.selection_set(tree_id)
        for (root, rel), node in self._tree_nodes.items():
            if node == tree_id:
                key = _NodeKey(root, rel)
                break
        else:
            return
        menu = tk.Menu(self.folder_tree, tearoff=False)
        menu.add_command(label="Ignore this folder in future scans", command=lambda: self._ignore_folder(key))
        menu.add_command(label="Collapse all mismatches here", command=lambda: self._collapse_node(tree_id))
        menu.tk_popup(event.x_root, event.y_root)

    def _ignore_folder(self, key: _NodeKey):
        rules = IgnoreRules(key.root)
        rules.add(key.rel)
        self._result_store.mark_ignored(key)
        Messagebox.show_info(title="Mirror Verifier", message=f"Folder {key.rel or key.root.name} will be ignored next time.")
        self._refresh_detail_view()
        summary = self._result_store.summary()
        self._set_summary(
            f"Progress – {summary['total']} files ({summary['matched']} OK, {summary['missing']} missing, {summary['mismatch']} mismatch)"
        )

    def _collapse_node(self, tree_id: str):
        if not self.folder_tree:
            return
        def _collapse(item):
            self.folder_tree.item(item, open=False)
            for child in self.folder_tree.get_children(item):
                _collapse(child)
        _collapse(tree_id)

    def _save_report(self):
        import tkinter.filedialog as fd

        if not self.detail_tree:
            return
        selection = self.folder_tree.selection() if self.folder_tree else ()
        if not selection:
            Messagebox.show_info(title="Mirror Verifier", message="Select a folder in the tree first.")
            return
        file_path = fd.asksaveasfilename(
            title="Save mirror verification report",
            defaultextension=".json",
            filetypes=(("JSON report", "*.json"), ("CSV report", "*.csv")),
        )
        if not file_path:
            return
        key = None
        tree_id = selection[0]
        for (root, rel), node in self._tree_nodes.items():
            if node == tree_id:
                key = _NodeKey(root, rel)
                break
        if not key:
            return
        items = self._result_store.node_leaf_items(key)
        filtered = [
            {
                "status": item.status,
                "source_rel": item.source_rel,
                "detail": item.detail,
                "ignored": item.ignored,
            }
            for item in items
        ]
        try:
            if file_path.endswith(".csv"):
                with open(file_path, "w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=["status", "source_rel", "detail", "ignored"])
                    writer.writeheader()
                    writer.writerows(filtered)
            else:
                with open(file_path, "w", encoding="utf-8") as handle:
                    json.dump(filtered, handle, ensure_ascii=False, indent=2)
            Messagebox.show_info(title="Mirror Verifier", message=f"Report saved to {file_path}")
        except OSError as exc:
            Messagebox.show_error(title="Mirror Verifier", message=f"Cannot save report: {exc}")

    def _cancel_scan(self, wait: bool = False):
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._pause_event.set()
            if wait:
                self._worker.join(timeout=5)
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.pause_button.configure(state="disabled", text="Pause", bootstyle="secondary")
        self._paused = False

    def _toggle_pause(self):
        if not self._worker or not self._worker.is_alive():
            return
        if not self._paused:
            self._paused = True
            self._pause_event.clear()
            self.pause_button.configure(text="Resume", bootstyle="info")
            self._set_progress(f"Paused — {self._last_progress_message}")
        else:
            self._paused = False
            self._pause_event.set()
            self.pause_button.configure(text="Pause", bootstyle="secondary")
            self._set_progress(self._last_progress_message)


PLUGIN = MirrorVerifierTool()
