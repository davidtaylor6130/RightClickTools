from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Tuple

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext


_STATUS_TAGS = {
    "OK": "success",
    "MISSING": "danger",
    "MISMATCH": "warning",
    "SOURCE": "secondary",
}


class _ScanInterrupted(Exception):
    """Internal signal raised to cancel or pause a scan."""


class _HashLogWriter:
    """Persist mirror file hashes to a custom log file."""

    def __init__(self, root: Path):
        self.root = root
        self.path = root / "mirror_hashes.rcthash"
        self._lock = threading.Lock()
        self._handle: Optional[TextIO] = None
        try:
            self._handle = self.path.open("a", encoding="utf-8")
        except OSError:
            self._handle = None

    @property
    def available(self) -> bool:
        return self._handle is not None

    def log(self, relative_path: str, digest: str) -> None:
        if not self._handle:
            return
        with self._lock:
            self._handle.write(f"{relative_path}|{digest}\n")
            self._handle.flush()

    def close(self) -> None:
        if self._handle:
            try:
                self._handle.close()
            finally:
                self._handle = None


class _ProgressLog:
    """Track per-source progress so scans can resume after closing the app."""

    def __init__(self, root: Path):
        self.root = root
        self.path = root / "mirror_verifier_progress.rctresume"
        self._lock = threading.Lock()
        self._handle: Optional[TextIO] = None
        self._entries: Dict[str, Tuple[str, str]] = {}
        self._status_counts: Dict[str, int] = {}
        self._load_existing()
        self._open_append()

    def _load_existing(self) -> None:
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rel = payload.get("rel")
                    status = payload.get("status")
                    detail = payload.get("detail", "")
                    if not rel or not status:
                        continue
                    self._entries[rel] = (status, detail)
        except OSError:
            return
        self._recount_statuses()

    def _open_append(self) -> None:
        try:
            self._handle = self.path.open("a", encoding="utf-8")
        except OSError:
            self._handle = None

    def _recount_statuses(self) -> None:
        self._status_counts.clear()
        for status, _ in self._entries.values():
            self._status_counts[status] = self._status_counts.get(status, 0) + 1

    @property
    def available(self) -> bool:
        return self._handle is not None

    @property
    def total_processed(self) -> int:
        return len(self._entries)

    @property
    def status_counts(self) -> Dict[str, int]:
        return dict(self._status_counts)

    def is_processed(self, rel: str) -> bool:
        return rel in self._entries

    def iter_entries(self):
        for rel in sorted(self._entries):
            status, detail = self._entries[rel]
            yield rel, status, detail

    def record(self, rel: str, status: str, detail: str) -> None:
        if not rel:
            return
        previous = self._entries.get(rel)
        if previous:
            prev_status, _ = previous
            if prev_status in self._status_counts:
                self._status_counts[prev_status] -= 1
                if self._status_counts[prev_status] <= 0:
                    self._status_counts.pop(prev_status, None)
        self._entries[rel] = (status, detail)
        self._status_counts[status] = self._status_counts.get(status, 0) + 1
        if not self._handle:
            return
        payload = {"rel": rel, "status": status, "detail": detail}
        with self._lock:
            self._handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._handle.flush()

    def close(self) -> None:
        if self._handle:
            try:
                self._handle.close()
            finally:
                self._handle = None

    def clear_file(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            return


def _hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _mtimes_close(left: float, right: float, tolerance: float = 2.0) -> bool:
    return abs(left - right) <= tolerance


@dataclass
class _IndexedFile:
    path: str
    size: int
    mtime: float
    sha256: Optional[str] = None
    error: Optional[str] = None

    def ensure_hash(self) -> Optional[str]:
        if self.sha256 is None and self.error is None:
            try:
                self.sha256 = _hash_file(Path(self.path))
            except OSError as exc:
                self.error = str(exc)
        return self.sha256


@dataclass
class _MirrorIndex:
    by_rel: Dict[str, _IndexedFile] = field(default_factory=dict)
    by_signature: Dict[Tuple[str, int], List[_IndexedFile]] = field(default_factory=dict)

    def add(self, rel_key: str, entry: _IndexedFile, include_signature: bool):
        self.by_rel[rel_key] = entry
        if include_signature:
            signature = (Path(entry.path).name.lower(), entry.size)
            self.by_signature.setdefault(signature, []).append(entry)


@dataclass
class _SourceEntry:
    path: str
    rel_key: str
    stat: Optional[os.stat_result]
    error: Optional[str] = None


class _VerificationMode(str, Enum):
    SIZE_ONLY = "size"
    SIZE_AND_MTIME = "size_mtime"
    ADAPTIVE_HASH = "adaptive"
    FULL_HASH = "hash"


_VERIFY_LABELS = {
    _VerificationMode.SIZE_ONLY: "Size only (fastest)",
    _VerificationMode.SIZE_AND_MTIME: "Size & modified time",
    _VerificationMode.ADAPTIVE_HASH: "Adaptive hash fallback",
    _VerificationMode.FULL_HASH: "Full SHA-256",
}


class MirrorVerifierTool:
    """Verify that files under one or more source folders exist in mirrors."""

    key = "mirror_verifier"
    title = "Mirror Verifier"
    description = (
        "Check that every file under a set of source directories has a duplicate "
        "in one or more mirror locations. Verification can be performed by size "
        "or by full SHA-256 checksum."
    )

    def __init__(self) -> None:
        self.ctx: Optional[AppContext] = None
        self._ui_mode = "standard"

        self.panel = None
        self.sources_list: Optional[Any] = None
        self.mirror_list: Optional[Any] = None
        self.verify_mode_var: Optional[tb.StringVar] = None
        self.follow_symlinks_var: Optional[tb.BooleanVar] = None
        self.ignore_structure_var: Optional[tb.BooleanVar] = None
        self.summary_var: Optional[tb.StringVar] = None
        self.results_tv = None
        self.scan_button = None
        self.cancel_button = None
        self.pause_button = None

        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self._pause_event.set()
        self._paused = False
        self._last_summary_message = "Ready."
        self._hash_logs: Dict[Path, Optional[_HashLogWriter]] = {}
        self._progress_logs: Dict[Path, Optional[_ProgressLog]] = {}

    # ------------------------------------------------------------------ UI --
    def make_panel(self, master, context: AppContext):
        import tkinter as tk
        from tkinter import filedialog

        self.ctx = context
        self._ui_mode = context.ui_mode

        root = tb.Frame(master)
        self.panel = root

        # Sources frame
        sources_frame = tb.Labelframe(root, text="Source directories", padding=8)
        sources_frame.pack(fill="both", expand=False, padx=8, pady=(10, 6))
        self.sources_list = tk.Listbox(sources_frame, height=5)
        self.sources_list.pack(fill="both", expand=True, padx=(0, 6), side="left")
        src_buttons = tb.Frame(sources_frame)
        src_buttons.pack(side="right", fill="y")
        tb.Button(src_buttons, text="Add…", command=lambda: self._add_path(self.sources_list, filedialog.askdirectory))\
            .pack(fill="x", pady=2)
        tb.Button(src_buttons, text="Remove", command=lambda: self._remove_selected(self.sources_list)).pack(fill="x", pady=2)
        tb.Button(src_buttons, text="Clear", command=lambda: self._clear_list(self.sources_list)).pack(fill="x", pady=2)

        # Mirror frame
        mirror_frame = tb.Labelframe(root, text="Mirror locations", padding=8)
        mirror_frame.pack(fill="both", expand=False, padx=8, pady=(0, 6))
        self.mirror_list = tk.Listbox(mirror_frame, height=5)
        self.mirror_list.pack(fill="both", expand=True, padx=(0, 6), side="left")
        mirror_buttons = tb.Frame(mirror_frame)
        mirror_buttons.pack(side="right", fill="y")
        tb.Button(mirror_buttons, text="Add…", command=lambda: self._add_path(self.mirror_list, filedialog.askdirectory))\
            .pack(fill="x", pady=2)
        tb.Button(mirror_buttons, text="Remove", command=lambda: self._remove_selected(self.mirror_list)).pack(fill="x", pady=2)
        tb.Button(mirror_buttons, text="Clear", command=lambda: self._clear_list(self.mirror_list)).pack(fill="x", pady=2)

        # Options
        options = tb.Labelframe(root, text="Options", padding=8)
        options.pack(fill="x", expand=False, padx=8, pady=(0, 6))
        self.verify_mode_var = tk.StringVar(value=_VERIFY_LABELS[_VerificationMode.SIZE_ONLY])
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
        verify_combo.set(_VERIFY_LABELS[_VerificationMode.SIZE_ONLY])
        tb.Checkbutton(options, text="Follow symbolic links", variable=self.follow_symlinks_var).pack(anchor="w", pady=(4, 0))
        tb.Checkbutton(
            options,
            text="Ignore folder structure (match by file name & size)",
            variable=self.ignore_structure_var,
        ).pack(anchor="w", pady=(4, 0))

        # Actions
        actions = tb.Frame(root)
        actions.pack(fill="x", padx=8, pady=(0, 6))
        self.scan_button = tb.Button(actions, text="Scan mirrors", bootstyle="success",
                                     command=self._start_scan)
        self.scan_button.pack(side="left")
        self.pause_button = tb.Button(actions, text="Pause", bootstyle="secondary",
                                      command=self._toggle_pause, state="disabled")
        self.pause_button.pack(side="left", padx=(6, 0))
        self.cancel_button = tb.Button(actions, text="Cancel", bootstyle="warning",
                                       command=self._cancel_scan, state="disabled")
        self.cancel_button.pack(side="left", padx=(6, 0))
        self.summary_var = tk.StringVar(value="Ready.")
        tb.Label(actions, textvariable=self.summary_var, bootstyle="secondary").pack(side="right")

        # Results
        results = tb.Labelframe(root, text="Results", padding=8)
        results.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        columns = ("status", "path", "detail")
        self.results_tv = tb.Treeview(results, columns=columns, show="headings")
        self.results_tv.heading("status", text="Status")
        self.results_tv.heading("path", text="Source relative path")
        self.results_tv.heading("detail", text="Details")
        self.results_tv.column("status", width=110, anchor="w")
        self.results_tv.column("path", width=320, anchor="w")
        self.results_tv.column("detail", anchor="w")
        self.results_tv.pack(fill="both", expand=True)

        style_manager = tb.Style()
        for status, style in _STATUS_TAGS.items():
            if not style:
                continue
            try:
                self.results_tv.tag_configure(status, bootstyle=style)
            except tk.TclError:
                color = getattr(getattr(style_manager, "colors", None), style, None)
                if color:
                    self.results_tv.tag_configure(status, foreground=color)

        return root

    # --------------------------------------------------------------- actions --
    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        # Treat provided targets as source directories
        if self.sources_list is None:
            return
        for target in targets or []:
            if target.exists():
                self.sources_list.insert("end", str(target))

        # Extra args: --mirror PATH
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
    def _iter_files(self, root: Path, follow_symlinks: bool):
        stack = [root]
        root_str = str(root)
        while stack:
            if not self._wait_for_resume():
                return
            current = stack.pop()
            if self._stop_event.is_set():
                return
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        if not self._wait_for_resume():
                            return
                        if self._stop_event.is_set():
                            return
                        try:
                            if entry.is_symlink() and not follow_symlinks:
                                continue
                            if entry.is_dir(follow_symlinks=follow_symlinks):
                                stack.append(Path(entry.path))
                            elif entry.is_file(follow_symlinks=follow_symlinks):
                                rel_key = os.path.relpath(entry.path, root_str)
                                if rel_key.startswith(".."):
                                    continue
                                if os.sep != "/":
                                    rel_key = rel_key.replace(os.sep, "/")
                                try:
                                    stat_result = entry.stat(follow_symlinks=follow_symlinks)
                                    yield _SourceEntry(entry.path, rel_key, stat_result)
                                except OSError as exc:
                                    yield _SourceEntry(entry.path, rel_key, None, str(exc))
                        except OSError:
                            continue
            except OSError:
                continue

    def _estimate_total_files(self, sources: List[str], follow_symlinks: bool) -> int:
        total = 0
        for src_str in sources:
            if not self._wait_for_resume():
                return total
            src_root = Path(src_str)
            if not src_root.is_dir():
                continue
            stack = [src_root]
            root_str = str(src_root)
            while stack:
                if not self._wait_for_resume():
                    return total
                if self._stop_event.is_set():
                    return total
                current = stack.pop()
                try:
                    with os.scandir(current) as it:
                        for entry in it:
                            if not self._wait_for_resume():
                                return total
                            if self._stop_event.is_set():
                                return total
                            try:
                                if entry.is_symlink() and not follow_symlinks:
                                    continue
                                if entry.is_dir(follow_symlinks=follow_symlinks):
                                    stack.append(Path(entry.path))
                                elif entry.is_file(follow_symlinks=follow_symlinks):
                                    rel_key = os.path.relpath(entry.path, root_str)
                                    if rel_key.startswith(".."):
                                        continue
                                    total += 1
                            except OSError:
                                continue
                except OSError:
                    continue
        return total

    def _get_hash_logger(self, root: Path) -> Optional[_HashLogWriter]:
        if root in self._hash_logs:
            return self._hash_logs[root]
        writer = _HashLogWriter(root)
        if not writer.available:
            self._hash_logs[root] = None
            return None
        self._hash_logs[root] = writer
        return writer

    def _record_hash(self, root: Path, file_path: Path, digest: str) -> None:
        if not digest:
            return
        logger = self._get_hash_logger(root)
        if logger is None:
            return
        try:
            relative = file_path.relative_to(root)
        except ValueError:
            relative = file_path
        logger.log(str(relative), digest)

    def _record_entry_hash(
        self,
        resolved_root: Path,
        entry: Optional[_IndexedFile],
        precomputed: Optional[str] = None,
    ) -> Optional[str]:
        if entry is None:
            return "Mirror entry metadata unavailable"
        digest = precomputed if precomputed is not None else entry.ensure_hash()
        if entry.error:
            return f"Mirror entry {entry.path} could not be hashed: {entry.error}"
        if not digest:
            return "Mirror entry hash could not be determined"
        self._record_hash(resolved_root, Path(entry.path), digest)
        return None

    def _close_hash_logs(self) -> None:
        for writer in self._hash_logs.values():
            if writer:
                writer.close()
        self._hash_logs.clear()

    def _prepare_progress_logs(self, sources: List[str]) -> Dict[Path, Optional[_ProgressLog]]:
        logs: Dict[Path, Optional[_ProgressLog]] = {}
        for src in sources:
            src_root = Path(src)
            log: Optional[_ProgressLog] = None
            try:
                log = _ProgressLog(src_root)
            except Exception:
                log = None
            logs[src_root] = log
        self._progress_logs = logs
        return logs

    def _get_progress_log(self, root: Path) -> Optional[_ProgressLog]:
        return self._progress_logs.get(root)

    def _record_progress(self, root: Path, rel: str, status: str, detail: str) -> None:
        log = self._get_progress_log(root)
        if not log:
            return
        try:
            log.record(rel, status, detail)
        except Exception:
            return

    def _replay_progress(self, logs: Dict[Path, Optional[_ProgressLog]]) -> Dict[str, int]:
        summary = {"total": 0, "matched": 0, "missing": 0, "mismatch": 0}
        for root, log in logs.items():
            if not log:
                continue
            counts = log.status_counts
            summary["total"] += log.total_processed
            summary["matched"] += counts.get("OK", 0)
            summary["missing"] += counts.get("MISSING", 0)
            summary["mismatch"] += counts.get("MISMATCH", 0)
            for rel, status, detail in log.iter_entries():
                display = f"{root.name}/{rel}"
                self._append_result(status, display, detail)
        return summary

    def _close_progress_logs(self, clear_completed: bool) -> None:
        for log in self._progress_logs.values():
            if not log:
                continue
            log.close()
            if clear_completed:
                log.clear_file()
        self._progress_logs.clear()

    def _ready_message(self, expected: int) -> str:
        if expected:
            return f"Preparing scan – 0/{expected} files queued"
        return "No source files found in selected directories."

    def _format_progress(self, display_path: str, processed: int, expected: int) -> str:
        if expected <= 0:
            expected = processed
        return f"Processing file {display_path} – on file {processed}/{expected}"

    def _resume_message(self, processed: int, expected: int) -> str:
        if expected > 0:
            return f"Resuming – processed {processed}/{expected} files so far"
        return f"Resuming – processed {processed} files so far"

    def _start_scan(self):
        if self._worker and self._worker.is_alive():
            Messagebox.show_info(
                message="A scan is already in progress. Cancel it before starting another.",
                title="Mirror Verifier",
            )
            return
        sources = self._listbox_values(self.sources_list)
        mirrors = self._listbox_values(self.mirror_list)
        if not sources:
            Messagebox.show_error(title="Mirror Verifier", message="Add at least one source directory.")
            return
        if not mirrors:
            Messagebox.show_error(title="Mirror Verifier", message="Add at least one mirror directory.")
            return

        # Validate paths
        missing_sources = [p for p in sources if not Path(p).exists()]
        if missing_sources:
            Messagebox.show_error(title="Mirror Verifier", message=f"Source missing: {missing_sources[0]}")
            return
        missing_mirrors = [p for p in mirrors if not Path(p).exists()]
        if missing_mirrors:
            Messagebox.show_error(title="Mirror Verifier", message=f"Mirror missing: {missing_mirrors[0]}")
            return

        self.results_tv.delete(*self.results_tv.get_children())
        self._set_summary("Scanning…")
        self.scan_button.configure(state="disabled")
        if self.pause_button:
            self.pause_button.configure(state="normal", text="Pause", bootstyle="secondary")
        self.cancel_button.configure(state="normal")
        self._stop_event.clear()
        self._pause_event.set()
        self._paused = False

        verify_mode = self._selected_mode()
        follow_symlinks = bool(self.follow_symlinks_var.get() if self.follow_symlinks_var else False)
        ignore_structure = bool(self.ignore_structure_var.get() if self.ignore_structure_var else False)

        self._worker = threading.Thread(
            target=self._scan_worker,
            args=(sources, mirrors, verify_mode, follow_symlinks, ignore_structure),
            daemon=True,
        )
        self._worker.start()

    def _cancel_scan(self, wait: bool = False):
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._pause_event.set()
            self._paused = False
            if wait:
                self._worker.join(timeout=5)
        self.scan_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        if self.pause_button:
            self.pause_button.configure(state="disabled", text="Pause", bootstyle="secondary")

    def _toggle_pause(self):
        if not self._worker or not self._worker.is_alive():
            return
        if not self._paused:
            self._paused = True
            self._pause_event.clear()
            if self.pause_button:
                self.pause_button.configure(text="Resume", bootstyle="info")
            self._show_paused_summary()
        else:
            self._paused = False
            self._pause_event.set()
            if self.pause_button:
                self.pause_button.configure(text="Pause", bootstyle="secondary")
            self._set_summary(self._last_summary_message)

    def _scan_worker(
        self,
        sources: List[str],
        mirrors: List[str],
        verify_mode: _VerificationMode,
        follow_symlinks: bool,
        ignore_structure: bool,
    ):
        summary = {
            "total": 0,
            "matched": 0,
            "missing": 0,
            "mismatch": 0,
            "expected": 0,
        }
        aborted = False
        self._hash_logs = {}
        progress_logs = self._prepare_progress_logs(sources)
        resumed = self._replay_progress(progress_logs)
        summary["total"] += resumed.get("total", 0)
        summary["matched"] += resumed.get("matched", 0)
        summary["missing"] += resumed.get("missing", 0)
        summary["mismatch"] += resumed.get("mismatch", 0)

        try:
            mirror_roots = [Path(mirror) for mirror in mirrors]
            resolved_mirrors: Dict[Path, Path] = {
                mirror_root: self._resolve_path(mirror_root) for mirror_root in mirror_roots
            }

            self._set_summary("Counting source files…")
            summary["expected"] = self._estimate_total_files(sources, follow_symlinks)
            if self._stop_event.is_set():
                aborted = True
                self._finalise_summary(summary, aborted=True)
                return

            if summary["total"] > summary["expected"]:
                summary["expected"] = summary["total"]
            self._set_summary(self._ready_message(summary["expected"]))
            if summary["total"]:
                self._set_summary(self._resume_message(summary["total"], summary["expected"]))

            mirror_indexes: Dict[Path, _MirrorIndex] = {}
            need_index = ignore_structure
            if need_index:
                prepared = self._prepare_mirror_indexes(
                    mirror_roots,
                    resolved_mirrors,
                    follow_symlinks,
                    include_signatures=ignore_structure,
                )
                if prepared is None:
                    aborted = True
                    self._finalise_summary(summary, aborted=True)
                    return
                mirror_indexes = prepared

            dest_cache: Dict[str, _IndexedFile] = {}

            for src_str in sources:
                if not self._wait_for_resume():
                    aborted = True
                    self._finalise_summary(summary, aborted=True)
                    return
                src_root = Path(src_str)
                if not src_root.is_dir():
                    self._append_result("SOURCE", src_str, "Source is not a directory – skipped")
                    continue
                progress_log = self._get_progress_log(src_root)

                for entry in self._iter_files(src_root, follow_symlinks):
                    if self._stop_event.is_set():
                        aborted = True
                        self._finalise_summary(summary, aborted=True)
                        return
                    if not self._wait_for_resume():
                        aborted = True
                        self._finalise_summary(summary, aborted=True)
                        return
                    if progress_log and progress_log.is_processed(entry.rel_key):
                        continue
                    summary["total"] += 1
                    rel = entry.rel_key
                    display_path = f"{src_root.name}/{rel}"
                    expected = summary["expected"] or summary["total"]
                    self._set_summary(
                        self._format_progress(display_path, summary["total"], expected)
                    )
                    source = Path(entry.path)
                    try:
                        status, detail = self._check_in_mirrors(
                            source,
                            rel,
                            entry.stat,
                            entry.error,
                            mirror_roots,
                            resolved_mirrors,
                            verify_mode,
                            mirror_indexes,
                            dest_cache,
                            ignore_structure,
                            follow_symlinks,
                        )
                    except _ScanInterrupted:
                        aborted = True
                        self._finalise_summary(summary, aborted=True)
                        return
                    if status == "OK":
                        summary["matched"] += 1
                    elif status == "MISSING":
                        summary["missing"] += 1
                    else:
                        summary["mismatch"] += 1
                    self._record_progress(src_root, rel, status, detail)
                    self._append_result(status, display_path, detail)

            self._finalise_summary(summary, aborted=False)
        finally:
            self._close_hash_logs()
            self._close_progress_logs(clear_completed=not aborted)

    def _check_in_mirrors(
        self,
        source: Path,
        rel_key: str,
        src_stat_result: Optional[os.stat_result],
        src_error: Optional[str],
        mirror_roots: List[Path],
        resolved_mirrors: Dict[Path, Path],
        verify_mode: _VerificationMode,
        mirror_indexes: Dict[Path, _MirrorIndex],
        dest_cache: Dict[str, _IndexedFile],
        ignore_structure: bool,
        follow_symlinks: bool,
    ) -> Tuple[str, str]:
        if src_error:
            return "MISMATCH", f"Cannot read source file metadata: {src_error}"
        src_stat = src_stat_result or None
        if src_stat is None:
            try:
                src_stat = source.stat()
            except OSError as exc:
                return "MISMATCH", f"Cannot read source file metadata: {exc}"
        src_size = src_stat.st_size
        src_mtime = src_stat.st_mtime
        src_suffix = source.suffix.lower()
        src_hash: Optional[str] = None
        rel_path = Path(rel_key)
        for mirror_root in mirror_roots:
            if not self._wait_for_resume():
                raise _ScanInterrupted()
            if self._stop_event.is_set():
                raise _ScanInterrupted()
            resolved_root = resolved_mirrors.get(mirror_root, mirror_root)
            index = mirror_indexes.get(resolved_root)
            indexed_entry: Optional[_IndexedFile] = None
            dest_entry: Optional[_IndexedFile] = None
            candidate: Path
            dest_size: int
            dest_mtime: float

            if index and rel_key in index.by_rel:
                indexed_entry = index.by_rel[rel_key]
                if indexed_entry.error:
                    return "MISMATCH", f"Mirror entry {indexed_entry.path} could not be read: {indexed_entry.error}"
                dest_entry = indexed_entry
                candidate = Path(dest_entry.path)
                dest_size = dest_entry.size
                dest_mtime = dest_entry.mtime
            elif ignore_structure and index:
                signature = (source.name.lower(), src_size)
                candidates = index.by_signature.get(signature, [])
                if not candidates:
                    continue
                result = self._evaluate_candidates(
                    source,
                    candidates,
                    verify_mode,
                    src_suffix,
                    src_size,
                    src_mtime,
                    src_hash,
                    resolved_root,
                )
                if result:
                    status, detail, src_hash = result
                    return status, detail
                continue
            else:
                candidate = resolved_root / rel_path
                dest_entry = self._get_dest_entry(candidate, dest_cache, follow_symlinks)
                if dest_entry.error:
                    if "not found" in dest_entry.error:
                        continue
                    return "MISMATCH", dest_entry.error
                dest_size = dest_entry.size
                dest_mtime = dest_entry.mtime
                candidate = Path(dest_entry.path)

            target_entry = dest_entry or indexed_entry
            if target_entry is None:
                return "MISMATCH", "Mirror entry metadata unavailable"

            if candidate.suffix.lower() != src_suffix:
                return "MISMATCH", f"File extension mismatch against {candidate}"
            if dest_size != src_size:
                return "MISMATCH", f"Size mismatch against {candidate}"

            mtimes_match = _mtimes_close(dest_mtime, src_mtime)
            if not self._wait_for_resume():
                raise _ScanInterrupted()
            if verify_mode == _VerificationMode.SIZE_ONLY:
                error = self._record_entry_hash(resolved_root, target_entry)
                if error:
                    return "MISMATCH", error
                return "OK", f"Size match in {candidate}"
            if verify_mode == _VerificationMode.SIZE_AND_MTIME:
                if mtimes_match:
                    error = self._record_entry_hash(resolved_root, target_entry)
                    if error:
                        return "MISMATCH", error
                    return "OK", f"Size and timestamp match in {candidate}"
                return "MISMATCH", f"Modified time mismatch against {candidate}"
            if verify_mode == _VerificationMode.ADAPTIVE_HASH and mtimes_match:
                error = self._record_entry_hash(resolved_root, target_entry)
                if error:
                    return "MISMATCH", error
                return "OK", f"Metadata match in {candidate}"

            if verify_mode in (_VerificationMode.ADAPTIVE_HASH, _VerificationMode.FULL_HASH):
                try:
                    if not self._wait_for_resume():
                        raise _ScanInterrupted()
                    if src_hash is None:
                        src_hash = _hash_file(source)
                    if not self._wait_for_resume():
                        raise _ScanInterrupted()
                    dest_hash = target_entry.ensure_hash()
                    if target_entry.error:
                        return "MISMATCH", f"Mirror entry {target_entry.path} could not be hashed: {target_entry.error}"
                except OSError as exc:
                    return "MISMATCH", f"Cannot hash file: {exc}"
                if dest_hash != src_hash:
                    return "MISMATCH", f"Hash mismatch against {candidate}"
                error = self._record_entry_hash(resolved_root, target_entry, dest_hash)
                if error:
                    return "MISMATCH", error
                return "OK", f"Hash verified in {candidate}"

        return "MISSING", "No mirror file found"

    def _evaluate_candidates(
        self,
        source: Path,
        candidates: List[_IndexedFile],
        verify_mode: _VerificationMode,
        src_suffix: str,
        src_size: int,
        src_mtime: float,
        src_hash: Optional[str],
        resolved_root: Path,
    ) -> Optional[Tuple[str, str, Optional[str]]]:
        last_error: Optional[str] = None
        for entry in candidates:
            if not self._wait_for_resume():
                raise _ScanInterrupted()
            if self._stop_event.is_set():
                raise _ScanInterrupted()
            if entry.error:
                last_error = f"Mirror entry {entry.path} could not be read: {entry.error}"
                continue
            candidate = Path(entry.path)
            if candidate.suffix.lower() != src_suffix:
                continue
            if entry.size != src_size:
                continue
            mtimes_match = _mtimes_close(entry.mtime, src_mtime)
            if verify_mode == _VerificationMode.SIZE_ONLY:
                error = self._record_entry_hash(resolved_root, entry)
                if error:
                    last_error = error
                    continue
                return "OK", f"Size match in {candidate}", src_hash
            if verify_mode == _VerificationMode.SIZE_AND_MTIME:
                if mtimes_match:
                    error = self._record_entry_hash(resolved_root, entry)
                    if error:
                        last_error = error
                        continue
                    return "OK", f"Size and timestamp match in {candidate}", src_hash
                continue
            if verify_mode == _VerificationMode.ADAPTIVE_HASH and mtimes_match:
                error = self._record_entry_hash(resolved_root, entry)
                if error:
                    last_error = error
                    continue
                return "OK", f"Metadata match in {candidate}", src_hash
            if verify_mode in (_VerificationMode.ADAPTIVE_HASH, _VerificationMode.FULL_HASH):
                try:
                    if not self._wait_for_resume():
                        raise _ScanInterrupted()
                    if src_hash is None:
                        src_hash = _hash_file(source)
                    if not self._wait_for_resume():
                        raise _ScanInterrupted()
                    dest_hash = entry.ensure_hash()
                    if entry.error:
                        last_error = f"Mirror entry {entry.path} could not be hashed: {entry.error}"
                        continue
                except OSError as exc:
                    last_error = f"Cannot hash file: {exc}"
                    continue
                if dest_hash != src_hash:
                    continue
                error = self._record_entry_hash(resolved_root, entry, dest_hash)
                if error:
                    last_error = error
                    continue
                return "OK", f"Hash verified in {candidate}", src_hash
        if last_error:
            return "MISMATCH", last_error, src_hash
        return None

    def _append_result(self, status: str, path: str, detail: str):
        if not self.results_tv:
            return

        def _insert():
            self.results_tv.insert("", "end", values=(status, path, detail), tags=(status,))

        self.results_tv.after(0, _insert)

    def _finalise_summary(self, summary, aborted: bool):
        if not self.summary_var:
            return

        def _update():
            expected = summary.get("expected") or summary["total"]
            if aborted:
                message = (
                    f"Aborted – processed {summary['total']}/{expected} files "
                    f"({summary['matched']} matched, {summary['missing']} missing, {summary['mismatch']} mismatches)"
                )
            else:
                message = (
                    f"Completed – processed {summary['total']} of {expected} files "
                    f"({summary['matched']} matched, {summary['missing']} missing, {summary['mismatch']} mismatches)"
                )
            self._last_summary_message = message
            self.summary_var.set(message)
            self.scan_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            if self.pause_button:
                self.pause_button.configure(state="disabled", text="Pause", bootstyle="secondary")
            self._paused = False
            self._pause_event.set()

        widget = self.results_tv or self.scan_button
        if widget:
            widget.after(0, _update)

    def _listbox_values(self, listbox) -> List[str]:
        if not listbox:
            return []
        return [listbox.get(idx) for idx in range(listbox.size())]

    def _get_dest_entry(
        self,
        candidate: Path,
        cache: Dict[str, _IndexedFile],
        follow_symlinks: bool,
    ) -> _IndexedFile:
        key = str(candidate)
        entry = cache.get(key)
        if entry is not None:
            return entry
        try:
            dest_stat = candidate.stat(follow_symlinks=follow_symlinks)
        except FileNotFoundError:
            entry = _IndexedFile(path=key, size=0, mtime=0.0, error=f"Mirror entry {candidate} not found")
        except OSError as exc:
            entry = _IndexedFile(path=key, size=0, mtime=0.0, error=f"Cannot read mirror file metadata {candidate}: {exc}")
        else:
            if not stat.S_ISREG(dest_stat.st_mode):
                entry = _IndexedFile(
                    path=key,
                    size=dest_stat.st_size,
                    mtime=dest_stat.st_mtime,
                    error=f"Mirror entry exists but is not a file: {candidate}",
                )
            else:
                entry = _IndexedFile(path=key, size=dest_stat.st_size, mtime=dest_stat.st_mtime)
        cache[key] = entry
        return entry

    def _selected_mode(self) -> _VerificationMode:
        if not self.verify_mode_var:
            return _VerificationMode.SIZE_ONLY
        selected = self.verify_mode_var.get()
        for mode, label in _VERIFY_LABELS.items():
            if selected == label or selected == mode.value:
                return mode
        return _VerificationMode.SIZE_ONLY

    # ----------------------------------------------------- Mirror indexing --
    def _resolve_path(self, path: Path) -> Path:
        try:
            return path.resolve()
        except OSError:
            return path

    def _prepare_mirror_indexes(
        self,
        mirror_roots: List[Path],
        resolved_mirrors: Dict[Path, Path],
        follow_symlinks: bool,
        include_signatures: bool,
    ) -> Optional[Dict[Path, _MirrorIndex]]:
        indexes: Dict[Path, _MirrorIndex] = {}
        total = len(mirror_roots)
        for idx, mirror_root in enumerate(mirror_roots, start=1):
            if not self._wait_for_resume():
                return None
            if self._stop_event.is_set():
                return None
            self._set_summary(f"Indexing mirror {idx}/{total}: {mirror_root}")
            index = _MirrorIndex()
            try:
                stack = [mirror_root]
                root_str = str(mirror_root)
                while stack:
                    current = stack.pop()
                    if not self._wait_for_resume():
                        return None
                    if self._stop_event.is_set():
                        return None
                    try:
                        with os.scandir(current) as it:
                            for entry in it:
                                if not self._wait_for_resume():
                                    return None
                                if self._stop_event.is_set():
                                    return None
                                try:
                                    if entry.is_symlink() and not follow_symlinks:
                                        continue
                                    if entry.is_dir(follow_symlinks=follow_symlinks):
                                        stack.append(Path(entry.path))
                                        continue
                                    if entry.is_file(follow_symlinks=follow_symlinks):
                                        rel_key = os.path.relpath(entry.path, root_str)
                                        if rel_key.startswith(".."):
                                            continue
                                        if os.sep != "/":
                                            rel_key = rel_key.replace(os.sep, "/")
                                        try:
                                            stat = entry.stat(follow_symlinks=follow_symlinks)
                                            indexed = _IndexedFile(
                                                path=entry.path,
                                                size=stat.st_size,
                                                mtime=stat.st_mtime,
                                            )
                                        except OSError as exc:
                                            indexed = _IndexedFile(
                                                path=entry.path,
                                                size=0,
                                                mtime=0.0,
                                                error=str(exc),
                                            )
                                        index.add(rel_key, indexed, include_signatures)
                                except OSError:
                                    continue
                    except OSError:
                        index = _MirrorIndex()
                        break
            except OSError:
                # If mirror cannot be read, leave index empty. Verification will report missing entries.
                index = _MirrorIndex()
            resolved_root = resolved_mirrors.get(mirror_root, mirror_root)
            indexes[resolved_root] = index
        self._set_summary("Scanning…")
        return indexes

    def _set_summary(self, message: str):
        if not self.summary_var:
            return
        self._last_summary_message = message

        def _update():
            self.summary_var.set(message)

        widget = self.results_tv or self.scan_button
        if widget:
            widget.after(0, _update)

    def _show_paused_summary(self):
        if not self.summary_var:
            return

        def _update():
            self.summary_var.set(f"Paused – {self._last_summary_message}")

        widget = self.results_tv or self.scan_button
        if widget:
            widget.after(0, _update)

    def _wait_for_resume(self) -> bool:
        if self._stop_event.is_set():
            return False
        if self._pause_event.is_set():
            return True
        while not self._pause_event.wait(0.1):
            if self._stop_event.is_set():
                return False
        return not self._stop_event.is_set()


PLUGIN = MirrorVerifierTool()
