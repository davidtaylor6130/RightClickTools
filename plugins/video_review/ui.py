"""Tkinter UI for the Video Review & Log plugin."""
from __future__ import annotations

import queue
import threading
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

import tkinter as tk
from tkinter import filedialog, simpledialog

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from . import scanning
from .export_excel import export_to_excel
from .export_txt import write_rejected_list
from .model import VideoItem, VideoReviewStore


class VideoReviewFrame(tb.Frame):
    """Main frame for the Video Review & Log plugin."""

    def __init__(self, master: tk.Misc, app: Optional[object] = None):
        super().__init__(master)
        self.app = app
        self.store = VideoReviewStore()
        self.directory_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="")
        self.progress_var = tk.StringVar(value="")

        self._progress_queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._scan_thread: Optional[threading.Thread] = None
        self._scan_cancel = threading.Event()
        self._scan_lock = threading.Lock()
        self._selected_iid: Optional[str] = None

        self._build_ui()
        self._poll_progress_queue()

    # ------------------------------------------------------------------ UI
    def _build_ui(self) -> None:
        header = tb.Frame(self)
        header.pack(fill="x", pady=(0, 6))

        self.select_btn = tb.Button(header, text="Select Directory", command=self._select_directory)
        self.select_btn.pack(side="left")

        entry = tb.Entry(header, textvariable=self.directory_var, state="readonly")
        entry.pack(side="left", fill="x", expand=True, padx=8)

        self.scan_btn = tb.Button(header, text="Scan", bootstyle="primary", command=self._start_scan)
        self.scan_btn.pack(side="left")

        progress_frame = tb.Frame(self)
        progress_frame.pack(fill="x", pady=(0, 6))
        self.progress = tb.Progressbar(progress_frame, mode="indeterminate")
        self.progress_label = tb.Label(progress_frame, textvariable=self.progress_var, bootstyle="secondary")

        main_split = tb.Panedwindow(self, orient="horizontal")
        main_split.pack(fill="both", expand=True)

        # Table area
        table_frame = tb.Frame(main_split)
        self.tree = tb.Treeview(
            table_frame,
            columns=("index", "filename", "rel_path", "duration", "status", "notes"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("index", text="#", anchor="w", command=lambda: self._sort_by("index"))
        self.tree.heading("filename", text="Filename", anchor="w", command=lambda: self._sort_by("filename"))
        self.tree.heading("rel_path", text="Relative Path", anchor="w", command=lambda: self._sort_by("rel_path"))
        self.tree.heading("duration", text="Duration", anchor="center", command=lambda: self._sort_by("duration"))
        self.tree.heading("status", text="Status", anchor="center", command=lambda: self._sort_by("status"))
        self.tree.heading("notes", text="Notes", anchor="w", command=lambda: self._sort_by("notes"))

        self.tree.column("index", width=60, stretch=False, anchor="w")
        self.tree.column("filename", width=220, anchor="w")
        self.tree.column("rel_path", width=320, anchor="w")
        self.tree.column("duration", width=80, anchor="center")
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("notes", width=260, anchor="w")

        y_scroll = tb.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        x_scroll = tb.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)

        self.tree.tag_configure("approved", foreground="#1a7f2e")
        self.tree.tag_configure("rejected", foreground="#a8232a")
        self.tree.tag_configure("pending", foreground="")

        self.tree.bind("<<TreeviewSelect>>", lambda _: self._on_select())
        self.tree.bind("<Double-1>", lambda _: self._focus_reason())
        self.tree.bind("<Key>", self._on_tree_key)

        self.tree.pack(fill="both", expand=True, side="top")
        y_scroll.pack(side="right", fill="y")
        x_scroll.pack(side="bottom", fill="x")

        table_frame.pack(fill="both", expand=True)
        main_split.add(table_frame, weight=3)

        # Inspector
        inspector = tb.Labelframe(main_split, text="Inspector", padding=8)
        self.meta_name = tk.StringVar(value="—")
        self.meta_size = tk.StringVar(value="—")
        self.meta_mtime = tk.StringVar(value="—")

        meta_grid = tb.Frame(inspector)
        meta_grid.pack(fill="x")
        tb.Label(meta_grid, text="Filename:", bootstyle="secondary").grid(row=0, column=0, sticky="w")
        tb.Label(meta_grid, textvariable=self.meta_name, wraplength=220).grid(row=0, column=1, sticky="w", padx=(6, 0))
        tb.Label(meta_grid, text="Size (MB):", bootstyle="secondary").grid(row=1, column=0, sticky="w", pady=(4, 0))
        tb.Label(meta_grid, textvariable=self.meta_size).grid(row=1, column=1, sticky="w", padx=(6, 0), pady=(4, 0))
        tb.Label(meta_grid, text="Modified:", bootstyle="secondary").grid(row=2, column=0, sticky="w", pady=(4, 0))
        tb.Label(meta_grid, textvariable=self.meta_mtime, wraplength=220).grid(row=2, column=1, sticky="w", padx=(6, 0), pady=(4, 0))

        button_row = tb.Frame(inspector)
        button_row.pack(fill="x", pady=(12, 6))
        self.approve_btn = tb.Button(button_row, text="Approve", bootstyle="success", command=self._approve_selected)
        self.approve_btn.pack(side="left", padx=(0, 6))
        self.reject_btn = tb.Button(button_row, text="Reject", bootstyle="danger", command=self._reject_selected)
        self.reject_btn.pack(side="left", padx=(0, 6))
        self.undo_btn = tb.Button(button_row, text="Undo", bootstyle="secondary", command=self._undo_selected)
        self.undo_btn.pack(side="left")

        reason_frame = tb.Frame(inspector)
        reason_frame.pack(fill="both", expand=True)
        tb.Label(reason_frame, text="Reason / Notes:", bootstyle="secondary").pack(anchor="w")
        self.reason_text = tk.Text(reason_frame, height=6, wrap="word", state="disabled")
        self.reason_text.pack(fill="both", expand=True, pady=(4, 0))
        self.reason_text.bind("<KeyRelease>", self._on_reason_edited)

        inspector.pack(fill="both", expand=True)
        main_split.add(inspector, weight=2)

        # Footer actions
        footer = tb.Frame(self)
        footer.pack(fill="x", pady=(6, 0))
        self.export_btn = tb.Button(footer, text="Export to Excel…", command=self._export_excel)
        self.export_btn.pack(side="left")
        self.rejected_btn = tb.Button(footer, text="Write Rejected .txt", command=self._export_rejected)
        self.rejected_btn.pack(side="left", padx=(6, 0))
        self.approve_all_btn = tb.Button(footer, text="Approve All Visible", bootstyle="success", command=self._approve_all_visible)
        self.approve_all_btn.pack(side="right")
        self.reject_all_btn = tb.Button(footer, text="Reject All Visible (with reason…)", bootstyle="danger", command=self._reject_all_visible)
        self.reject_all_btn.pack(side="right", padx=(0, 6))

        status_bar = tb.Frame(self)
        status_bar.pack(fill="x", pady=(4, 0))
        tb.Label(status_bar, textvariable=self.status_var, bootstyle="secondary").pack(side="left")
        self._update_counts()

    # ---------------------------------------------------------------- Events
    def _poll_progress_queue(self) -> None:
        try:
            while True:
                event = self._progress_queue.get_nowait()
                kind = event[0]
                if kind == "progress":
                    count = event[1]
                    rel_path = event[2]
                    if rel_path:
                        self.progress_var.set(f"Found {count} videos… {rel_path}")
                    else:
                        self.progress_var.set(f"Found {count} videos…")
                elif kind == "done":
                    items = event[1]
                    self._finish_scan(items)
                elif kind == "error":
                    message = event[1]
                    self._finish_scan([])
                    Messagebox.show_error(message=message, title="Scan error")
        except queue.Empty:
            pass
        finally:
            self.after(150, self._poll_progress_queue)

    def _select_directory(self) -> None:
        directory = filedialog.askdirectory()
        if directory:
            self.directory_var.set(directory)

    def _start_scan(self) -> None:
        directory = self.directory_var.get()
        if not directory:
            Messagebox.show_info(message="Select a directory first.", title="Video Review")
            return
        path = Path(directory)
        if not path.exists():
            Messagebox.show_error(message="Selected directory does not exist.", title="Video Review")
            return
        with self._scan_lock:
            if self._scan_thread and self._scan_thread.is_alive():
                Messagebox.show_info(message="A scan is already running.", title="Video Review")
                return
            self._scan_cancel = threading.Event()
            self._scan_thread = threading.Thread(
                target=self._scan_worker,
                args=(path,),
                daemon=True,
            )
            self._scan_thread.start()
        self.progress.pack(fill="x")
        self.progress_label.pack(anchor="w")
        self.progress.start(10)
        self.progress_var.set("Scanning…")
        self.scan_btn.configure(state="disabled")

    def _scan_worker(self, path: Path) -> None:
        try:
            def progress(count: int, rel_path: Optional[str]) -> None:
                self._progress_queue.put(("progress", count, rel_path))

            items = scanning.scan_directory(path, progress=progress, should_stop=self._scan_cancel.is_set)
            self._progress_queue.put(("done", items))
        except Exception as exc:  # pragma: no cover - defensive
            self._progress_queue.put(("error", str(exc)))
        finally:
            self.scan_btn.after(0, lambda: self.scan_btn.configure(state="normal"))
            self.progress.after(0, self.progress.stop)
            self.progress.after(0, lambda: self.progress.pack_forget())
            self.progress_label.after(0, lambda: self.progress_label.pack_forget())
            self.progress_var.set("")

    def _finish_scan(self, items: Iterable[VideoItem]) -> None:
        selected = self._selected_iid
        self.store.reset(items)
        self._refresh_tree()
        if selected and self.store.get(selected):
            self._select_iid(selected)
        else:
            self._select_first()
        self.progress.stop()
        self.progress.pack_forget()
        self.progress_label.pack_forget()
        self.scan_btn.configure(state="normal")
        self._update_counts()

    def _sort_by(self, key: str) -> None:
        self.store.toggle_sort(key)
        sorted_items = self.store.sorted_items()
        self.store.set_order([item.abs_path for item in sorted_items])
        self._refresh_tree()
        if self._selected_iid and self.store.get(self._selected_iid):
            self._select_iid(self._selected_iid)

    def _refresh_tree(self) -> None:
        existing_selection = self._selected_iid
        self.tree.delete(*self.tree.get_children(""))
        for item in self.store.items():
            display_values = self._item_values(item)
            tags = (item.status,)
            self.tree.insert("", "end", iid=item.abs_path, values=display_values, tags=tags)
        if existing_selection and self.store.get(existing_selection):
            self._select_iid(existing_selection)
        else:
            self._selected_iid = None
        self._update_counts()

    def _item_values(self, item: VideoItem) -> tuple:
        return (
            item.index,
            item.filename,
            item.rel_path,
            self._format_duration(item.duration_seconds),
            self._status_text(item.status),
            item.note,
        )

    def _status_text(self, status: str) -> str:
        if status == "approved":
            return "✓ Approved"
        if status == "rejected":
            return "✗ Rejected"
        return ""

    def _format_duration(self, duration: Optional[int]) -> str:
        if duration is None or duration < 0:
            return "--"
        minutes, seconds = divmod(duration, 60)
        return f"{int(minutes):02d}:{int(seconds):02d}"

    def _on_select(self) -> None:
        sel = self.tree.selection()
        if not sel:
            self._selected_iid = None
            self._clear_inspector()
            return
        iid = sel[0]
        self._selected_iid = iid
        item = self.store.get(iid)
        if item:
            self._update_inspector(item)

    def _select_first(self) -> None:
        children = self.tree.get_children("")
        if children:
            self._select_iid(children[0])

    def _select_iid(self, iid: str) -> None:
        self.tree.selection_set((iid,))
        self.tree.see(iid)
        self._selected_iid = iid
        item = self.store.get(iid)
        if item:
            self._update_inspector(item)

    def _clear_inspector(self) -> None:
        self.meta_name.set("—")
        self.meta_size.set("—")
        self.meta_mtime.set("—")
        self._set_reason_text("", editable=False)

    def _update_inspector(self, item: VideoItem) -> None:
        self.meta_name.set(item.filename)
        size_mb = item.size_bytes / (1024 * 1024)
        self.meta_size.set(f"{size_mb:.2f}")
        self.meta_mtime.set(datetime.fromtimestamp(item.mtime).strftime("%Y-%m-%d %H:%M:%S"))
        self._set_reason_text(item.note, editable=item.status == "rejected")

    def _set_reason_text(self, text: str, editable: bool) -> None:
        self.reason_text.configure(state="normal")
        self.reason_text.delete("1.0", "end")
        if text:
            self.reason_text.insert("1.0", text)
        state = "normal" if editable else "disabled"
        self.reason_text.configure(state=state)

    def _reason_text_value(self) -> str:
        return self.reason_text.get("1.0", "end").strip()

    def _approve_selected(self, *_args) -> None:
        item = self._current_item()
        if not item:
            return
        self.store.update_status(item.abs_path, "approved")
        self._update_row(item.abs_path)
        self._update_counts()

    def _reject_selected(self, *_args) -> None:
        item = self._current_item()
        if not item:
            return
        note = self._reason_text_value()
        if item.status != "rejected":
            if not note:
                note = simpledialog.askstring("Rejection Reason", "Provide a reason for rejection:", parent=self)
                if note is None:
                    return
                note = note.strip()
            if not note:
                Messagebox.show_info(message="A rejection reason is required.", title="Video Review")
                return
        self.store.update_status(item.abs_path, "rejected", note)
        self._update_row(item.abs_path)
        self._set_reason_text(note, editable=True)
        self.reason_text.focus_set()
        self._update_counts()

    def _undo_selected(self, *_args) -> None:
        item = self._current_item()
        if not item:
            return
        self.store.update_status(item.abs_path, "pending")
        self._update_row(item.abs_path)
        self._set_reason_text("", editable=False)
        self._update_counts()

    def _approve_all_visible(self) -> None:
        for iid in self.tree.get_children(""):
            self.store.update_status(iid, "approved")
            self._update_row(iid)
        self._update_counts()

    def _reject_all_visible(self) -> None:
        reason = simpledialog.askstring("Reject All Visible", "Provide a reason for rejecting all visible items:", parent=self)
        if reason is None:
            return
        reason = reason.strip()
        if not reason:
            Messagebox.show_info(message="A reason is required to reject all items.", title="Video Review")
            return
        for iid in self.tree.get_children(""):
            self.store.update_status(iid, "rejected", reason)
            self._update_row(iid)
        self._update_counts()
        if self._selected_iid and self.store.get(self._selected_iid):
            self._set_reason_text(self.store.get(self._selected_iid).note, editable=True)

    def _export_excel(self) -> None:
        directory = self.directory_var.get()
        if not directory:
            Messagebox.show_info(message="Select a directory before exporting.", title="Video Review")
            return
        initial = Path(directory) / "video_review_log.xlsx"
        filename = filedialog.asksaveasfilename(
            title="Save Excel Log",
            defaultextension=".xlsx",
            filetypes=(("Excel Workbook", "*.xlsx"),),
            initialfile=initial.name,
            initialdir=initial.parent,
        )
        if not filename:
            return
        try:
            export_to_excel(Path(filename), self.store.items())
            Messagebox.show_info(message="Excel log exported successfully.", title="Video Review")
        except PermissionError:
            Messagebox.show_error(message="Unable to write the Excel file. Close it if it's already open and try again.", title="Video Review")
        except Exception as exc:
            Messagebox.show_error(message=f"Failed to export Excel log: {exc}", title="Video Review")

    def _export_rejected(self) -> None:
        directory = self.directory_var.get()
        if not directory:
            Messagebox.show_info(message="Select a directory before exporting.", title="Video Review")
            return
        initial = Path(directory) / "rejected_videos.txt"
        filename = filedialog.asksaveasfilename(
            title="Save Rejected List",
            defaultextension=".txt",
            filetypes=(("Text Files", "*.txt"),),
            initialfile=initial.name,
            initialdir=initial.parent,
        )
        if not filename:
            return
        try:
            write_rejected_list(Path(filename), self.store.items())
            Messagebox.show_info(message="Rejected list written successfully.", title="Video Review")
        except PermissionError:
            Messagebox.show_error(message="Unable to write the file. Close it if it's already open and try again.", title="Video Review")
        except Exception as exc:
            Messagebox.show_error(message=f"Failed to write rejected list: {exc}", title="Video Review")

    def _update_row(self, iid: str) -> None:
        item = self.store.get(iid)
        if not item:
            return
        self.tree.item(iid, values=self._item_values(item), tags=(item.status,))
        if self._selected_iid == iid:
            self._update_inspector(item)

    def _current_item(self) -> Optional[VideoItem]:
        if not self._selected_iid:
            return None
        return self.store.get(self._selected_iid)

    def _update_counts(self) -> None:
        counts = self.store.counts()
        self.status_var.set(
            f"Total: {counts['total']}  |  Approved: {counts['approved']}  |  Rejected: {counts['rejected']}  |  Pending: {counts['pending']}"
        )

    def _on_tree_key(self, event: tk.Event) -> str | None:
        if event.keysym.lower() == "a":
            self._approve_selected()
            return "break"
        if event.keysym.lower() == "r":
            self._reject_selected()
            return "break"
        if event.keysym.lower() == "u" or event.keysym == "Delete":
            self._undo_selected()
            return "break"
        return None

    def _on_reason_edited(self, _event) -> None:
        if self.reason_text.cget("state") == "disabled":
            return
        item = self._current_item()
        if not item or item.status != "rejected":
            return
        note = self._reason_text_value()
        self.store.update_note(item.abs_path, note)
        self.tree.set(item.abs_path, "notes", note)

    def _focus_reason(self) -> None:
        if self.reason_text.cget("state") == "normal":
            self.reason_text.focus_set()

    # ---------------------------------------------------------------- Close
    def on_close(self) -> None:
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_cancel.set()
            self._scan_thread.join(timeout=0.5)


__all__ = ["VideoReviewFrame"]
