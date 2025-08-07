from __future__ import annotations
import hashlib, csv
from pathlib import Path
from typing import List

import tkinter as tk
import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext

class HashTool:
    key = "hash"
    title = "Hash to CSV"
    description = "Compute SHA256 for selected files/folders and export CSV."

    def __init__(self):
        self.panel = None
        self.out_var = None
        self.recursive_var = None
        self.listbox = None
        self.targets: List[Path] = []

    def make_panel(self, master, context: AppContext):
        frm = tb.Labelframe(master, text=self.title)
        top = tb.Frame(frm); top.pack(fill="x", padx=8, pady=6)
        self.out_var = tb.StringVar(value=str(Path.home()/ "hashes.csv"))
        self.recursive_var = tb.BooleanVar(value=True)
        tb.Label(top, text="Output CSV:").pack(side="left")
        tb.Entry(top, textvariable=self.out_var).pack(side="left", fill="x", expand=True, padx=6)
        tb.Checkbutton(top, text="Recursive", variable=self.recursive_var).pack(side="left", padx=6)
        tb.Button(top, text="Run", command=self._run, bootstyle="success").pack(side="right", padx=4)

        self.listbox = tk.Listbox(frm, height=15)
        self.listbox.pack(fill="both", expand=True, padx=8, pady=8)

        self.panel = frm
        return frm

    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        self.targets = targets
        if self.targets:
            self.listbox.delete(0, "end")
            for t in self.targets: self.listbox.insert("end", str(t))

    def cleanup(self):
        pass

    def _run(self):
        if not self.targets:
            Messagebox.show_warning("No targets selected.")
            return
        out_file = Path(self.out_var.get())
        with open(out_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Path", "SHA256"])
            for t in self.targets:
                if t.is_dir():
                    files = t.rglob("*") if self.recursive_var.get() else t.glob("*")
                else:
                    files = [t]
                for file in files:
                    if file.is_file():
                        h = self._sha256(file)
                        writer.writerow([str(file), h])
        Messagebox.show_info(f"Hashes written to {out_file}")

    def _sha256(self, file: Path) -> str:
        h = hashlib.sha256()
        with open(file, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

PLUGIN = HashTool()