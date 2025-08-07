from __future__ import annotations
import fnmatch, shutil, traceback, xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

# GUI
import tkinter as tk
from tkinter import ttk, messagebox
from tkinter.scrolledtext import ScrolledText  # avoids ttk style issues on some macOS Tk builds

GUI_AVAILABLE = True

# Optional trash support
try:
    from send2trash import send2trash
    HAS_TRASH = True
except Exception:
    HAS_TRASH = False

from plugins.base import AppContext


# ----------------------------- Data -----------------------------
@dataclass
class Rule:
    name: str
    path: Path
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    recursive: bool = True
    delete_empty_dirs: bool = True
    max_age_days: Optional[int] = None
    enabled: bool = True


@dataclass
class Config:
    rules: List[Rule]
    dry_run: bool = True
    move_to_recycle_bin: bool = True


# -------------------------- XML parsing -------------------------
def parse_bool(text: Optional[str], default=False) -> bool:
    if text is None:
        return default
    return str(text).strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_config(xml_path: Path) -> Config:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if root.tag != "CleanerConfig":
        raise ValueError("Root element must be <CleanerConfig>")
    dry_run = parse_bool(root.findtext("DryRun"), True)
    move_to_recycle_bin = parse_bool(root.findtext("MoveToRecycleBin"), True)
    rules_el = root.find("Rules")
    if rules_el is None:
        raise ValueError("Missing <Rules>")
    rules: List[Rule] = []
    for r in rules_el.findall("Rule"):
        name = r.attrib.get("name") or "Unnamed Rule"
        p = r.attrib.get("path")
        if not p:
            raise ValueError(f"Rule '{name}' missing path")
        path = Path(p).expanduser()
        inc = (r.find("Include").attrib.get("pattern") if r.find("Include") is not None else "")
        exc = (r.find("Exclude").attrib.get("pattern") if r.find("Exclude") is not None else "")
        include = [s.strip() for s in inc.split(";") if s.strip()]
        exclude = [s.strip() for s in exc.split(";") if s.strip()]
        recursive = parse_bool(r.findtext("Recursive"), True)
        delete_empty_dirs = parse_bool(r.findtext("DeleteEmptyDirs"), True)
        enabled = parse_bool(r.findtext("Enabled"), True)
        mad = None
        mx = r.find("MaxAge")
        if mx is not None:
            try:
                mad = int((mx.attrib.get("days") or "").strip())
            except Exception:
                pass
        rules.append(Rule(name, path, include, exclude, recursive, delete_empty_dirs, mad, enabled))
    return Config(rules, dry_run, move_to_recycle_bin)


# --------------------------- Helpers ----------------------------
def _iter_paths(rule: Rule):
    if not rule.path.exists():
        return []
    return rule.path.rglob("*") if rule.recursive else rule.path.glob("*")


def _matches_any(p: Path, patterns: List[str]) -> bool:
    if not patterns:
        return False
    s = str(p)
    return any(fnmatch.fnmatch(s, pat) or fnmatch.fnmatch(p.name, pat) for pat in patterns)


def _older_than(p: Path, days: int) -> bool:
    try:
        m = datetime.fromtimestamp(p.stat().st_mtime)
        return (datetime.now() - m) > timedelta(days=days)
    except Exception:
        return False


def collect_deletions(rule: Rule):
    notes: List[str] = []
    if not rule.path.exists():
        notes.append(f"[WARN] base not found: {rule.path}")
        return [], notes
    cand: List[Path] = []
    for p in _iter_paths(rule):
        if rule.include and not _matches_any(p, rule.include):
            continue
        if _matches_any(p, rule.exclude):
            continue
        if rule.max_age_days is not None and not _older_than(p, rule.max_age_days):
            continue
        cand.append(p)
    if rule.delete_empty_dirs:
        for parent in sorted({x.parent for x in cand if x.exists()}, key=lambda x: len(str(x)), reverse=True):
            try:
                if parent.is_dir() and not any(parent.iterdir()):
                    cand.append(parent)
            except Exception:
                pass
    files_first = sorted(cand, key=lambda p: (p.is_dir(), len(str(p))))
    return files_first, notes


# ---------------------------- Plugin ----------------------------
class CleanTool:
    key = "clean"  # discovery uses this as the dictionary key
    title = "Cleaner"
    description = "XML-driven cleaner with preview and recycle bin."

    def __init__(self):
        # GUI refs
        self.panel = None
        self.cfg: Optional[Config] = None
        self.xml_path_var: tk.StringVar | None = None
        self.dry_var: tk.BooleanVar | None = None
        self.trash_var: tk.BooleanVar | None = None
        self.rules_list = None
        self.preview: ScrolledText | None = None
        self.log: ScrolledText | None = None

    # ---- UI ----
    def make_panel(self, master, context: AppContext):
        if not GUI_AVAILABLE:
            raise RuntimeError("GUI dependencies (tkinter/ttkbootstrap) are not installed")

        frm = ttk.LabelFrame(master, text=self.title)  # correct casing
        # Tk variables (ttkbootstrap doesn't export *Var reliably across versions)
        self.xml_path_var = tk.StringVar(value=str((context.resource_dir / "configs" / "settings.clean.xml")))
        self.dry_var = tk.BooleanVar(value=True)
        self.trash_var = tk.BooleanVar(value=(True and HAS_TRASH))

        top = ttk.Frame(frm)
        top.pack(fill="x", padx=8, pady=6)
        ttk.Label(top, text="Settings XML:").pack(side="left")
        ttk.Entry(top, textvariable=self.xml_path_var).pack(side="left", fill="x", expand=True, padx=6)
        ttk.Button(top, text="Browse", command=self._browse).pack(side="left", padx=3)
        ttk.Button(top, text="Load", command=self._load).pack(side="left", padx=3)

        self.rules_list = ttk.Treeview(
            frm,
            columns=("path", "include", "exclude", "recursive", "age", "enabled"),
            show="headings",
            height=6,
        )
        for col, w in (("path", 260), ("include", 160), ("exclude", 160), ("recursive", 80), ("age", 60), ("enabled", 70)):
            self.rules_list.heading(col, text=col.capitalize())
            self.rules_list.column(col, width=w, anchor="w")
        self.rules_list.pack(fill="x", padx=8, pady=6)

        # Use Tk's ScrolledText to dodge ttk style issues on some macOS Tk builds
        self.preview = ScrolledText(frm, height=12, wrap="word")
        self.preview.pack(fill="both", expand=True, padx=8, pady=6)
        self.log = ScrolledText(frm, height=8, wrap="word")
        self.log.pack(fill="both", expand=True, padx=8, pady=6)

        bottom = ttk.Frame(frm)
        bottom.pack(fill="x", padx=8, pady=8)
        ttk.Checkbutton(bottom, text="Dry run (preview only)", variable=self.dry_var).pack(side="left", padx=6)
        ttk.Checkbutton(
            bottom,
            text="Move to Recycle Bin",
            variable=self.trash_var,
            state=("normal" if HAS_TRASH else "disabled"),
        ).pack(side="left", padx=6)
        ttk.Button(bottom, text="Preview", command=self._preview).pack(side="right", padx=4)
        ttk.Button(bottom, text="Run Clean", command=self._clean).pack(side="right", padx=4)

        self.panel = frm
        return frm

    # ---- Lifecycle ----
    def start(self, context: AppContext, targets, argv):
        try:
            self._load()
            if self.cfg and targets:
                adhoc = []
                for t in targets:
                    adhoc.append(
                        Rule(
                            name=f"Ad-hoc: {Path(t).name}",
                            path=Path(t),
                            include=["**/*"],
                            exclude=[],
                            recursive=True,
                            delete_empty_dirs=False,
                            max_age_days=None,
                            enabled=True,
                        )
                    )
                self.cfg.rules = adhoc + self.cfg.rules
                self.cfg.dry_run = True
                self._refresh_rules()
                self._preview()
        except Exception as e:
            messagebox.showerror(title="Cleaner start error", message=str(e))

    def cleanup(self):
        pass

    # ---- Actions ----
    def _browse(self):
        from tkinter import filedialog
        p = filedialog.askopenfilename(title="Select XML", filetypes=[("XML files", "*.xml"), ("All files", "*.*")])
        if p and self.xml_path_var is not None:
            self.xml_path_var.set(p)

    def _load(self):
        if not self.xml_path_var:
            return
        cfg = parse_config(Path(self.xml_path_var.get()))
        self.cfg = cfg
        if self.dry_var:
            self.dry_var.set(cfg.dry_run)
        if self.trash_var:
            self.trash_var.set(cfg.move_to_recycle_bin and HAS_TRASH)
        self._refresh_rules()

    def _refresh_rules(self):
        if not self.rules_list:
            return
        self.rules_list.delete(*self.rules_list.get_children())
        if not self.cfg:
            return
        for i, r in enumerate(self.cfg.rules):
            self.rules_list.insert(
                "",
                "end",
                iid=str(i),
                values=(
                    str(r.path),
                    ";".join(r.include) or "(all)",
                    ";".join(r.exclude) or "(none)",
                    "Yes" if r.recursive else "No",
                    (str(r.max_age_days) if r.max_age_days is not None else "-"),
                    "On" if r.enabled else "Off",
                ),
            )

    def _preview(self):
        if not self.cfg:
            messagebox.showwarning(message="Load a settings XML first.")
            return
        if not self.preview:
            return
        if self.dry_var:
            self.cfg.dry_run = self.dry_var.get()
        if self.trash_var:
            self.cfg.move_to_recycle_bin = self.trash_var.get()

        self.preview.delete("1.0", "end")
        total = 0
        for r in [x for x in self.cfg.rules if x.enabled]:
            files, notes = collect_deletions(r)
            for n in notes:
                self.preview.insert("end", n + "\n")
            self.preview.insert("end", f"--- {r.name} ({r.path}) ---\n")
            for p in files:
                self.preview.insert("end", f"DELETE: {p}\n")
            self.preview.insert("end", f"({len(files)} items)\n\n")
            total += len(files)
        self.preview.insert("end", f"TOTAL: {total} items\n")

    def _clean(self):
        if not self.cfg:
            messagebox.showwarning(message="Load a settings XML first.")
            return
        if self.dry_var:
            self.cfg.dry_run = self.dry_var.get()
        if self.trash_var:
            self.cfg.move_to_recycle_bin = self.trash_var.get()

        if self.cfg.dry_run:
            self._preview()
            messagebox.showinfo(message="Dry run is ON. Turn it off to delete.")
            return
        if not messagebox.askokcancel(title="Confirm Clean", message="This will delete items per rules. Continue?"):
            return

        to_trash = bool(self.trash_var.get() if self.trash_var else False)
        total = 0
        for r in [x for x in self.cfg.rules if x.enabled]:
            try:
                files, notes = collect_deletions(r)
                if self.log:
                    for n in notes:
                        self.log.insert("end", n + "\n")
                    self.log.insert("end", f"--- {r.name} ---\n")
                for p in files:
                    msg = self._delete(p, to_trash)
                    if self.log:
                        self.log.insert("end", msg + "\n")
                if self.log:
                    self.log.insert("end", f"({len(files)} items processed)\n\n")
                    self.log.see("end")
                total += len(files)
            except Exception as e:
                if self.log:
                    self.log.insert("end", f"[ERROR] {e}\n{traceback.format_exc()}\n")
        messagebox.showinfo(message=f"Done. Processed {total} items.", title="Completed")

    def _delete(self, p: Path, to_trash: bool) -> str:
        try:
            if to_trash and HAS_TRASH:
                send2trash(str(p))
                return f"[TRASH] {p}"
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
                return f"[DEL DIR] {p}"
            p.unlink(missing_ok=True)
            return f"[DEL] {p}"
        except Exception as e:
            return f"[ERROR] {p} -> {e}"


# ---- Exports expected by different discovery schemes ----
PLUGIN = CleanTool()

def get_plugin():
    """Some discovery functions call get_plugin(); others look for PLUGIN."""
    return PLUGIN

__all__ = ["PLUGIN", "get_plugin"]