from __future__ import annotations
import fnmatch, shutil, traceback, xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

try:
    from send2trash import send2trash
    HAS_TRASH = True
except Exception:
    HAS_TRASH = False

from plugins.base import AppContext

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

def parse_bool(text: Optional[str], default=False) -> bool:
    if text is None: return default
    return str(text).strip().lower() in {"1","true","yes","y","on"}

def parse_config(xml_path: Path) -> Config:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if root.tag != "CleanerConfig":
        raise ValueError("Root element must be <CleanerConfig>")
    dry_run = parse_bool(root.findtext("DryRun"), True)
    move_to_recycle_bin = parse_bool(root.findtext("MoveToRecycleBin"), True)
    rules_el = root.find("Rules")
    if rules_el is None: raise ValueError("Missing <Rules>")
    rules: List[Rule] = []
    for r in rules_el.findall("Rule"):
        name = r.attrib.get("name") or "Unnamed Rule"
        p = r.attrib.get("path");  assert p, f"Rule '{name}' missing path"
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
            try: mad = int((mx.attrib.get("days") or "").strip())
            except Exception: pass
        rules.append(Rule(name, path, include, exclude, recursive, delete_empty_dirs, mad, enabled))
    return Config(rules, dry_run, move_to_recycle_bin)

def _iter_paths(rule: Rule):
    if not rule.path.exists():
        return []
    return rule.path.rglob("*") if rule.recursive else rule.path.glob("*")

def _matches_any(p: Path, patterns: List[str]) -> bool:
    if not patterns: return False
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

class CleanTool:
    key = "clean"
    title = "Cleaner"
    description = "XML-driven cleaner with preview and recycle bin."

    def __init__(self):
        # State/refs
        self.panel = None
        self.cfg: Optional[Config] = None
        self.xml_path_var = None
        self.dry_var = None
        self.trash_var = None

        # Basic section
        self.basic_frame = None
        self.status_var = None

        # Pro section
        self.pro_frame = None
        self.rules_list = None
        self.preview = None
        self.log = None

        self._current_mode = "standard"

    def make_panel(self, master, context: AppContext):
        root = tb.Frame(master)
        self._current_mode = context.ui_mode

        # --- Header / config ---
        header = tb.Frame(root); header.pack(fill="x", padx=8, pady=(8,6))
        self.xml_path_var = tb.StringVar(value=str((context.resource_dir / "configs" / "settings.clean.xml")))
        tb.Label(header, text="Settings XML:").pack(side="left")
        tb.Entry(header, textvariable=self.xml_path_var).pack(side="left", fill="x", expand=True, padx=6)
        tb.Button(header, text="Browse", command=self._browse, bootstyle="secondary").pack(side="left", padx=3)
        tb.Button(header, text="Load", command=self._load, bootstyle="primary").pack(side="left", padx=3)

        # --- Basic controls (always visible) ---
        self.basic_frame = tb.Labelframe(root, text="Basic Controls")
        self.basic_frame.pack(fill="x", padx=8, pady=(0,8))
        row = tb.Frame(self.basic_frame); row.pack(fill="x", padx=8, pady=8)
        self.dry_var = tb.BooleanVar(value=True)
        self.trash_var = tb.BooleanVar(value=True and HAS_TRASH)
        tb.Checkbutton(row, text="Dry run", variable=self.dry_var).pack(side="left", padx=6)
        tb.Checkbutton(row, text="Recycle Bin", variable=self.trash_var, state=("normal" if HAS_TRASH else "disabled")).pack(side="left", padx=6)
        tb.Button(row, text="Preview", command=self._preview, bootstyle="secondary").pack(side="right", padx=4)
        tb.Button(row, text="Run Clean", command=self._clean, bootstyle="success").pack(side="right", padx=4)

        self.status_var = tb.StringVar(value="No config loaded.")
        tb.Label(self.basic_frame, textvariable=self.status_var, bootstyle="secondary").pack(anchor="w", padx=8, pady=(0,8))

        # --- Pro section (advanced UI) ---
        self.pro_frame = tb.Labelframe(root, text="Advanced (Pro)")
        # Rules table
        self.rules_list = tb.Treeview(self.pro_frame, columns=("path","include","exclude","recursive","age","enabled"), show="headings", height=6)
        for col, w in (("path",260),("include",160),("exclude",160),("recursive",80),("age",60),("enabled",70)):
            self.rules_list.heading(col, text=col.capitalize()); self.rules_list.column(col, width=w, anchor="w")
        self.rules_list.pack(fill="x", padx=8, pady=6)
        # Preview/Log areas
        self.preview = tb.ScrolledText(self.pro_frame, height=12)
        self.preview.pack(fill="both", expand=True, padx=8, pady=6)
        self.log = tb.ScrolledText(self.pro_frame, height=8)
        self.log.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Load defaults
        self._load(silent=True)
        # Apply initial mode
        self._apply_mode(context.ui_mode, first_time=True)

        self.panel = root
        return root

    def start(self, context: AppContext, targets, argv):
        try:
            if self.cfg and targets:
                adhoc = []
                for t in targets:
                    adhoc.append(Rule(name=f"Ad-hoc: {Path(t).name}", path=Path(t), include=["**/*"], exclude=[], recursive=True, delete_empty_dirs=False, max_age_days=None, enabled=True))
                self.cfg.rules = adhoc + self.cfg.rules
                self.cfg.dry_run = True
                self._refresh_rules()
                # In standard mode, just update status; in pro, also fill preview
                if self._current_mode == "pro":
                    self._preview()
                else:
                    self.status_var.set(f"Loaded {len(self.cfg.rules)} rule(s). Ready to preview.")
        except Exception as e:
            Messagebox.show_error(message=str(e), title="Cleaner start error")

    def cleanup(self):
        pass

    def on_mode_changed(self, ui_mode: str):
        self._apply_mode(ui_mode)

    # ---- UI helpers ----
    def _apply_mode(self, ui_mode: str, first_time: bool=False):
        self._current_mode = ui_mode
        if ui_mode == "pro":
            if first_time:
                self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
            else:
                # Only pack if not already visible
                if not self.pro_frame.winfo_ismapped():
                    self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
        else:
            if self.pro_frame.winfo_ismapped():
                self.pro_frame.pack_forget()

    def _browse(self):
        from tkinter import filedialog
        p = filedialog.askopenfilename(title="Select XML", filetypes=[("XML files","*.xml"),("All files","*.*")])
        if p: self.xml_path_var.set(p)

    def _load(self, silent: bool=False):
        try:
            cfg = parse_config(Path(self.xml_path_var.get()))
            self.cfg = cfg
            self.dry_var.set(cfg.dry_run)
            self.trash_var.set(cfg.move_to_recycle_bin and HAS_TRASH)
            self._refresh_rules()
            self.status_var.set(f"Loaded {len(cfg.rules)} rule(s).")
        except Exception as e:
            if not silent:
                Messagebox.show_error(message=str(e), title="Load Error")

    def _refresh_rules(self):
        if not self.rules_list: return
        self.rules_list.delete(*self.rules_list.get_children())
        if not self.cfg: return
        for i, r in enumerate(self.cfg.rules):
            self.rules_list.insert("", "end", iid=str(i), values=(
                str(r.path), ";".join(r.include) or "(all)", ";".join(r.exclude) or "(none)",
                "Yes" if r.recursive else "No", (str(r.max_age_days) if r.max_age_days is not None else "-"),
                "On" if r.enabled else "Off",
            ))

    def _preview(self):
        if not self.cfg:
            Messagebox.show_warning("Load a settings XML first."); return
        self.cfg.dry_run = self.dry_var.get(); self.cfg.move_to_recycle_bin = self.trash_var.get()

        if self._current_mode == "pro":
            self.preview.delete("1.0","end")

        total = 0
        for r in [x for x in self.cfg.rules if x.enabled]:
            files, notes = collect_deletions(r)
            if self._current_mode == "pro":
                for n in notes: self.preview.insert("end", n+"\n")
                self.preview.insert("end", f"--- {r.name} ({r.path}) ---\n")
                for p in files: self.preview.insert("end", f"DELETE: {p}\n")
                self.preview.insert("end", f"({len(files)} items)\n\n")
            total += len(files)

        if self._current_mode == "pro":
            self.preview.insert("end", f"TOTAL: {total} items\n")
        self.status_var.set(f"Preview: {total} item(s) would be deleted.")

    def _clean(self):
        if not self.cfg:
            Messagebox.show_warning("Load a settings XML first."); return
        self.cfg.dry_run = self.dry_var.get(); self.cfg.move_to_recycle_bin = self.trash_var.get()
        if self.cfg.dry_run:
            self._preview(); Messagebox.show_info("Dry run is ON. Turn it off to delete."); return
        if not Messagebox.okcancel("This will delete items per rules. Continue?", title="Confirm Clean"):
            return

        to_trash = self.trash_var.get()
        total = 0
        for r in [x for x in self.cfg.rules if x.enabled]:
            try:
                files, notes = collect_deletions(r)
                if self._current_mode == "pro":
                    for n in notes: self.log.insert("end", n+"\n")
                    self.log.insert("end", f"--- {r.name} ---\n")
                for p in files:
                    msg = self._delete(p, to_trash)
                    if self._current_mode == "pro":
                        self.log.insert("end", msg+"\n")
                if self._current_mode == "pro":
                    self.log.insert("end", f"({len(files)} items processed)\n\n")
                    self.log.see("end")
                total += len(files)
            except Exception as e:
                if self._current_mode == "pro":
                    self.log.insert("end", f"[ERROR] {e}\n{traceback.format_exc()}\n")
        Messagebox.show_info(f"Done. Processed {total} items.", title="Completed")

    def _delete(self, p: Path, to_trash: bool) -> str:
        try:
            if to_trash and HAS_TRASH:
                send2trash(str(p)); return f"[TRASH] {p}"
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True); return f"[DEL DIR] {p}"
            p.unlink(missing_ok=True); return f"[DEL] {p}"
        except Exception as e:
            return f"[ERROR] {p} -> {e}"

PLUGIN = CleanTool()