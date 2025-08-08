from __future__ import annotations
import fnmatch, shutil, traceback, xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Iterable
import os

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

try:
    from send2trash import send2trash
    HAS_TRASH = True
except Exception:
    HAS_TRASH = False

from plugins.base import AppContext

# ===================== Models / Config =====================

@dataclass
class Rule:
    name: str
    path: Path                      # effective resolved path
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    recursive: bool = True
    delete_empty_dirs: bool = True
    max_age_days: Optional[int] = None
    enabled: bool = True

@dataclass
class RuleSpec:
    """Unresolved rule coming from XML; may contain relative paths or {TARGET}."""
    name: str
    path_str: str                   # as written in XML (may be relative or include {TARGET})
    include: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)
    recursive: bool = True
    delete_empty_dirs: bool = True
    max_age_days: Optional[int] = None
    enabled: bool = True

    def resolve(self, target_folder: Optional[Path]) -> Rule:
        raw = (self.path_str or "").strip()
        if not raw:
            base = target_folder or Path.cwd()
            path = base
        else:
            raw_expanded = Path(os.path.expandvars(raw)).expanduser()
            raw_s = str(raw_expanded)
            if "{TARGET}" in raw_s and target_folder:
                raw_s = raw_s.replace("{TARGET}", str(target_folder))
                path = Path(raw_s)
            else:
                path = Path(raw_s)
                if not path.is_absolute() and target_folder:
                    path = target_folder / path
        return Rule(
            name=self.name,
            path=path,
            include=list(self.include),
            exclude=list(self.exclude),
            recursive=self.recursive,
            delete_empty_dirs=self.delete_empty_dirs,
            max_age_days=self.max_age_days,
            enabled=self.enabled,
        )

@dataclass
class Profile:
    name: str
    detect_names: List[str] = field(default_factory=list)  # e.g. ["MyTool.exe", "Game.exe"]
    rulespecs: List[RuleSpec] = field(default_factory=list)

@dataclass
class Config:
    profiles: List[Profile] = field(default_factory=list)
    default_profile: Optional[str] = None
    dry_run: bool = True
    move_to_recycle_bin: bool = True

# ===================== Helpers =====================

def parse_bool(text: Optional[str], default=False) -> bool:
    if text is None: return default
    return str(text).strip().lower() in {"1","true","yes","y","on"}

def _parse_rules_element(rules_el) -> List[RuleSpec]:
    specs: List[RuleSpec] = []
    for r in rules_el.findall("Rule"):
        name = r.attrib.get("name") or "Unnamed Rule"
        p = r.attrib.get("path", "")
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
        specs.append(RuleSpec(
            name=name, path_str=p, include=include, exclude=exclude,
            recursive=recursive, delete_empty_dirs=delete_empty_dirs,
            max_age_days=mad, enabled=enabled
        ))
    return specs

def parse_config(xml_path: Path) -> Config:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    if root.tag != "CleanerConfig":
        raise ValueError("Root element must be <CleanerConfig>")

    cfg = Config()
    cfg.dry_run = parse_bool(root.findtext("DryRun"), True)
    cfg.move_to_recycle_bin = parse_bool(root.findtext("MoveToRecycleBin"), True)

    profiles_el = root.find("Profiles")
    rules_el = root.find("Rules")

    if profiles_el is not None:
        cfg.default_profile = profiles_el.attrib.get("default")
        for pnode in profiles_el.findall("Profile"):
            pname = pnode.attrib.get("name") or "Unnamed"
            detect_attr = pnode.attrib.get("detectExe") or pnode.attrib.get("detectFile") or ""
            detect_names = [s.strip() for s in detect_attr.split(";") if s.strip()]
            prules_el = pnode.find("Rules")
            rulespecs = _parse_rules_element(prules_el) if prules_el is not None else []
            cfg.profiles.append(Profile(name=pname, detect_names=detect_names, rulespecs=rulespecs))

    if rules_el is not None and not cfg.profiles:
        specs = _parse_rules_element(rules_el)
        cfg.profiles.append(Profile(name="Default", detect_names=[], rulespecs=specs))
        cfg.default_profile = cfg.default_profile or "Default"

    if not cfg.profiles:
        raise ValueError("No profiles/rules found. Define <Profiles><Profile>...</Profile></Profiles> or top-level <Rules>.")
    return cfg

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
        if rule.include and not _matches_any(p, rule.include): continue
        if _matches_any(p, rule.exclude): continue
        if rule.max_age_days is not None and not _older_than(p, rule.max_age_days): continue
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

# ===================== Confirmation Dialog =====================

class ConfirmDialog(tb.Toplevel):
    """
    Modal tree-based confirmation dialog with tri-state checkboxes.
    Only nodes that are actual candidates are "targets"; parents created
    just for structure can still toggle descendents but won't be deleted
    themselves unless they're also candidates.
    """
    ICON_CHECKED = "☑"
    ICON_UNCHECKED = "☐"
    ICON_MIXED = "◪"

    def __init__(self, master, title: str, base_folder: Optional[Path], paths: List[Path]):
        super().__init__(master=master)
        self.title(title)
        self.geometry("900x600")
        self.resizable(True, True)
        self.transient(master)
        self.grab_set()

        self.base_folder = base_folder
        self.paths = sorted(set(Path(p) for p in paths), key=lambda p: (p.is_dir(), str(p)))

        # Map: iid -> dict(path: Path, state: 'checked'|'unchecked'|'mixed', is_target: bool)
        self.meta: Dict[str, Dict] = {}

        top = tb.Frame(self, padding=8); top.pack(fill="both", expand=True)
        tb.Label(top, text="Confirm items to delete (toggle the checkboxes):").pack(anchor="w")

        cols = ("sel", "path")
        self.tree = tb.Treeview(top, columns=cols, show="tree headings", height=22)
        self.tree.heading("sel", text="✓")
        self.tree.column("sel", width=34, anchor="center", stretch=False)
        self.tree.heading("path", text="Path")
        self.tree.column("path", width=780, anchor="w", stretch=True)
        self.tree.pack(fill="both", expand=True, pady=(6,6))

        # Mouse toggle
        self.tree.bind("<Button-1>", self._on_click)

        # Buttons
        btns = tb.Frame(self, padding=8); btns.pack(fill="x")
        tb.Button(btns, text="Select All", command=self._select_all, bootstyle="secondary").pack(side="left")
        tb.Button(btns, text="Deselect All", command=self._deselect_all, bootstyle="secondary").pack(side="left", padx=6)
        tb.Button(btns, text="Cancel", command=self._cancel, bootstyle="danger").pack(side="right")
        tb.Button(btns, text="OK", command=self._ok, bootstyle="success").pack(side="right", padx=6)

        self.result: Optional[List[Path]] = None

        self._build_tree()

        # focus
        try:
            self.tree.focus(self.tree.get_children()[0])
        except Exception:
            pass

        self.wait_window(self)

    # ---------- Tree building ----------
    def _rel(self, p: Path) -> str:
        try:
            if self.base_folder and self.base_folder in p.parents or p == self.base_folder:
                return str(p.relative_to(self.base_folder))
        except Exception:
            pass
        return str(p)

    def _ensure_ancestors(self, parent_map: Dict[str, str], full_parts: List[str], anchor: str) -> str:
        """
        Ensure a chain of ancestors exists under 'anchor'. Returns final parent iid.
        parent_map maps "anchor|partpath" -> iid to avoid duplicates.
        """
        cur_parent = ""
        running = []
        for part in full_parts:
            running.append(part)
            key = anchor + "|" + "/".join(running)
            iid = parent_map.get(key)
            if not iid:
                text = part if part else "/"
                iid = self.tree.insert(cur_parent, "end", text=text, values=(self.ICON_UNCHECKED, "/".join(running)))
                self.meta[iid] = {"path": None, "state": "unchecked", "is_target": False}
                parent_map[key] = iid
            cur_parent = iid
        return cur_parent

    def _build_tree(self):
        # Build a tree grouped by base folder if available; otherwise by drive/anchor
        parent_map: Dict[str, str] = {}
        for p in self.paths:
            # Display path as relative when we can; also compute ancestor parts
            rel = self._rel(p)
            parts = [part for part in Path(rel).parts if part not in (".",)]
            # Build parent nodes
            parent = self._ensure_ancestors(parent_map, parts[:-1], anchor=str(self.base_folder or ""))

            # Insert the actual candidate node
            leaf_text = parts[-1] if parts else str(p.name)
            iid = self.tree.insert(parent, "end", text=leaf_text, values=(self.ICON_CHECKED, rel))
            self.meta[iid] = {"path": p, "state": "checked", "is_target": True}

            # Bubble states up (parent becomes checked)
            self._bubble_up(iid)

        # Expand top-level a bit
        for iid in self.tree.get_children():
            self.tree.item(iid, open=True)

    # ---------- State helpers ----------
    def _set_state_icon(self, iid: str, state: str):
        icon = self.ICON_CHECKED if state == "checked" else self.ICON_UNCHECKED if state == "unchecked" else self.ICON_MIXED
        vals = list(self.tree.item(iid, "values"))
        if not vals:
            vals = [icon, ""]
        else:
            vals[0] = icon
        self.tree.item(iid, values=tuple(vals))

    def _set_state(self, iid: str, state: str, cascade_children: bool = True, bubble_parent: bool = True):
        meta = self.meta.get(iid)
        if meta is None:
            return
        # Only actual targets are directly stateful; structure-only parents can become mixed via bubbling
        if meta["is_target"] or state in ("mixed", "unchecked", "checked"):
            meta["state"] = state
            self._set_state_icon(iid, state)

        if cascade_children:
            for child in self.tree.get_children(iid):
                self._set_state(child, state, cascade_children=True, bubble_parent=False)

        if bubble_parent:
            self._bubble_up(iid)

    def _bubble_up(self, iid: str):
        # compute parent state from children
        parent = self.tree.parent(iid)
        if not parent:
            return
        children = list(self.tree.get_children(parent))
        states = []
        for c in children:
            st = self.meta.get(c, {}).get("state", "unchecked")
            states.append(st)
        if all(s == "checked" for s in states):
            new_state = "checked"
        elif all(s == "unchecked" for s in states):
            new_state = "unchecked"
        else:
            new_state = "mixed"
        # parent may be structure-only; store state but will never be returned for deletion unless is_target
        self.meta[parent]["state"] = new_state
        self._set_state_icon(parent, new_state)
        # continue bubbling
        self._bubble_up(parent)

    def _toggle(self, iid: str):
        cur = self.meta.get(iid, {}).get("state", "unchecked")
        new_state = "unchecked" if cur == "checked" else "checked"
        self._set_state(iid, new_state, cascade_children=True, bubble_parent=True)

    # ---------- Events ----------
    def _on_click(self, event):
        row = self.tree.identify_row(event.y)
        if not row:
            return
        col = self.tree.identify_column(event.x)
        # Toggle when clicking the checkbox column or the tree text
        if col in ("#1", "#0"):
            self._toggle(row)

    # ---------- Buttons ----------
    def _select_all(self):
        for iid in self.meta.keys():
            if self.meta[iid]["is_target"]:
                self._set_state(iid, "checked", cascade_children=False, bubble_parent=True)

    def _deselect_all(self):
        for iid in self.meta.keys():
            if self.meta[iid]["is_target"]:
                self._set_state(iid, "unchecked", cascade_children=False, bubble_parent=True)

    def _ok(self):
        selected: List[Path] = []
        for iid, m in self.meta.items():
            if m["is_target"] and m["state"] == "checked":
                selected.append(m["path"])
        self.result = selected
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

# ===================== Clean Tool =====================

class CleanTool:
    key = "clean"
    title = "Cleaner"
    description = "Profile-based cleaner with auto-detect via marker .exe. Supports {TARGET} and relative paths."

    def __init__(self):
        # Parsed config / profiles
        self.cfg: Optional[Config] = None
        self.profiles: List[Profile] = []
        self.default_profile: Optional[str] = None

        # Active state
        self._current_mode = "standard"
        self.base_folder: Optional[Path] = None
        self.active_profile: Optional[str] = None
        self.active_rules: List[Rule] = []

        # UI refs
        self.panel = None
        self.xml_path_var = None
        self.dry_var = None
        self.trash_var = None
        self.status_var = None

        self.profile_var = None
        self.profile_combo = None
        self.folder_var = None

        # Pro widgets
        self.pro_frame = None
        self.rules_list = None
        self.preview = None
        self.log = None

    # ---------- UI Building ----------
    def make_panel(self, master, context: AppContext):
        self._current_mode = context.ui_mode

        root = tb.Frame(master)
        # --- Header / config ---
        header = tb.Frame(root); header.pack(fill="x", padx=8, pady=(8,6))
        self.xml_path_var = tb.StringVar(value=str((context.resource_dir / "configs" / "settings.clean.xml")))
        tb.Label(header, text="Settings XML:").pack(side="left")
        tb.Entry(header, textvariable=self.xml_path_var).pack(side="left", fill="x", expand=True, padx=6)
        tb.Button(header, text="Browse", command=self._browse_xml, bootstyle="secondary").pack(side="left", padx=3)
        tb.Button(header, text="Load", command=self._load, bootstyle="primary").pack(side="left", padx=3)

        # Profile + Folder row
        pf = tb.Frame(root); pf.pack(fill="x", padx=8, pady=(0,6))
        tb.Label(pf, text="Profile:").pack(side="left")
        self.profile_var = tb.StringVar(value="(auto)")
        self.profile_combo = tb.Combobox(pf, textvariable=self.profile_var, state="readonly")
        self.profile_combo.pack(side="left", padx=6)
        self.profile_combo.bind("<<ComboboxSelected>>", lambda e: self._on_profile_changed())

        tb.Label(pf, text="Target Folder:").pack(side="left", padx=(16,0))
        self.folder_var = tb.StringVar(value="")
        tb.Entry(pf, textvariable=self.folder_var, width=50).pack(side="left", padx=6, fill="x", expand=True)
        tb.Button(pf, text="Pick", command=self._pick_folder, bootstyle="secondary").pack(side="left")

        # --- Basic controls (always visible) ---
        basic = tb.Labelframe(root, text="Basic Controls")
        basic.pack(fill="x", padx=8, pady=(0,8))
        row = tb.Frame(basic); row.pack(fill="x", padx=8, pady=8)
        self.dry_var = tb.BooleanVar(value=True)
        self.trash_var = tb.BooleanVar(value=True and HAS_TRASH)
        tb.Checkbutton(row, text="Dry run", variable=self.dry_var).pack(side="left", padx=6)
        tb.Checkbutton(row, text="Recycle Bin", variable=self.trash_var, state=("normal" if HAS_TRASH else "disabled")).pack(side="left", padx=6)
        tb.Button(row, text="Preview", command=self._preview, bootstyle="secondary").pack(side="right", padx=4)
        tb.Button(row, text="Run Clean", command=self._clean, bootstyle="success").pack(side="right", padx=4)

        self.status_var = tb.StringVar(value="No config loaded.")
        tb.Label(basic, textvariable=self.status_var, bootstyle="secondary").pack(anchor="w", padx=8, pady=(0,8))

        # --- Pro section (advanced UI) ---
        self.pro_frame = tb.Labelframe(root, text="Advanced (Pro)")
        self.rules_list = tb.Treeview(self.pro_frame, columns=("path","include","exclude","recursive","age","enabled"), show="headings", height=6)
        for col, w in (("path",260),("include",160),("exclude",160),("recursive",80),("age",60),("enabled",70)):
            self.rules_list.heading(col, text=col.capitalize()); self.rules_list.column(col, width=w, anchor="w")
        self.rules_list.pack(fill="x", padx=8, pady=6)
        self.preview = tb.ScrolledText(self.pro_frame, height=12); self.preview.pack(fill="both", expand=True, padx=8, pady=6)
        self.log = tb.ScrolledText(self.pro_frame, height=8); self.log.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Initial load + mode
        self._load(silent=True)
        self._apply_mode(context.ui_mode, first_time=True)

        self.panel = root
        return root

    # ---------- Lifecycle ----------
    def start(self, context: AppContext, targets, argv):
        try:
            # Pick first target folder (if file, use parent)
            base = None
            for t in targets or []:
                tp = Path(t)
                if tp.is_dir(): base = tp; break
                elif tp.exists(): base = tp.parent; break
            if base:
                self.base_folder = base.resolve()
                self.folder_var.set(str(self.base_folder))
            self._auto_detect_and_apply()
            if self._current_mode == "pro": self._preview()
            else:
                if self.active_profile:
                    self.status_var.set(f"Profile '{self.active_profile}' ready. Click Preview/Run.")
        except Exception as e:
            Messagebox.show_error(message=str(e), title="Cleaner start error")

    def cleanup(self): pass
    def on_mode_changed(self, ui_mode: str): self._apply_mode(ui_mode)

    # ---------- Mode handling ----------
    def _apply_mode(self, ui_mode: str, first_time: bool=False):
        self._current_mode = ui_mode
        if ui_mode == "pro":
            if first_time or not self.pro_frame.winfo_ismapped():
                self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
        else:
            if self.pro_frame.winfo_ismapped():
                self.pro_frame.pack_forget()

    # ---------- Config / Profiles ----------
    def _browse_xml(self):
        from tkinter import filedialog
        p = filedialog.askopenfilename(title="Select XML", filetypes=[("XML files","*.xml"),("All files","*.*")])
        if p: self.xml_path_var.set(p)

    def _load(self, silent: bool=False):
        try:
            cfg = parse_config(Path(self.xml_path_var.get()))
            self.cfg = cfg
            self.profiles = cfg.profiles
            self.default_profile = cfg.default_profile
            names = ["(auto)"] + [p.name for p in self.profiles]
            self.profile_combo.configure(values=names)
            self.profile_var.set(self.profile_var.get() if self.profile_var.get() in names else "(auto)")
            self.dry_var.set(cfg.dry_run)
            self.trash_var.set(cfg.move_to_recycle_bin and HAS_TRASH)
            self._apply_selected_profile()
            self.status_var.set(f"Loaded {len(self.profiles)} profile(s).")
        except Exception as e:
            if not silent:
                Messagebox.show_error(message=str(e), title="Load Error")

    def _on_profile_changed(self):
        self._apply_selected_profile()
        if self._current_mode == "pro":
            self._refresh_rules_table()

    def _pick_folder(self):
        from tkinter import filedialog
        p = filedialog.askdirectory(title="Select target folder")
        if p:
            self.base_folder = Path(p).resolve()
            self.folder_var.set(str(self.base_folder))
            if (self.profile_var.get() or "").strip().lower() == "(auto)":
                self._auto_detect_and_apply()
            else:
                self._apply_selected_profile()
            if self._current_mode == "pro":
                self._refresh_rules_table()

    def _auto_detect_and_apply(self):
        if not self.profiles:
            return
        chosen = None
        # detect based on marker files
        if self.base_folder:
            for prof in self.profiles:
                for mark in prof.detect_names:
                    try:
                        if (self.base_folder / mark).exists():
                            chosen = prof.name; break
                        hits = list(self.base_folder.rglob(mark))
                        if hits:
                            chosen = prof.name; break
                    except Exception:
                        pass
                if chosen:
                    break
        if not chosen:
            chosen = self.default_profile
        self.active_profile = chosen
        self._prepare_active_rules()

    def _apply_selected_profile(self):
        sel = (self.profile_var.get() or "").strip()
        if sel.lower() == "(auto)":
            self._auto_detect_and_apply()
        else:
            self.active_profile = sel or None
            self._prepare_active_rules()

    def _prepare_active_rules(self):
        self.active_rules = []
        profile = None
        if self.active_profile:
            for p in self.profiles:
                if p.name == self.active_profile:
                    profile = p; break
        if profile is None:
            if self.default_profile:
                profile = next((p for p in self.profiles if p.name == self.default_profile), None)
            if profile is None and self.profiles:
                profile = self.profiles[0]
        if profile:
            for spec in profile.rulespecs:
                self.active_rules.append(spec.resolve(self.base_folder))
        if self._current_mode == "pro":
            self._refresh_rules_table()

    # ---------- Table / Preview / Run ----------
    def _refresh_rules_table(self):
        if not self.rules_list: return
        self.rules_list.delete(*self.rules_list.get_children())
        for i, r in enumerate(self.active_rules):
            self.rules_list.insert("", "end", iid=str(i), values=(
                str(r.path), ";".join(r.include) or "(all)", ";".join(r.exclude) or "(none)",
                "Yes" if r.recursive else "No", (str(r.max_age_days) if r.max_age_days is not None else "-"),
                "On" if r.enabled else "Off",
            ))

    def _gather_candidates(self) -> Tuple[List[Path], List[str]]:
        """Return (all candidate paths, notes) from active rules."""
        all_paths: List[Path] = []
        notes: List[str] = []
        for r in [x for x in self.active_rules if x.enabled]:
            paths, n = collect_deletions(r)
            notes.extend(n)
            all_paths.extend(paths)
        # De-dupe while preserving order
        seen = set()
        deduped = []
        for p in all_paths:
            if p not in seen:
                deduped.append(p); seen.add(p)
        return deduped, notes

    def _preview(self):
        if not self.active_rules:
            Messagebox.show_warning("No active rules. Load config, pick a folder, and ensure a profile is applied.")
            return
        if self._current_mode == "pro":
            self.preview.delete("1.0","end")
        total = 0
        for r in [x for x in self.active_rules if x.enabled]:
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
        if not self.active_rules:
            Messagebox.show_warning("No active rules. Load config, pick a folder, and ensure a profile is applied.")
            return

        # sync toggles from UI
        if self.cfg:
            self.cfg.dry_run = self.dry_var.get()
            self.cfg.move_to_recycle_bin = self.trash_var.get()

        if self.cfg and self.cfg.dry_run:
            self._preview(); Messagebox.show_info("Dry run is ON. Turn it off to delete."); return
        if not Messagebox.okcancel("This will delete items per rules. Continue?", title="Confirm Clean"):
            return

        # Gather all candidates, then show confirmation tree
        all_candidates, notes = self._gather_candidates()
        if not all_candidates:
            Messagebox.show_info("Nothing to delete for current rules.")
            return

        dlg = ConfirmDialog(self.panel or self.rules_list, "Confirm Deletions", self.base_folder, all_candidates)
        chosen = dlg.result
        if chosen is None:
            # user cancelled
            self.status_var.set("Deletion cancelled.")
            return
        if not chosen:
            Messagebox.show_info("No items selected. Nothing was deleted.")
            return

        # Order: files before directories; shorter paths first for files, longer first for dirs
        files = [p for p in chosen if p.is_file()]
        dirs  = [p for p in chosen if p.is_dir()]
        files_sorted = sorted(files, key=lambda p: (len(str(p)), str(p)))
        dirs_sorted  = sorted(dirs, key=lambda p: (-len(str(p)), str(p)))
        selected_sorted = files_sorted + dirs_sorted

        to_trash = (self.cfg.move_to_recycle_bin if self.cfg else True) and HAS_TRASH
        processed = 0
        if self._current_mode == "pro":
            # show notes first
            for n in notes: self.log.insert("end", n+"\n")
            self.log.insert("end", f"--- Deleting {len(selected_sorted)} selected item(s) ---\n")
        for p in selected_sorted:
            msg = self._delete(p, to_trash)
            processed += 1
            if self._current_mode == "pro":
                self.log.insert("end", msg + "\n"); self.log.see("end")

        Messagebox.show_info(f"Done. Deleted {processed} item(s).", title="Completed")

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