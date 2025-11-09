from __future__ import annotations
import os
import time
import threading
import fnmatch
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext

# Optional: if user has 'xmlschema' installed, we can validate against XSD
try:
    import xmlschema  # type: ignore
    HAS_XMLSCHEMA = True
except Exception:
    HAS_XMLSCHEMA = False

# ---------- Persistence ----------
import json

def _state_path() -> Path:
    base = Path.home() / ".rct"
    base.mkdir(parents=True, exist_ok=True)
    return base / "xml_checker.json"

def _load_state() -> Dict[str, Any]:
    p = _state_path()
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def _save_state(data: Dict[str, Any]) -> None:
    try:
        _state_path().write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

# ---------- Data ----------
@dataclass
class Finding:
    when: float
    severity: str   # "ERROR" | "WARNING" | "INFO"
    path: Path
    line: Optional[int]
    column: Optional[int]
    message: str

# ---------- Helpers ----------
def _is_xml_file(p: Path) -> bool:
    return p.is_file() and p.suffix.lower() == ".xml"

def _iter_xml_targets(target: Path, recursive: bool) -> List[Path]:
    if target.is_file():
        return [target] if _is_xml_file(target) else []
    if not target.is_dir():
        return []
    if recursive:
        return [p for p in target.rglob("*.xml") if p.is_file()]
    else:
        return [p for p in target.glob("*.xml") if p.is_file()]

def _match_any(path: Path, patterns: List[str]) -> bool:
    """Glob-match against basename and full posix path."""
    if not patterns:
        return False
    s = path.as_posix()
    b = path.name
    for pat in patterns:
        pat = pat.strip()
        if not pat:
            continue
        if fnmatch.fnmatch(b, pat) or fnmatch.fnmatch(s, pat):
            return True
    return False

def _read_first_kb(p: Path, n: int = 2048) -> str:
    try:
        with p.open("rb") as f:
            return f.read(n).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def _check_warnings_preparse(text_head: str) -> List[str]:
    warns = []
    # Simple heuristic: DOCTYPE usage (often okay, but can be risky / unexpected)
    if "<!DOCTYPE" in text_head:
        warns.append("Document declares a DOCTYPE.")
    # XML declaration multiple times?
    if text_head.count("<?xml") > 1:
        warns.append("Multiple XML declarations detected near start.")
    return warns

def _validate_xml_etree(p: Path) -> Tuple[List[Finding], Optional[ET.ElementTree]]:
    findings: List[Finding] = []
    head = _read_first_kb(p)
    for w in _check_warnings_preparse(head):
        findings.append(Finding(time.time(), "WARNING", p, None, None, w))
    try:
        tree = ET.parse(p)
        return findings, tree
    except ET.ParseError as e:
        # e.position is (line, column)
        line, col = getattr(e, "position", (None, None))
        findings.append(Finding(time.time(), "ERROR", p, line, col, f"ParseError: {e}"))
        return findings, None
    except Exception as e:
        findings.append(Finding(time.time(), "ERROR", p, None, None, f"Error: {e}"))
        return findings, None

def _validate_with_xsd(tree: ET.ElementTree, schema_path: Path, xml_path: Path) -> List[Finding]:
    """Validate against XSD if xmlschema is available."""
    if not HAS_XMLSCHEMA:
        return [Finding(time.time(), "WARNING", xml_path, None, None,
                        "XSD validation requested but 'xmlschema' is not installed.")]
    try:
        xs = xmlschema.XMLSchema(str(schema_path))
        # xmlschema expects source as path or string; give file path
        xs.validate(str(xml_path))
        return []  # valid
    except xmlschema.validators.exceptions.XMLSchemaValidationError as e:  # type: ignore
        # The error often carries a line/column if available
        line = getattr(e, "position", (None, None))[0] if hasattr(e, "position") else None
        col = getattr(e, "position", (None, None))[1] if hasattr(e, "position") else None
        return [Finding(time.time(), "ERROR", xml_path, line, col, f"XSD validation error: {e}")]
    except Exception as e:
        return [Finding(time.time(), "ERROR", xml_path, None, None, f"XSD validator error: {e}")]

# ---------- Plugin ----------
class XmlCheckerTool:
    key = "xml_checker"
    title = "XML Checker"
    description = "Watch a folder or file for XML changes. Blacklist files/folders. Flags parse and (optional) XSD errors."

    def __init__(self):
        self.ctx: Optional[AppContext] = None
        self._ui_mode = "standard"

        # UI vars
        self.target_var: Optional[tb.StringVar] = None
        self.recursive_var: Optional[tb.BooleanVar] = None
        self.interval_var: Optional[tb.DoubleVar] = None
        self.blacklist_var: Optional[tb.StringVar] = None  # semicolon-separated globs
        self.scan_on_start_var: Optional[tb.BooleanVar] = None

        self.xsd_enable_var: Optional[tb.BooleanVar] = None
        self.xsd_path_var: Optional[tb.StringVar] = None

        # Presets
        self._state: Dict[str, Any] = {}
        self.preset_var: Optional[tb.StringVar] = None
        self.preset_combo = None

        # Pro widgets
        self.pro_frame = None
        self.results_tv = None
        self.log = None
        self.summary_var = None

        # Watcher
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._mtimes: Dict[Path, float] = {}

        self.panel = None

    # ----- UI -----
    def make_panel(self, master, context: AppContext):
        self.ctx = context
        self._ui_mode = context.ui_mode
        self._state = _load_state()

        root = tb.Frame(master)

        # Presets
        pr = tb.Frame(root); pr.pack(fill="x", padx=8, pady=(8,6))
        tb.Label(pr, text="Preset:").pack(side="left")
        self.preset_var = tb.StringVar(value=self._initial_preset_value())
        self.preset_combo = tb.Combobox(pr, textvariable=self.preset_var, state="readonly", width=30)
        self._refresh_preset_combo()
        self.preset_combo.pack(side="left", padx=6)
        self.preset_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_preset_from_combo())
        tb.Button(pr, text="Save as…", command=self._save_as_preset, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(pr, text="Delete", command=self._delete_preset, bootstyle="warning").pack(side="left", padx=4)

        # Target + options
        basic = tb.Labelframe(root, text="Target & Options")
        basic.pack(fill="x", padx=8, pady=(0,8))

        r1 = tb.Frame(basic); r1.pack(fill="x", padx=8, pady=6)
        tb.Label(r1, text="Folder or XML file:").pack(side="left")
        self.target_var = tb.StringVar()
        tb.Entry(r1, textvariable=self.target_var).pack(side="left", fill="x", expand=True, padx=6)
        tb.Button(r1, text="Pick", command=self._pick_target, bootstyle="secondary").pack(side="left")

        r2 = tb.Frame(basic); r2.pack(fill="x", padx=8, pady=6)
        self.recursive_var = tb.BooleanVar(value=True)
        self.interval_var = tb.DoubleVar(value=2.0)
        self.blacklist_var = tb.StringVar(value="*/.git/*;*/node_modules/*;*.bak;*.tmp")
        self.scan_on_start_var = tb.BooleanVar(value=True)
        tb.Checkbutton(r2, text="Recursive", variable=self.recursive_var).pack(side="left", padx=6)
        tb.Label(r2, text="Watch interval (s):").pack(side="left", padx=(10,4))
        tb.Spinbox(r2, from_=0.2, to=60.0, increment=0.2, textvariable=self.interval_var, width=6).pack(side="left")
        tb.Checkbutton(r2, text="Scan all at start", variable=self.scan_on_start_var).pack(side="left", padx=10)

        r3 = tb.Frame(basic); r3.pack(fill="x", padx=8, pady=6)
        tb.Label(r3, text="Blacklist globs (;) :").pack(side="left")
        tb.Entry(r3, textvariable=self.blacklist_var).pack(side="left", fill="x", expand=True, padx=6)

        # XSD (optional)
        r4 = tb.Frame(basic); r4.pack(fill="x", padx=8, pady=6)
        self.xsd_enable_var = tb.BooleanVar(value=False)
        self.xsd_path_var = tb.StringVar(value="")
        tb.Checkbutton(r4, text="Validate against XSD", variable=self.xsd_enable_var,
                       state=("normal" if HAS_XMLSCHEMA else "disabled")).pack(side="left")
        tb.Entry(r4, textvariable=self.xsd_path_var, width=40,
                 state=("normal" if HAS_XMLSCHEMA else "disabled")).pack(side="left", padx=6)
        tb.Button(r4, text="Pick XSD", command=self._pick_xsd, bootstyle="secondary",
                  state=("normal" if HAS_XMLSCHEMA else "disabled")).pack(side="left")

        # Actions
        actions = tb.Frame(root); actions.pack(fill="x", padx=8, pady=(0,8))
        tb.Button(actions, text="Scan once", command=self._scan_once, bootstyle="success").pack(side="left", padx=4)
        tb.Button(actions, text="Start watch", command=self._start_watch, bootstyle="info").pack(side="left", padx=4)
        tb.Button(actions, text="Stop watch", command=self._stop_watch, bootstyle="warning").pack(side="left", padx=4)
        tb.Button(actions, text="Clear results", command=self._clear_results, bootstyle="secondary").pack(side="left", padx=4)

        # Pro: results table + log + summary
        self.pro_frame = tb.Labelframe(root, text="Results (Pro)")
        self.results_tv = tb.Treeview(self.pro_frame, columns=("when","sev","file","pos","msg"),
                                      show="headings", height=12)
        self.results_tv.heading("when", text="Time")
        self.results_tv.heading("sev", text="Severity")
        self.results_tv.heading("file", text="File")
        self.results_tv.heading("pos", text="Line:Col")
        self.results_tv.heading("msg", text="Message")
        self.results_tv.column("when", width=120, anchor="w")
        self.results_tv.column("sev", width=80, anchor="w")
        self.results_tv.column("file", width=360, anchor="w")
        self.results_tv.column("pos", width=80, anchor="w")
        self.results_tv.column("msg", width=520, anchor="w")
        self.results_tv.pack(fill="both", expand=True, padx=8, pady=(8,6))

        self.log = tb.ScrolledText(self.pro_frame, height=6)
        self.log.pack(fill="both", expand=True, padx=8, pady=(0,8))
        self.summary_var = tb.StringVar(value="Ready.")
        tb.Label(self.pro_frame, textvariable=self.summary_var, bootstyle="secondary").pack(anchor="w", padx=8, pady=(0,8))

        if self._ui_mode == "pro":
            self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Load last used
        self._apply_last_used()

        self.panel = root
        return root

    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        # Seed target from right-click selection (prefer folder; else XML file)
        for t in targets or []:
            p = Path(t)
            if p.is_dir():
                self.target_var.set(str(p)); break
            if p.is_file() and p.suffix.lower() == ".xml":
                self.target_var.set(str(p))
                break

        if not self.target_var.get().strip():
            self._apply_last_used()

        # Optional: kickoff a quick scan in Pro for feedback
        if self._ui_mode == "pro" and self.target_var.get().strip():
            self._scan_once()

    def cleanup(self):
        self._stop_watch()
        self._persist_last_used()

    def on_mode_changed(self, ui_mode: str):
        self._ui_mode = ui_mode
        if ui_mode == "pro":
            if not self.pro_frame.winfo_ismapped():
                self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
        else:
            if self.pro_frame.winfo_ismapped():
                self.pro_frame.pack_forget()

    # ----- Presets -----
    def _initial_preset_value(self) -> str:
        st = _load_state()
        names = [p.get("name") for p in st.get("presets", []) if "name" in p]
        return "(last used)" if st.get("last") else (names[0] if names else "(none)")

    def _refresh_preset_combo(self):
        st = _load_state()
        names = ["(last used)"] + [p.get("name","") for p in st.get("presets", [])]
        self.preset_combo.configure(values=names)

    def _apply_preset_from_combo(self):
        name = self.preset_var.get().strip()
        if name == "(last used)":
            self._apply_last_used(); return
        st = _load_state()
        for p in st.get("presets", []):
            if p.get("name") == name:
                self._apply_snapshot(p); return

    def _save_as_preset(self):
        prompt = tb.Toplevel(master=self.panel)
        prompt.title("Save Preset"); prompt.geometry("360x150")
        frm = tb.Frame(prompt, padding=10); frm.pack(fill="both", expand=True)
        tb.Label(frm, text="Preset name:").pack(anchor="w")
        name_var = tb.StringVar()
        tb.Entry(frm, textvariable=name_var).pack(fill="x", pady=6)
        btns = tb.Frame(frm); btns.pack(fill="x", pady=(6,0))
        def ok():
            name = name_var.get().strip()
            if not name:
                Messagebox.show_warning("Enter a name."); return
            st = _load_state()
            snap = self._snapshot(); snap["name"] = name
            arr = st.get("presets", [])
            # replace if exists
            for i, p in enumerate(arr):
                if p.get("name") == name:
                    arr[i] = snap; break
            else:
                arr.append(snap)
            st["presets"] = arr
            _save_state(st)
            self._refresh_preset_combo()
            self.preset_var.set(name)
            prompt.destroy()
        tb.Button(btns, text="Save", command=ok, bootstyle="success").pack(side="right", padx=6)
        tb.Button(btns, text="Cancel", command=prompt.destroy, bootstyle="secondary").pack(side="right")

    def _delete_preset(self):
        name = self.preset_var.get().strip()
        if name in ("(last used)", "(none)", ""):
            Messagebox.show_info("Select a saved preset to delete."); return
        st = _load_state()
        arr = [p for p in st.get("presets", []) if p.get("name") != name]
        st["presets"] = arr
        _save_state(st)
        self._refresh_preset_combo()
        self.preset_var.set("(last used)" if st.get("last") else "(none)")

    def _snapshot(self) -> Dict[str, Any]:
        return {
            "target": self.target_var.get().strip(),
            "recursive": bool(self.recursive_var.get()),
            "interval": float(self.interval_var.get() or 2.0),
            "blacklist": self.blacklist_var.get().strip(),
            "scan_on_start": bool(self.scan_on_start_var.get()),
            "xsd_enable": bool(self.xsd_enable_var.get()),
            "xsd_path": self.xsd_path_var.get().strip(),
        }

    def _apply_snapshot(self, snap: Dict[str, Any]):
        self.target_var.set(snap.get("target",""))
        self.recursive_var.set(bool(snap.get("recursive", True)))
        self.interval_var.set(float(snap.get("interval", 2.0)))
        self.blacklist_var.set(snap.get("blacklist",""))
        self.scan_on_start_var.set(bool(snap.get("scan_on_start", True)))
        self.xsd_enable_var.set(bool(snap.get("xsd_enable", False)) and HAS_XMLSCHEMA)
        self.xsd_path_var.set(snap.get("xsd_path",""))

    def _apply_last_used(self):
        st = _load_state()
        last = st.get("last")
        if last:
            self._apply_snapshot(last)

    def _persist_last_used(self):
        st = _load_state()
        st["last"] = self._snapshot()
        _save_state(st)

    # ----- Browsers -----
    def _pick_target(self):
        from tkinter import filedialog
        # Ask directory first; if cancelled, ask for file
        d = filedialog.askdirectory(title="Select folder (Cancel for file)")
        if d:
            self.target_var.set(d)
            return
        f = filedialog.askopenfilename(title="Select XML file", filetypes=[("XML files","*.xml"),("All files","*.*")])
        if f:
            self.target_var.set(f)

    def _pick_xsd(self):
        from tkinter import filedialog
        p = filedialog.askopenfilename(title="Select XSD file", filetypes=[("XSD files","*.xsd"),("All files","*.*")])
        if p:
            self.xsd_path_var.set(p)

    # ----- Actions -----
    def _validate_inputs(self) -> Optional[Tuple[Path, bool, float, List[str]]]:
        target = Path(self.target_var.get().strip())
        if not target.exists():
            Messagebox.show_warning("Pick a valid folder or XML file.")
            return None
        rec = bool(self.recursive_var.get())
        try:
            interval = max(0.2, float(self.interval_var.get() or 2.0))
        except Exception:
            interval = 2.0
        bl = [s.strip() for s in (self.blacklist_var.get() or "").split(";") if s.strip()]
        return target, rec, interval, bl

    def _scan_once(self):
        args = self._validate_inputs()
        if not args:
            return
        target, rec, _interval, blacklist = args
        self._log("[SCAN] Starting scan…")
        paths = _iter_xml_targets(target, rec)
        n_err = n_warn = 0
        for p in paths:
            if _match_any(p, blacklist):
                continue
            findings = self._check_one(p)
            for f in findings:
                self._report_finding(f)
                if f.severity == "ERROR": n_err += 1
                elif f.severity == "WARNING": n_warn += 1
        self._set_summary(f"Scan complete. Errors: {n_err}, Warnings: {n_warn}, Files: {len(paths)}.")

    def _start_watch(self):
        args = self._validate_inputs()
        if not args:
            return
        target, rec, interval, blacklist = args
        if self._worker and self._worker.is_alive():
            Messagebox.show_info("Watch already running.")
            return

        # Initialize mtimes
        self._mtimes.clear()
        xmls = _iter_xml_targets(target, rec)
        for p in xmls:
            try:
                if not _match_any(p, blacklist):
                    self._mtimes[p] = p.stat().st_mtime
            except Exception:
                pass

        if bool(self.scan_on_start_var.get()):
            self._scan_once()

        self._stop_event.clear()
        self._worker = threading.Thread(target=self._watch_loop, args=(target, rec, interval, blacklist), daemon=True)
        self._worker.start()
        self._log(f"[WATCH] Started (every {interval:.1f}s).")

    def _stop_watch(self):
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._log("[WATCH] Stopping…")

    def _watch_loop(self, target: Path, rec: bool, interval: float, blacklist: List[str]):
        try:
            while not self._stop_event.is_set():
                xmls = _iter_xml_targets(target, rec)
                seen = set()
                for p in xmls:
                    if _match_any(p, blacklist):
                        continue
                    seen.add(p)
                    try:
                        mt = p.stat().st_mtime
                    except Exception:
                        continue
                    old = self._mtimes.get(p)
                    if old is None:
                        # new file -> treat as update
                        self._mtimes[p] = mt
                        self._on_file_changed(p)
                    elif mt > old + 1e-6:
                        self._mtimes[p] = mt
                        self._on_file_changed(p)
                # purge deleted
                for tracked in list(self._mtimes.keys()):
                    if tracked not in seen:
                        self._mtimes.pop(tracked, None)
                # sleep in small chunks so stop is responsive
                end = time.time() + interval
                while time.time() < end and not self._stop_event.is_set():
                    time.sleep(min(0.2, end - time.time()))
        finally:
            self._stop_event.clear()
            self._log("[WATCH] Stopped.")

    # ----- Checking -----
    def _on_file_changed(self, p: Path):
        self._log(f"[CHANGE] {p}")
        findings = self._check_one(p)
        n_err = sum(1 for f in findings if f.severity == "ERROR")
        n_warn = sum(1 for f in findings if f.severity == "WARNING")
        if not findings:
            self._report_finding(Finding(time.time(), "INFO", p, None, None, "OK"))
        else:
            for f in findings:
                self._report_finding(f)
        self._set_summary(f"Last change: {p.name} — Errors: {n_err}, Warnings: {n_warn}")

    def _check_one(self, p: Path) -> List[Finding]:
        findings, tree = _validate_xml_etree(p)
        # Optional XSD
        if tree is not None and bool(self.xsd_enable_var.get()) and self.xsd_path_var.get().strip():
            xsd = Path(self.xsd_path_var.get().strip())
            if xsd.exists():
                findings.extend(_validate_with_xsd(tree, xsd, p))
            else:
                findings.append(Finding(time.time(), "WARNING", p, None, None, f"XSD not found: {xsd}"))
        return findings

    # ----- UI updates (thread-safe) -----
    def _report_finding(self, f: Finding):
        # Push into UI via .after to stay thread-safe
        if self._ui_mode == "pro" and self.results_tv and self.results_tv.winfo_exists():
            when_str = time.strftime("%H:%M:%S", time.localtime(f.when))
            pos = "-" if f.line is None else f"{f.line}:{f.column or 0}"
            vals = (when_str, f.severity, str(f.path), pos, f.message)
            self.results_tv.after(0, lambda v=vals: self.results_tv.insert("", "end", values=v))
        else:
            # In Standard mode, only pop modal for errors
            if f.severity == "ERROR":
                try:
                    Messagebox.show_error(message=f"{f.path.name}\n{f.message}", title="XML Error")
                except Exception:
                    pass

    def _log(self, msg: str):
        if self._ui_mode != "pro" or not self.log:
            return
        try:
            self.log.insert("end", msg + "\n")
            self.log.see("end")
        except Exception:
            pass

    def _set_summary(self, text: str):
        if self._ui_mode == "pro" and self.summary_var:
            try:
                self.summary_var.set(text)
            except Exception:
                pass

    def _clear_results(self):
        if self.results_tv:
            try:
                self.results_tv.delete(*self.results_tv.get_children())
            except Exception:
                pass
        if self.log:
            try:
                self.log.delete("1.0", "end")
            except Exception:
                pass
        self._set_summary("Cleared.")

PLUGIN = XmlCheckerTool()


if __name__ == "__main__":
    from plugins.base import run_plugin_standalone

    run_plugin_standalone(PLUGIN)
