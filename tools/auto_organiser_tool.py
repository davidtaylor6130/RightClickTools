from __future__ import annotations
import os
import re
import shutil
import threading
import time
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext

# ===================== State persistence =====================

def _state_path() -> Path:
    base = Path.home() / ".rct"
    base.mkdir(parents=True, exist_ok=True)
    return base / "auto_organiser.json"

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

# ===================== Data =====================

@dataclass
class OrganiseSpec:
    base: Path
    pattern: str
    recursive: bool = True
    move_instead_of_copy: bool = True
    overwrite: bool = False
    group_root: str = "next_to_file"  # or "under_base"
    interval_s: float = 0.0           # 0 = no auto

# ===================== Pattern handling =====================

def build_regex_from_pattern(pattern: str) -> Tuple[re.Pattern, Optional[str]]:
    """
    Convert a human-friendly pattern to a compiled regex against the FILENAME (not path).
    Tokens:
      - %DONTCARE%  ->  .*?
      - %FACTOR%    ->  (?P<factor>.+?)
    Everything else is treated literally.

    Returns (compiled_regex, fallback_factor_literal)
    The fallback is the longest literal chunk in the pattern (no tokens).
    """
    # Split on tokens to identify literal chunks
    token_re = re.compile(r'%DONTCARE%|%FACTOR%')
    parts = token_re.split(pattern)
    tokens = token_re.findall(pattern)

    # Longest literal fallback (strip extension dots if you like; we keep as-is but it usually excludes .txt anyway)
    literal_chunks = [p for p in parts if p]
    fallback = max(literal_chunks, key=len) if literal_chunks else None

    # Rebuild to regex
    out = []
    # We iterate through interleaved parts/tokens
    it_parts = iter(parts)
    it_tokens = iter(tokens)
    for i, part in enumerate(parts):
        # part is literal
        out.append(re.escape(part))
        # append token translation if any (peek from tokens by index)
        # but since we’re iterating parts directly, we need to add the token that follows this part (if any)
        try:
            tok = next(it_tokens)
        except StopIteration:
            tok = None
        if tok:
            if tok == "%DONTCARE%":
                out.append(r".*?")
            elif tok == "%FACTOR%":
                out.append(r"(?P<factor>.+?)")
    # Anchor to anywhere in filename: use search, so no ^$
    rx = re.compile("".join(out), re.IGNORECASE)
    return rx, fallback

def extract_factor(rx: re.Pattern, fname: str, fallback_literal: Optional[str]) -> Optional[str]:
    m = rx.search(fname)
    if not m:
        return None
    if "factor" in m.groupdict():
        fac = (m.group("factor") or "").strip()
        if fac:
            return fac
    # fallback to longest literal chunk if present in the match (or globally)
    return fallback_literal

# ===================== Core organiser logic =====================

def iter_files(base: Path, recursive: bool) -> List[Path]:
    if not base.exists():
        return []
    if recursive:
        return [p for p in base.rglob("*") if p.is_file()]
    else:
        return [p for p in base.glob("*") if p.is_file()]

def resolve_dest_for(file: Path, factor: str, spec: OrganiseSpec) -> Path:
    if spec.group_root == "under_base":
        return spec.base / factor / file.name
    # default: next to the file
    return file.parent / factor / file.name

def safe_ensure_dir(d: Path):
    d.mkdir(parents=True, exist_ok=True)

def safe_copy_or_move(src: Path, dst: Path, move: bool, overwrite: bool) -> Tuple[bool, Path, str]:
    """
    Returns (ok, final_dst, msg)
    If overwrite is False and dst exists, we append ' (1)', ' (2)', etc. before suffix.
    """
    final = dst
    if final.exists():
        if overwrite:
            pass
        else:
            stem = final.stem
            suffix = final.suffix
            parent = final.parent
            i = 1
            while final.exists():
                final = parent / f"{stem} ({i}){suffix}"
                i += 1
    try:
        if move:
            # If overwriting and target exists, remove it first
            if overwrite and dst.exists():
                dst.unlink(missing_ok=True)
            safe_ensure_dir(final.parent)
            shutil.move(str(src), str(final))
            return True, final, f"[MOVE] {src} -> {final}"
        else:
            safe_ensure_dir(final.parent)
            shutil.copy2(str(src), str(final))
            return True, final, f"[COPY] {src} -> {final}"
    except Exception as e:
        return False, final, f"[ERROR] {src}: {e}"

# ===================== Plugin =====================

class AutoOrganiserTool:
    key = "auto_organiser"
    title = "Auto File Organiser"
    description = "Group files by a pattern into folders named by the common factor. Tokens: %DONTCARE%, %FACTOR%."

    def __init__(self):
        self.ctx: Optional[AppContext] = None
        self._ui_mode = "standard"

        # UI vars
        self.base_var: Optional[tb.StringVar] = None
        self.pattern_var: Optional[tb.StringVar] = None
        self.recursive_var: Optional[tb.BooleanVar] = None
        self.move_var: Optional[tb.BooleanVar] = None
        self.overwrite_var: Optional[tb.BooleanVar] = None
        self.root_mode_var: Optional[tb.StringVar] = None  # next_to_file / under_base
        self.interval_var: Optional[tb.DoubleVar] = None

        # Presets
        self._state: Dict[str, Any] = {}
        self.preset_var: Optional[tb.StringVar] = None
        self.preset_combo = None

        # Pro UI
        self.pro_frame = None
        self.preview_tv = None
        self.log = None

        # Auto thread
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self.panel = None

    # ---------- UI ----------
    def make_panel(self, master, context: AppContext):
        self.ctx = context
        self._ui_mode = context.ui_mode
        self._state = _load_state()

        root = tb.Frame(master)

        # Presets row
        pr = tb.Frame(root); pr.pack(fill="x", padx=8, pady=(8,6))
        tb.Label(pr, text="Preset:").pack(side="left")
        self.preset_var = tb.StringVar(value=self._initial_preset_value())
        self.preset_combo = tb.Combobox(pr, textvariable=self.preset_var, state="readonly", width=30)
        self._refresh_preset_combo()
        self.preset_combo.pack(side="left", padx=6)
        self.preset_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_preset_from_combo())
        tb.Button(pr, text="Save as…", command=self._save_as_preset, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(pr, text="Delete", command=self._delete_preset, bootstyle="warning").pack(side="left", padx=4)

        # Basic settings
        basic = tb.Labelframe(root, text="Settings")
        basic.pack(fill="x", padx=8, pady=(0,8))

        row1 = tb.Frame(basic); row1.pack(fill="x", padx=8, pady=6)
        tb.Label(row1, text="Base folder:").pack(side="left")
        self.base_var = tb.StringVar()
        tb.Entry(row1, textvariable=self.base_var).pack(side="left", fill="x", expand=True, padx=6)
        tb.Button(row1, text="Pick", command=self._pick_base, bootstyle="secondary").pack(side="left")

        row2 = tb.Frame(basic); row2.pack(fill="x", padx=8, pady=6)
        tb.Label(row2, text="Pattern:").pack(side="left")
        self.pattern_var = tb.StringVar(value="%DONTCARE%Day_%FACTOR%%DONTCARE%.txt")
        tb.Entry(row2, textvariable=self.pattern_var).pack(side="left", fill="x", expand=True, padx=6)

        row3 = tb.Frame(basic); row3.pack(fill="x", padx=8, pady=6)
        self.recursive_var = tb.BooleanVar(value=True)
        self.move_var = tb.BooleanVar(value=True)
        self.overwrite_var = tb.BooleanVar(value=False)
        self.root_mode_var = tb.StringVar(value="next_to_file")
        self.interval_var = tb.DoubleVar(value=0.0)
        tb.Checkbutton(row3, text="Recursive", variable=self.recursive_var).pack(side="left", padx=6)
        tb.Checkbutton(row3, text="Move files (uncheck = copy)", variable=self.move_var).pack(side="left", padx=6)
        tb.Checkbutton(row3, text="Overwrite on conflict", variable=self.overwrite_var).pack(side="left", padx=6)

        row4 = tb.Frame(basic); row4.pack(fill="x", padx=8, pady=6)
        tb.Label(row4, text="Group into:").pack(side="left")
        tb.Combobox(row4, textvariable=self.root_mode_var, state="readonly",
                    values=["next_to_file","under_base"], width=14).pack(side="left", padx=6)
        tb.Label(row4, text="Auto interval (sec):").pack(side="left", padx=(16,4))
        tb.Spinbox(row4, from_=0.0, to=86400.0, increment=1.0,
                   textvariable=self.interval_var, width=8).pack(side="left")

        # Actions
        actions = tb.Frame(root); actions.pack(fill="x", padx=8, pady=(0,8))
        tb.Button(actions, text="Preview", command=self._preview, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(actions, text="Organise once", command=self._organise_once, bootstyle="success").pack(side="left", padx=4)
        tb.Button(actions, text="Start auto", command=self._start_auto, bootstyle="info").pack(side="left", padx=4)
        tb.Button(actions, text="Stop auto", command=self._stop_auto, bootstyle="warning").pack(side="left", padx=4)

        # Pro: preview + log
        self.pro_frame = tb.Labelframe(root, text="Preview & Log (Pro)")
        pv = tb.Frame(self.pro_frame); pv.pack(fill="both", expand=True, padx=8, pady=6)
        self.preview_tv = tb.Treeview(pv, columns=("file","factor","dest"), show="headings", height=10)
        self.preview_tv.heading("file", text="File")
        self.preview_tv.heading("factor", text="Factor")
        self.preview_tv.heading("dest", text="Destination")
        self.preview_tv.column("file", width=300, anchor="w")
        self.preview_tv.column("factor", width=120, anchor="w")
        self.preview_tv.column("dest", width=360, anchor="w")
        self.preview_tv.pack(fill="both", expand=True)
        self.log = tb.ScrolledText(self.pro_frame, height=8)
        if self._ui_mode == "pro":
            self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
            self.log.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Load last used
        self._apply_last_used()

        self.panel = root
        return root

    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        # If launched with a folder, use it as base
        for t in targets or []:
            p = Path(t)
            if p.is_dir():
                self.base_var.set(str(p))
                break

        # If nothing, use last used
        if not self.base_var.get().strip():
            self._apply_last_used()

    def cleanup(self):
        self._stop_auto()
        self._persist_last_used()

    def on_mode_changed(self, ui_mode: str):
        self._ui_mode = ui_mode
        if ui_mode == "pro":
            if not self.pro_frame.winfo_ismapped():
                self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
                self.log.pack(fill="both", expand=True, padx=8, pady=(0,8))
        else:
            if self.pro_frame.winfo_ismapped():
                self.pro_frame.pack_forget()

    # ---------- Presets ----------
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
        prompt.title("Save Preset"); prompt.geometry("320x140")
        frm = tb.Frame(prompt, padding=10); frm.pack(fill="both", expand=True)
        tb.Label(frm, text="Preset name:").pack(anchor="w")
        name_var = tb.StringVar()
        tb.Entry(frm, textvariable=name_var).pack(fill="x", pady=6)
        btns = tb.Frame(frm); btns.pack(fill="x", pady=(6,0))
        def ok():
            name = name_var.get().strip()
            if not name: Messagebox.show_warning("Enter a name."); return
            st = _load_state()
            snap = self._snapshot(); snap["name"] = name
            arr = st.get("presets", [])
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
            "base": self.base_var.get().strip(),
            "pattern": self.pattern_var.get().strip(),
            "recursive": bool(self.recursive_var.get()),
            "move_instead_of_copy": bool(self.move_var.get()),
            "overwrite": bool(self.overwrite_var.get()),
            "group_root": self.root_mode_var.get().strip() or "next_to_file",
            "interval_s": float(self.interval_var.get() or 0.0),
        }

    def _apply_snapshot(self, snap: Dict[str, Any]):
        self.base_var.set(snap.get("base",""))
        self.pattern_var.set(snap.get("pattern",""))
        self.recursive_var.set(bool(snap.get("recursive", True)))
        self.move_var.set(bool(snap.get("move_instead_of_copy", True)))
        self.overwrite_var.set(bool(snap.get("overwrite", False)))
        self.root_mode_var.set(snap.get("group_root", "next_to_file"))
        self.interval_var.set(float(snap.get("interval_s", 0.0)))

    def _apply_last_used(self):
        st = _load_state()
        last = st.get("last")
        if last:
            self._apply_snapshot(last)

    def _persist_last_used(self):
        st = _load_state()
        st["last"] = self._snapshot()
        _save_state(st)

    # ---------- Browsers ----------
    def _pick_base(self):
        from tkinter import filedialog
        p = filedialog.askdirectory(title="Select base folder")
        if p:
            self.base_var.set(p)

    # ---------- Preview / Run ----------
    def _validate(self) -> Optional[OrganiseSpec]:
        base = Path(self.base_var.get().strip())
        if not base.exists() or not base.is_dir():
            Messagebox.show_warning("Pick a valid base folder."); return None
        pattern = self.pattern_var.get().strip()
        if not pattern:
            Messagebox.show_warning("Enter a pattern using %DONTCARE% and/or %FACTOR%."); return None
        spec = OrganiseSpec(
            base=base,
            pattern=pattern,
            recursive=bool(self.recursive_var.get()),
            move_instead_of_copy=bool(self.move_var.get()),
            overwrite=bool(self.overwrite_var.get()),
            group_root=self.root_mode_var.get().strip() or "next_to_file",
            interval_s=float(self.interval_var.get() or 0.0),
        )
        return spec

    def _scan_matches(self, spec: OrganiseSpec) -> List[Tuple[Path, str, Path]]:
        rx, fallback = build_regex_from_pattern(spec.pattern)
        files = iter_files(spec.base, spec.recursive)
        results: List[Tuple[Path, str, Path]] = []
        for f in files:
            fac = extract_factor(rx, f.name, fallback)
            if not fac:
                continue
            dst = resolve_dest_for(f, fac, spec)
            results.append((f, fac, dst))
        return results

    def _preview(self):
        spec = self._validate()
        if not spec: return
        self._persist_last_used()
        rows = self._scan_matches(spec)
        if self._ui_mode == "pro":
            self.preview_tv.delete(*self.preview_tv.get_children())
            for f, fac, dst in rows:
                self.preview_tv.insert("", "end", values=(str(f), fac, str(dst)))
            self._log(f"[PREVIEW] {len(rows)} file(s) matched.")
        else:
            Messagebox.show_info(f"{len(rows)} file(s) matched.")

    def _organise_once(self):
        spec = self._validate()
        if not spec: return
        self._persist_last_used()
        t = threading.Thread(target=self._do_pass, args=(spec,), daemon=True)
        t.start()

    def _start_auto(self):
        spec = self._validate()
        if not spec: return
        if spec.interval_s <= 0:
            Messagebox.show_warning("Set Auto interval > 0 to start auto mode."); return
        if self._worker and self._worker.is_alive():
            Messagebox.show_info("Auto organiser already running."); return
        self._persist_last_used()
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._auto_loop, args=(spec,), daemon=True)
        self._worker.start()
        self._log(f"[AUTO] Started every {spec.interval_s:.0f}s.")

    def _stop_auto(self):
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._log("[AUTO] Stopping…")

    def _auto_loop(self, spec: OrganiseSpec):
        try:
            while not self._stop_event.is_set():
                self._do_pass(spec)
                # sleep in small chunks so Stop is responsive
                end = time.time() + spec.interval_s
                while time.time() < end and not self._stop_event.is_set():
                    time.sleep(min(0.2, end - time.time()))
        finally:
            self._stop_event.clear()
            self._log("[AUTO] Stopped.")

    def _do_pass(self, spec: OrganiseSpec):
        rows = self._scan_matches(spec)
        # Do the operations
        moved = 0
        for src, factor, dst in rows:
            ok, final, msg = safe_copy_or_move(src, dst, move=spec.move_instead_of_copy, overwrite=spec.overwrite)
            moved += 1 if ok else 0
            self._log(msg)
        if rows:
            self._log(f"[DONE] {moved}/{len(rows)} processed.")

    # ---------- Logging ----------
    def _log(self, msg: str):
        if self._ui_mode != "pro" or not self.log:
            return
        try:
            self.log.insert("end", msg + "\n")
            self.log.see("end")
        except Exception:
            pass

PLUGIN = AutoOrganiserTool()