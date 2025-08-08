from __future__ import annotations
import shutil
import threading
import time
import json
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext

# =============== Storage ===============

def _state_path() -> Path:
    # Store per-user; avoid writing inside PyInstaller bundle
    base = Path.home() / ".rct"
    base.mkdir(parents=True, exist_ok=True)
    return base / "interval_copy.json"

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

# =============== Data ===============

@dataclass
class CopySpec:
    files: List[Path]              # exactly 3 paths
    dest: Path
    delay_s: float = 2.0
    overwrite: bool = True

# =============== Tool ===============

class IntervalCopyTool:
    key = "interval_copy"
    title = "Interval Copy (3 files)"
    description = "Copy three files to a destination with a gap between each. Presets + auto-copy supported."

    def __init__(self):
        self.ctx: Optional[AppContext] = None
        self._ui_mode = "standard"

        # UI state vars
        self.file_vars: List[tb.StringVar] = []
        self.dest_var: Optional[tb.StringVar] = None
        self.delay_var: Optional[tb.DoubleVar] = None
        self.overwrite_var: Optional[tb.BooleanVar] = None

        # Presets
        self.preset_var: Optional[tb.StringVar] = None
        self.preset_combo = None
        self._state: Dict[str, Any] = {}

        # Auto thread
        self._worker: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Pro UI
        self.pro_frame = None
        self.log = None

        self.panel = None

    # ---------- UI ----------
    def make_panel(self, master, context: AppContext):
        self.ctx = context
        self._ui_mode = context.ui_mode

        self._state = _load_state()

        root = tb.Frame(master)

        # Preset row
        pr = tb.Frame(root); pr.pack(fill="x", padx=8, pady=(8,6))
        tb.Label(pr, text="Preset:").pack(side="left")
        self.preset_var = tb.StringVar(value=self._initial_preset_value())
        self.preset_combo = tb.Combobox(pr, textvariable=self.preset_var, state="readonly", width=30)
        self._refresh_preset_combo()
        self.preset_combo.pack(side="left", padx=6)
        self.preset_combo.bind("<<ComboboxSelected>>", lambda e: self._apply_preset_from_combo())

        tb.Button(pr, text="Save as…", command=self._save_as_preset, bootstyle="secondary").pack(side="left", padx=4)
        tb.Button(pr, text="Delete", command=self._delete_preset, bootstyle="warning").pack(side="left", padx=4)

        # File pickers
        grid = tb.Labelframe(root, text="Files")
        grid.pack(fill="x", padx=8, pady=(0,8))

        self.file_vars = [tb.StringVar(), tb.StringVar(), tb.StringVar()]
        for i in range(3):
            row = tb.Frame(grid); row.pack(fill="x", padx=8, pady=6)
            tb.Label(row, text=f"File {i+1}:").pack(side="left")
            tb.Entry(row, textvariable=self.file_vars[i]).pack(side="left", fill="x", expand=True, padx=6)
            tb.Button(row, text="Browse", command=lambda idx=i: self._browse_file(idx),
                      bootstyle="secondary").pack(side="left")

        # Dest + options
        dest_row = tb.Labelframe(root, text="Destination & Options")
        dest_row.pack(fill="x", padx=8, pady=(0,8))
        self.dest_var = tb.StringVar()
        self.delay_var = tb.DoubleVar(value=2.0)
        self.overwrite_var = tb.BooleanVar(value=True)

        dr1 = tb.Frame(dest_row); dr1.pack(fill="x", padx=8, pady=6)
        tb.Label(dr1, text="Destination folder:").pack(side="left")
        tb.Entry(dr1, textvariable=self.dest_var).pack(side="left", fill="x", expand=True, padx=6)
        tb.Button(dr1, text="Pick", command=self._browse_dest, bootstyle="secondary").pack(side="left")

        dr2 = tb.Frame(dest_row); dr2.pack(fill="x", padx=8, pady=6)
        tb.Label(dr2, text="Delay (seconds):").pack(side="left")
        tb.Spinbox(dr2, from_=0.0, to=3600.0, increment=0.5,
                   textvariable=self.delay_var, width=8).pack(side="left", padx=6)
        tb.Checkbutton(dr2, text="Overwrite existing", variable=self.overwrite_var).pack(side="left", padx=8)

        # Actions
        actions = tb.Frame(root); actions.pack(fill="x", padx=8, pady=(0,8))
        tb.Button(actions, text="Copy once", command=self._copy_once, bootstyle="success").pack(side="left", padx=4)
        tb.Button(actions, text="Start auto", command=self._start_auto, bootstyle="info").pack(side="left", padx=4)
        tb.Button(actions, text="Stop auto", command=self._stop_auto, bootstyle="warning").pack(side="left", padx=4)

        # Pro-only: live log
        self.pro_frame = tb.Labelframe(root, text="Log (Pro)")
        self.log = tb.ScrolledText(self.pro_frame, height=12)
        if self._ui_mode == "pro":
            self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
            self.log.pack(fill="both", expand=True, padx=8, pady=6)

        # Load last used, if any
        self._apply_last_used()

        self.panel = root
        return root

    def start(self, context: AppContext, targets: List[Path], argv: List[str]):
        # If launched from right-click with 1–3 files and/or a folder,
        # auto-fill: first 3 files -> File1..3, first folder -> dest.
        files = []
        dest = None
        for t in targets or []:
            p = Path(t)
            if p.is_dir() and dest is None:
                dest = p
            elif p.is_file() and len(files) < 3:
                files.append(p)
        if files:
            for i, f in enumerate(files):
                self.file_vars[i].set(str(f))
        if dest:
            self.dest_var.set(str(dest))

        # Re-apply last used if nothing given
        if not files and not dest:
            self._apply_last_used()

    def cleanup(self):
        self._stop_auto()
        self._persist_last_used()

    def on_mode_changed(self, ui_mode: str):
        self._ui_mode = ui_mode
        if ui_mode == "pro":
            if not self.pro_frame.winfo_ismapped():
                self.pro_frame.pack(fill="both", expand=True, padx=8, pady=(0,8))
                self.log.pack(fill="both", expand=True, padx=8, pady=6)
        else:
            if self.pro_frame.winfo_ismapped():
                self.pro_frame.pack_forget()

    # ---------- Presets ----------
    def _initial_preset_value(self) -> str:
        st = self._state
        names = [p.get("name") for p in st.get("presets", []) if "name" in p]
        return "(last used)" if st.get("last") else (names[0] if names else "(none)")

    def _refresh_preset_combo(self):
        st = self._state
        names = ["(last used)"] + [p.get("name","") for p in st.get("presets", [])]
        if not st.get("last"):  # if no last used yet, keep but it's empty
            pass
        self.preset_combo.configure(values=names)

    def _apply_preset_from_combo(self):
        name = self.preset_var.get().strip()
        if name == "(last used)":
            self._apply_last_used()
            return
        for p in self._state.get("presets", []):
            if p.get("name") == name:
                self._apply_snapshot(p)
                return

    def _save_as_preset(self):
        # Simple text input dialog using Messagebox.askyesno replacement: build a tiny prompt
        prompt = tb.Toplevel(master=self.panel)
        prompt.title("Save Preset")
        prompt.geometry("320x140")
        frm = tb.Frame(prompt, padding=10); frm.pack(fill="both", expand=True)
        tb.Label(frm, text="Preset name:").pack(anchor="w")
        name_var = tb.StringVar()
        tb.Entry(frm, textvariable=name_var).pack(fill="x", pady=6)
        btns = tb.Frame(frm); btns.pack(fill="x", pady=(6,0))
        def ok():
            name = name_var.get().strip()
            if not name:
                Messagebox.show_warning("Enter a name.")
                return
            snap = self._snapshot()
            snap["name"] = name
            arr = self._state.get("presets", [])
            # replace if exists
            for i, p in enumerate(arr):
                if p.get("name") == name:
                    arr[i] = snap; break
            else:
                arr.append(snap)
            self._state["presets"] = arr
            _save_state(self._state)
            self._refresh_preset_combo()
            self.preset_var.set(name)
            prompt.destroy()
        tb.Button(btns, text="Save", command=ok, bootstyle="success").pack(side="right", padx=6)
        tb.Button(btns, text="Cancel", command=prompt.destroy, bootstyle="secondary").pack(side="right")

    def _delete_preset(self):
        name = self.preset_var.get().strip()
        if name in ("(last used)", "(none)", ""):
            Messagebox.show_info("Select a saved preset to delete.")
            return
        arr = self._state.get("presets", [])
        arr = [p for p in arr if p.get("name") != name]
        self._state["presets"] = arr
        _save_state(self._state)
        self._refresh_preset_combo()
        self.preset_var.set("(last used)" if self._state.get("last") else "(none)")

    def _snapshot(self) -> Dict[str, Any]:
        return {
            "files": [self.file_vars[i].get().strip() for i in range(3)],
            "dest": self.dest_var.get().strip(),
            "delay_s": float(self.delay_var.get() or 0),
            "overwrite": bool(self.overwrite_var.get()),
        }

    def _apply_snapshot(self, snap: Dict[str, Any]):
        files = (snap.get("files") or [])[:3]
        while len(files) < 3:
            files.append("")
        for i in range(3):
            self.file_vars[i].set(files[i])
        self.dest_var.set(snap.get("dest",""))
        self.delay_var.set(float(snap.get("delay_s", 2.0)))
        self.overwrite_var.set(bool(snap.get("overwrite", True)))

    def _apply_last_used(self):
        last = self._state.get("last")
        if last:
            self._apply_snapshot(last)

    def _persist_last_used(self):
        self._state["last"] = self._snapshot()
        _save_state(self._state)

    # ---------- Browsers ----------
    def _browse_file(self, idx: int):
        from tkinter import filedialog
        p = filedialog.askopenfilename(title=f"Select File {idx+1}")
        if p:
            self.file_vars[idx].set(p)

    def _browse_dest(self):
        from tkinter import filedialog
        d = filedialog.askdirectory(title="Select Destination Folder")
        if d:
            self.dest_var.set(d)

    # ---------- Actions ----------
    def _validate_spec(self) -> Optional[CopySpec]:
        files = [Path(self.file_vars[i].get().strip()) for i in range(3)]
        if not all(f and f.exists() and f.is_file() for f in files):
            Messagebox.show_warning("Please pick three valid files.")
            return None
        dest = Path(self.dest_var.get().strip())
        if not dest or not dest.exists() or not dest.is_dir():
            Messagebox.show_warning("Please pick a valid destination folder.")
            return None
        delay = float(self.delay_var.get() or 0.0)
        if delay < 0:
            Messagebox.show_warning("Delay must be 0 or greater.")
            return None
        return CopySpec(files=files, dest=dest, delay_s=delay, overwrite=bool(self.overwrite_var.get()))

    def _copy_once(self):
        spec = self._validate_spec()
        if not spec:
            return
        self._persist_last_used()
        # run in thread so UI stays responsive
        t = threading.Thread(target=self._run_copy_sequence, args=(spec, False), daemon=True)
        t.start()

    def _start_auto(self):
        spec = self._validate_spec()
        if not spec:
            return
        if self._worker and self._worker.is_alive():
            Messagebox.show_info("Auto copy already running.")
            return
        self._persist_last_used()
        self._stop_event.clear()
        self._worker = threading.Thread(target=self._run_copy_sequence, args=(spec, True), daemon=True)
        self._worker.start()
        self._log("[AUTO] Started.")

    def _stop_auto(self):
        if self._worker and self._worker.is_alive():
            self._stop_event.set()
            self._log("[AUTO] Stopping…")
        else:
            # no-op
            pass

    # ---------- Copy logic ----------
    def _run_copy_sequence(self, spec: CopySpec, auto_loop: bool):
        """
        If auto_loop is True: continuously copy files, waiting spec.delay_s between each file,
        and immediately cycling back until stopped. If False: do one pass.
        """
        def copy_one(src: Path):
            try:
                dst = spec.dest / src.name
                if dst.exists() and not spec.overwrite:
                    self._log(f"[SKIP] {dst} exists.")
                else:
                    shutil.copy2(src, dst)
                    self._log(f"[COPY] {src} -> {dst}")
            except Exception as e:
                self._log(f"[ERROR] {src}: {e}")

        try:
            while True:
                for i, src in enumerate(spec.files):
                    if self._stop_event.is_set():
                        self._log("[AUTO] Stopped.")
                        return
                    copy_one(src)
                    # Wait gap between each file (even after the third if auto_loop continues)
                    # But if it's a single pass and we just did the last file, don't wait extra.
                    if spec.delay_s > 0 and (auto_loop or i < len(spec.files)-1):
                        self._sleep_with_pump(spec.delay_s)
                if not auto_loop:
                    break
        finally:
            if auto_loop:
                self._stop_event.clear()

    def _sleep_with_pump(self, secs: float):
        # Sleep in small chunks so UI doesn't feel frozen
        end = time.time() + secs
        while time.time() < end and not self._stop_event.is_set():
            time.sleep(min(0.1, end - time.time()))

    # ---------- Logging ----------
    def _log(self, msg: str):
        if self._ui_mode != "pro" or not self.log:
            return
        try:
            self.log.insert("end", msg + "\n")
            self.log.see("end")
        except Exception:
            pass

PLUGIN = IntervalCopyTool()