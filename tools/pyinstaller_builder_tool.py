from __future__ import annotations

import plistlib
import platform
import re
import shlex
import shutil
import subprocess
import threading
from pathlib import Path
from typing import List, Optional

from tkinter import filedialog

import ttkbootstrap as tb
from ttkbootstrap.dialogs import Messagebox

from plugins.base import AppContext


_VERSION_PATTERNS = [
    re.compile(r"__version__\s*=\s*['\"]([^'\"]+)['\"]"),
    re.compile(r"VERSION\s*=\s*['\"]([^'\"]+)['\"]"),
]


class PyInstallerBuilderTool:
    key = "pyinstaller_builder"
    title = "PyInstaller Builder"
    description = "Package a Python script into an executable/app next to the source using PyInstaller."

    def __init__(self) -> None:
        self.ctx: Optional[AppContext] = None
        self.panel: Optional[tb.Frame] = None

        self.script_var: Optional[tb.StringVar] = None
        self.mode_var: Optional[tb.StringVar] = None
        self.extra_args_var: Optional[tb.StringVar] = None

        self.log: Optional[tb.ScrolledText] = None
        self.build_btn: Optional[tb.Button] = None

        self._worker: Optional[threading.Thread] = None
        self._stop = threading.Event()

    # ---------------- UI ----------------
    def make_panel(self, master, context: AppContext):
        self.ctx = context
        root = tb.Frame(master)
        self.panel = root

        tb.Label(
            root,
            text=(
                "Select a Python file and build a distributable using PyInstaller. "
                "The executable/app is written next to the source and temporary build artefacts are cleaned up."
            ),
            wraplength=780,
            justify="left",
        ).pack(fill="x", padx=12, pady=(12, 8))

        row = tb.Frame(root)
        row.pack(fill="x", padx=12, pady=(0, 6))
        tb.Label(row, text="Python script:").pack(side="left")
        self.script_var = tb.StringVar()
        entry = tb.Entry(row, textvariable=self.script_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        tb.Button(row, text="Browse…", command=self._browse, bootstyle="secondary").pack(side="left")

        modes = tb.Labelframe(root, text="Build mode")
        modes.pack(fill="x", padx=12, pady=(0, 6))
        self.mode_var = tb.StringVar(value=self._default_mode())
        tb.Radiobutton(modes, text="One-file executable", value="onefile", variable=self.mode_var, bootstyle="round-toggle").pack(
            side="left", padx=6, pady=4
        )
        if platform.system() == "Darwin":
            tb.Radiobutton(
                modes,
                text="macOS .app bundle",
                value="bundle",
                variable=self.mode_var,
                bootstyle="round-toggle",
            ).pack(side="left", padx=6, pady=4)

        extra = tb.Frame(root)
        extra.pack(fill="x", padx=12, pady=(0, 10))
        tb.Label(extra, text="Additional PyInstaller arguments:").pack(side="left")
        self.extra_args_var = tb.StringVar()
        tb.Entry(extra, textvariable=self.extra_args_var).pack(side="left", fill="x", expand=True, padx=6)

        actions = tb.Frame(root)
        actions.pack(fill="x", padx=12)
        self.build_btn = tb.Button(actions, text="Build", command=self._on_build, bootstyle="success")
        self.build_btn.pack(side="left")

        self.log = tb.ScrolledText(root, height=14, state="disabled")
        self.log.pack(fill="both", expand=True, padx=12, pady=(8, 12))

        return root

    def _default_mode(self) -> str:
        return "bundle" if platform.system() == "Darwin" else "onefile"

    def _browse(self) -> None:
        if not self.panel:
            return
        path = filedialog.askopenfilename(parent=self.panel, filetypes=[("Python files", "*.py"), ("All files", "*.*")])
        if path and self.script_var:
            self.script_var.set(path)

    # ---------------- Lifecycle ----------------
    def start(self, context: AppContext, targets: List[Path], argv: List[str]) -> None:
        script = next((t for t in targets if t.is_file() and t.suffix.lower() == ".py"), None)
        if script and self.script_var:
            self.script_var.set(str(script))
        elif targets and self.script_var:
            self.script_var.set(str(targets[0]))

    def cleanup(self) -> None:
        self._stop.set()
        if self._worker and self._worker.is_alive():
            self._worker.join(timeout=0.5)

    def on_mode_changed(self, ui_mode: str) -> None:
        # No special handling yet; reserved for future UI adjustments.
        pass

    # ---------------- Build handling ----------------
    def _on_build(self) -> None:
        if self._worker and self._worker.is_alive():
            Messagebox.show_info("A build is already running.", title="PyInstaller Builder")
            return
        if not self.script_var:
            return
        script_path = Path(self.script_var.get()).expanduser()
        if not script_path.exists():
            Messagebox.show_error("Selected script does not exist.", title="PyInstaller Builder")
            return
        if script_path.suffix.lower() != ".py":
            Messagebox.show_error("Please select a .py file to build.", title="PyInstaller Builder")
            return

        mode = self.mode_var.get() if self.mode_var else self._default_mode()
        extra_args = shlex.split(self.extra_args_var.get()) if self.extra_args_var and self.extra_args_var.get().strip() else []

        self._stop.clear()
        self._set_building(True)
        self._append_log(f"Starting build for {script_path} (mode: {mode})")
        self._worker = threading.Thread(target=self._build_worker, args=(script_path, mode, extra_args), daemon=True)
        self._worker.start()

    def _set_building(self, building: bool) -> None:
        if not self.panel:
            return
        if self.build_btn:
            state = "disabled" if building else "normal"
            self.build_btn.configure(state=state)

    def _append_log(self, text: str) -> None:
        if not self.log:
            return
        def _write():
            if not self.log:
                return
            self.log.configure(state="normal")
            self.log.insert("end", text + "\n")
            self.log.see("end")
            self.log.configure(state="disabled")

        if self.panel:
            self.panel.after(0, _write)
        else:
            _write()

    def _build_worker(self, script_path: Path, mode: str, extra_args: List[str]) -> None:
        work_dir: Optional[Path] = None
        version_file: Optional[Path] = None
        try:
            version = self._extract_version(script_path)
            if version:
                self._append_log(f"Detected version: {version}")
            else:
                self._append_log("No version information found; continuing without version metadata.")

            if shutil.which("pyinstaller") is None:
                raise RuntimeError("PyInstaller is not installed or not on PATH.")

            script_dir = script_path.parent
            name = script_path.stem
            work_dir = script_dir / f".pyinstaller_{name}_build"
            dist_dir = script_dir
            work_dir.mkdir(parents=True, exist_ok=True)

            cmd = [
                "pyinstaller",
                "--noconfirm",
                "--clean",
                "--name",
                name,
                "--distpath",
                str(dist_dir),
                "--workpath",
                str(work_dir),
                "--specpath",
                str(work_dir),
            ]

            system = platform.system()
            if mode == "bundle" and system == "Darwin":
                cmd.append("--windowed")
            else:
                cmd.append("--onefile")

            if version and system == "Windows":
                version_file = work_dir / "version_info.txt"
                version_text = self._create_version_file(name, version)
                if version_text:
                    version_file.write_text(version_text, encoding="utf-8")
                    cmd.extend(["--version-file", str(version_file)])
                    self._append_log("Attached Windows version resource.")
                else:
                    self._append_log("Version string format not supported for Windows resource; skipping.")

            cmd.extend(extra_args)
            cmd.append(str(script_path))

            self._append_log("Running: " + " ".join(shlex.quote(part) for part in cmd))

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            assert process.stdout is not None
            for line in process.stdout:
                if self._stop.is_set():
                    process.terminate()
                    break
                self._append_log(line.rstrip())
            returncode = process.wait()
            if returncode != 0:
                raise RuntimeError(f"PyInstaller exited with code {returncode}.")

            self._append_log("PyInstaller build completed successfully.")
            self._postprocess_outputs(script_path, name, mode, version)

        except Exception as exc:
            self._append_log(f"ERROR: {exc}")
            self.panel.after(0, lambda: Messagebox.show_error(str(exc), title="PyInstaller Builder")) if self.panel else None
        finally:
            try:
                if work_dir and work_dir.exists():
                    shutil.rmtree(work_dir, ignore_errors=True)
                if version_file and version_file.exists():
                    version_file.unlink(missing_ok=True)
            except Exception:
                pass
            if self.panel:
                self.panel.after(0, lambda: self._set_building(False))

    def _postprocess_outputs(self, script_path: Path, name: str, mode: str, version: Optional[str]) -> None:
        system = platform.system()
        dist_dir = script_path.parent
        if system == "Darwin" and mode == "bundle":
            app_path = dist_dir / f"{name}.app"
            if app_path.exists():
                self._append_log(f"Created app bundle: {app_path}")
                if version:
                    plist_path = app_path / "Contents" / "Info.plist"
                    if plist_path.exists():
                        try:
                            data = plistlib.loads(plist_path.read_bytes())
                            data["CFBundleShortVersionString"] = version
                            data["CFBundleVersion"] = version
                            plist_path.write_bytes(plistlib.dumps(data))
                            self._append_log("Updated macOS bundle version metadata.")
                        except Exception as exc:
                            self._append_log(f"Failed to update Info.plist version: {exc}")
            else:
                self._append_log("Expected .app bundle was not found in dist directory.")
        else:
            exe_name = f"{name}.exe" if system == "Windows" else name
            candidate = dist_dir / exe_name
            if candidate.exists():
                self._append_log(f"Created executable: {candidate}")
            else:
                # Fallback: list contents
                produced = list(dist_dir.glob(f"{name}*"))
                if produced:
                    self._append_log("Build artefacts:")
                    for item in produced:
                        self._append_log(f"  - {item}")
                else:
                    self._append_log("No output artefacts were found in the dist directory.")

    def _extract_version(self, script_path: Path) -> Optional[str]:
        try:
            text = script_path.read_text(encoding="utf-8")
        except Exception:
            return None
        for pattern in _VERSION_PATTERNS:
            match = pattern.search(text)
            if match:
                candidate = match.group(1).strip()
                if candidate:
                    return candidate
        return None

    def _create_version_file(self, name: str, version: str) -> Optional[str]:
        numbers = [int(part) for part in re.findall(r"\d+", version)]
        if not numbers:
            return None
        while len(numbers) < 4:
            numbers.append(0)
        numbers = numbers[:4]
        from textwrap import dedent

        return dedent(
            f"""
            VSVersionInfo(
              ffi=FixedFileInfo(
                filevers=({numbers[0]}, {numbers[1]}, {numbers[2]}, {numbers[3]}),
                prodvers=({numbers[0]}, {numbers[1]}, {numbers[2]}, {numbers[3]}),
                mask=0x3f,
                flags=0x0,
                OS=0x40004,
                fileType=0x1,
                subtype=0x0,
                date=(0, 0)
              ),
              kids=[
                StringFileInfo([
                  StringTable(
                    '040904B0',
                    [
                      StringStruct('CompanyName', ''),
                      StringStruct('FileDescription', '{name}'),
                      StringStruct('FileVersion', '{version}'),
                      StringStruct('InternalName', '{name}'),
                      StringStruct('LegalCopyright', ''),
                      StringStruct('OriginalFilename', '{name}.exe'),
                      StringStruct('ProductName', '{name}'),
                      StringStruct('ProductVersion', '{version}')
                    ]
                  )
                ]),
                VarFileInfo([VarStruct('Translation', [1033, 1200])])
              ]
            )
            """
        ).strip()


PLUGIN = PyInstallerBuilderTool()
