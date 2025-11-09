#!/usr/bin/env python3
"""Cross-platform installer for RightClickToolkit context-menu entries."""
from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from plugins import discover_plugins  # noqa: E402  (import after sys.path tweak)


ToolInfo = Tuple[str, str, str]


def _collect_tool_info() -> List[ToolInfo]:
    plugins: Dict[str, object] = discover_plugins(ROOT)
    items: List[ToolInfo] = []
    for key in sorted(plugins):
        plugin = plugins[key]
        title = getattr(plugin, "title", key.title())
        description = getattr(plugin, "description", "Launch tool via RightClickToolkit")
        items.append((key, title, description))
    return items


def _ensure_python_command() -> str:
    python = Path(sys.executable).resolve()
    if platform.system() == "Windows":
        return f'"{python}"'
    return str(python)


def _script_command(tool_key: str) -> str:
    script = ROOT / "rightclick_toolkit.py"
    if not script.exists():
        raise SystemExit("Unable to locate rightclick_toolkit.py")
    python_cmd = _ensure_python_command()
    script_path = script.resolve()
    if platform.system() == "Windows":
        return f"{python_cmd} \"{script_path}\" --action {tool_key} %*"
    quoted_script = shlex.quote(str(script_path))
    if platform.system() == "Darwin":
        # macOS shell script receives arguments via "$@"
        return f"/usr/bin/env python3 {quoted_script} --action {tool_key} \"$@\""
    # Linux / other POSIX platforms
    return f"/usr/bin/env python3 {quoted_script} --action {tool_key} %F"


def _install_windows(tools: Iterable[ToolInfo]) -> None:
    try:
        import winreg  # type: ignore
    except ImportError:  # pragma: no cover - handled at runtime on non-Windows hosts
        raise SystemExit("winreg module is not available. Run this installer on Windows.")

    python_cmd = _ensure_python_command()
    script_path = ROOT / "rightclick_toolkit.py"

    def wipe_tree(root, path: str) -> None:
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_WRITE | winreg.KEY_READ)
        except FileNotFoundError:
            return
        # Enumerate subkeys first
        try:
            while True:
                sub = winreg.EnumKey(key, 0)
                wipe_tree(root, path + "\\" + sub)
        except OSError:
            pass
        winreg.CloseKey(key)
        try:
            winreg.DeleteKey(root, path)
        except OSError:
            pass

    tool_list = list(tools)

    def create_entries(base_path: str) -> None:
        parent_path = base_path + "\\RightClickToolkit"
        wipe_tree(winreg.HKEY_CURRENT_USER, parent_path)
        parent = winreg.CreateKey(winreg.HKEY_CURRENT_USER, parent_path)
        winreg.SetValueEx(parent, "MUIVerb", 0, winreg.REG_SZ, "RightClickToolkit")
        winreg.SetValueEx(parent, "Icon", 0, winreg.REG_SZ, python_cmd)
        shell_key = winreg.CreateKey(parent, "shell")
        for tool_key, title, _desc in tool_list:
            tool_key_obj = winreg.CreateKey(shell_key, tool_key)
            winreg.SetValueEx(tool_key_obj, "MUIVerb", 0, winreg.REG_SZ, title)
            command_key = winreg.CreateKey(tool_key_obj, "command")
            command = f'{python_cmd} "{script_path}" --action {tool_key} %*'
            winreg.SetValue(command_key, None, winreg.REG_SZ, command)
            winreg.CloseKey(command_key)
            winreg.CloseKey(tool_key_obj)
        winreg.CloseKey(shell_key)
        winreg.CloseKey(parent)

    create_entries(r"Software\Classes\*\shell")
    create_entries(r"Software\Classes\Directory\shell")
    print("Windows context-menu entries installed under HKCU. You may need to restart Explorer.")


def _install_macos(tools: Iterable[ToolInfo]) -> None:
    services_dir = Path.home() / "Library" / "Services"
    services_dir.mkdir(parents=True, exist_ok=True)
    script_path = ROOT / "rightclick_toolkit.py"

    for tool_key, title, description in tools:
        workflow_name = f"RightClickToolkit - {title}.workflow"
        workflow_dir = services_dir / workflow_name
        contents_dir = workflow_dir / "Contents"
        contents_dir.mkdir(parents=True, exist_ok=True)

        info_plist_path = contents_dir / "Info.plist"
        info_plist_data = {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleExecutable": "Automator Runner",
            "CFBundleIdentifier": f"com.rightclicktoolkit.{tool_key}",
            "CFBundleInfoDictionaryVersion": "6.0",
            "CFBundleName": f"RightClickToolkit - {title}",
            "CFBundlePackageType": "Wflow",
            "CFBundleShortVersionString": "1.0",
            "CFBundleVersion": "1.0",
            "AMApplicationBuild": "2.10",
            "AMApplicationVersion": "2.10",
            "NSHumanReadableDescription": description,
            "NSAppleScriptEnabled": False,
        }

        command = _script_command(tool_key)
        action_uuid = str(uuid.uuid4()).upper()
        workflow_uuid = str(uuid.uuid4()).upper()
        document_path = contents_dir / "document.wflow"
        document_data = {
            "actions": [
                {
                    "AMActionVersion": "2.5",
                    "AMParameterProperties": {
                        "COMMAND_STRING": {
                            "isValueDisplayNegated": False,
                            "value": command,
                        },
                        "CheckedForUserDefaultShell": {
                            "isValueDisplayNegated": False,
                            "value": True,
                        },
                        "inputMethod": {
                            "isValueDisplayNegated": False,
                            "value": 1,
                        },
                        "shell": {
                            "isValueDisplayNegated": False,
                            "value": "/bin/zsh",
                        },
                    },
                    "applicationBundleIDsByPath": {},
                    "applicationPaths": [],
                    "bundleIdentifier": "com.apple.actions.run-shell-script",
                    "className": "AMShellScriptAction",
                    "inputUUID": action_uuid,
                    "isViewVisible": True,
                    "outputUUID": workflow_uuid,
                    "parameters": {
                        "COMMAND_STRING": command,
                        "CheckedForUserDefaultShell": True,
                        "inputMethod": 1,
                        "shell": "/bin/zsh",
                    },
                }
            ],
            "connectors": [],
            "workflowMetaData": {
                "applicationBundleID": "com.apple.finder",
                "applicationBundleIDsByPath": {},
                "applicationPaths": [],
                "createdBy": "RightClickToolkit Installer",
                "inputTypeIdentifier": "com.apple.Automator.fileSystemObject",
                "outputTypeIdentifier": "com.apple.Automator.nothing",
                "presentationMode": 6,
                "processesInput": 0,
                "serviceApplicationBundleIDs": ["com.apple.finder"],
                "serviceInputTypeIdentifier": "com.apple.Automator.fileSystemObject",
                "serviceOutputTypeIdentifier": "com.apple.Automator.nothing",
                "serviceProcessesInput": 0,
                "systemImageName": "GenericApplicationIcon",
                "workflowID": str(uuid.uuid4()).upper(),
                "workflowTypeIdentifier": "com.apple.Automator.servicesMenu",
            },
        }

        import plistlib

        with info_plist_path.open("wb") as f:
            plistlib.dump(info_plist_data, f)
        with document_path.open("wb") as f:
            plistlib.dump(document_data, f)

        # Ensure metadata timestamp updates for Finder
        os.utime(workflow_dir, None)
        print(f"Created Finder Quick Action: {workflow_name}")

    print("macOS Quick Actions installed. Enable them from System Settings ▸ Privacy & Security ▸ Extensions if needed.")


def _install_linux(tools: Iterable[ToolInfo]) -> None:
    actions_dir = Path.home() / ".local" / "share" / "file-manager" / "actions"
    actions_dir.mkdir(parents=True, exist_ok=True)
    for tool_key, title, description in tools:
        desktop_path = actions_dir / f"rightclicktoolkit-{tool_key}.desktop"
        exec_command = _script_command(tool_key)
        desktop_data = f"""[Desktop Entry]\nType=Action\nName=RightClickToolkit - {title}\nTooltip={description}\nIcon=utilities-terminal\nProfiles=profile-{tool_key};\n\n[X-Action-Profile profile-{tool_key}]\nMimeTypes=inode/directory;application/octet-stream;text/plain;\nExec={exec_command}\n"""
        desktop_path.write_text(desktop_data)
        print(f"Installed file manager action: {desktop_path}")

    updater = shutil.which("update-desktop-database")
    if updater:
        subprocess.run([updater, str(actions_dir.parent)], check=False)
    print("Linux file-manager actions installed. Restart your file manager if entries do not appear immediately.")


def main() -> int:
    tools = list(_collect_tool_info())
    if not tools:
        print("No tools discovered. Ensure the tools directory contains *_tool.py modules.")
        return 1

    system = platform.system()
    if system == "Windows":
        _install_windows(tools)
    elif system == "Darwin":
        _install_macos(tools)
    elif system == "Linux":
        _install_linux(tools)
    else:
        print(f"Unsupported platform: {system}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
