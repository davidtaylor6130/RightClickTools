# RightClickToolkit

<p align="center">
  <img alt="Status" src="https://img.shields.io/badge/status-v1-2ea44f">
  <img alt="Privacy" src="https://img.shields.io/badge/privacy-offline--first-2ea44f">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey">
</p>

RightClickToolkit is a cross‑platform launcher for file‑management utilities that integrates with your operating system's right‑click context menu. Built in Python with a plugin architecture, it lets you add new tools with minimal boilerplate.

## Project Status

v1 — initial stable release. Core features are ready for daily use, though refinements may continue.

## Features

- **Plugin‑driven architecture.** Plugins are discovered at runtime from the [`tools/`](tools) directory and loaded even if another plugin fails to import.
- **Standard & Pro modes.** The main window can switch between simplified and advanced interfaces depending on user needs.
- **Cross‑platform integration.** Registry and Automator snippets are provided for Windows and macOS to add context‑menu entries.

### Built‑in Tools

| Tool | Description |
|------|-------------|
| Auto File Organiser | Groups files into folders named by a detected factor using `%DONTCARE%` and `%FACTOR%` tokens |
| Cleaner | Profile‑based cleaner with XML rules and optional recycle‑bin support |
| Interval Copy (3 files) | Copies three files to a destination with configurable delay and presets |
| Mirror Verifier | Confirms that source directories are fully mirrored with selectable size, timestamp, or hash checks, plus an option to ignore folder structure when comparing |
| Weekly Dates (UK) | Generates weekly or daily date lists annotated with UK bank holidays |
| XML Checker | Watches files or folders for XML changes and reports parse or XSD errors |

## Getting Started

1. **Install Python 3.8+** and required dependencies:
   ```bash
   pip install ttkbootstrap send2trash pyinstaller
   ```
2. **Run the launcher:**
   ```bash
   python rightclick_toolkit.py
   ```

## Context‑Menu Integration

RightClickToolkit ships with an automated installer that creates context-menu entries for every built-in tool on Windows, macOS and Linux.

```bash
python install_context_menus.py
```

- **Windows:** The installer registers a `RightClickToolkit` submenu for files and folders under the current user’s registry hive. Restart Explorer if the new entries do not appear immediately.
- **macOS:** Finder Quick Actions are generated in `~/Library/Services`. Enable the “RightClickToolkit – …” actions from **System Settings ▸ Privacy & Security ▸ Extensions** if macOS prompts for approval.
- **Linux:** `.desktop` action files are written to `~/.local/share/file-manager/actions`, which is supported by Nautilus, Nemo and other FreeDesktop-compliant file managers. Restart your file manager if the actions are not listed straight away.

## Configuration

Some tools use external configuration. For example, the Cleaner tool ships with [`config/settings.clean.xml`](config/settings.clean.xml), which defines reusable profiles for different project types such as Unity or Unreal.

## Developing Plugins

Create a new file ending with `_tool.py` in the `tools/` directory that exposes a `PLUGIN` object implementing the `ToolPlugin` protocol. See the existing tools for reference.

## Caveats

- **Dependencies:** `ttkbootstrap` is required for the GUI. `send2trash` enables safe deletions to the recycle bin, and `pyinstaller` is used for packaging but not required at runtime.
- **XML validation:** The XML Checker can optionally validate against an XSD if the `xmlschema` package is installed; otherwise a warning is logged.
- **Platform specifics:** Context‑menu integration scripts are provided for Windows and macOS only.

## License

Released under the [MIT License](LICENSE), permitting commercial and private use with minimal restrictions.

