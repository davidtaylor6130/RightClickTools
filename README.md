# RightClickToolkit

RightClickToolkit is a cross‑platform launcher for handy file‑management utilities, designed to be invoked from an operating system's right‑click context menu. It is written in Python with a plugin architecture so new tools can be added with minimal boilerplate.

## Features

- **Plugin‑driven architecture.** Plugins are discovered at runtime from the [`tools/`](tools) folder and loaded even if another plugin fails to import.
- **Standard & Pro modes.** The main window can switch between simplified and advanced interfaces depending on user needs.
- **Cross‑platform integration.** Registry and Automator snippets are provided for Windows and macOS to add context‑menu entries.

### Built‑in Tools

| Tool | Description |
|------|-------------|
| Auto File Organiser | Groups files into folders named by a detected factor using `%DONTCARE%` and `%FACTOR%` tokens |
| Cleaner | Profile‑based cleaner with XML rules and optional recycle‑bin support |
| Interval Copy (3 files) | Copies three files to a destination with configurable delay and presets |
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

- **Windows:** Import the registry snippet and update the path to the executable in [`Reg Files/windows.reg`](Reg%20Files/windows.reg) to add "Clean with RCT" and "Hash with RCT" actions.
- **macOS:** Use the command in [`Reg Files/MacOs.Automator.txt`](Reg%20Files/MacOs.Automator.txt) inside an Automator "Quick Action" to invoke the toolkit.

## Configuration

Some tools use external configuration. For example, the Cleaner tool ships with [`config/settings.clean.xml`](config/settings.clean.xml), which defines reusable profiles for different project types such as Unity or Unreal.

## Developing Plugins

Create a new file ending with `_tool.py` in the `tools/` directory that exposes a `PLUGIN` object implementing the `ToolPlugin` protocol. See the existing tools for reference.

## Caveats

- **Dependencies:** `ttkbootstrap` is required for the GUI. `send2trash` enables safe deletions to the recycle bin, and `pyinstaller` is used for packaging but not required at runtime.
- **XML validation:** The XML Checker can optionally validate against an XSD if the `xmlschema` package is installed; otherwise a warning is logged.
- **Platform specifics:** Context‑menu integration scripts are provided for Windows and macOS only.

## License

No license file was found in the repository. Use at your own discretion.

