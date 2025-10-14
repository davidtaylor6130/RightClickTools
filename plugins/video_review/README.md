# Video Review & Log Plugin

This plugin adds a video review workflow to the Right-Click Toolkit. It lets
you scan a directory recursively for video files, approve or reject each item,
and export the results.

## Features
- Recursive scanning for common video formats (`.mp4`, `.mov`, `.mkv`, and more).
- Lightweight Tkinter UI with a sortable table, keyboard shortcuts (A/R/U), and
  an inspector pane for each video.
- Approval and rejection tracking with per-item notes.
- Excel export powered by `openpyxl`, including styled status indicators and
  frozen/filterable headers.
- Rejected item list export (`rejected_videos.txt`).
- Works inside the Toolkit launcher and can run standalone for quick testing.

## Standalone Testing
To preview the tool without the full launcher:

```bash
python -m plugins.video_review
```

This spins up a basic Tkinter window hosting the plugin frame.

## Packaging
When bundling with PyInstaller, include `openpyxl` so the Excel export works:

```bash
pyinstaller --noconfirm --onefile --name "RightClickToolkit" main.py
```

The plugin relies only on the standard library plus `openpyxl`.
