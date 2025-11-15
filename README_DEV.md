# Mirror Verifier developer notes

The Mirror Verifier tool maintains per-root manifests and ignore rules under a hidden `.rct` folder. Each source and mirror root records file metadata in `manifest.jsonl` so subsequent runs can re-use size/mtime/hash information without touching every file again. If `.rct` cannot be created the tool falls back to `mirror_hashes.rcthash` in the root directory.

For slower or read-only roots you can redirect manifests into a dedicated cache directory. In the GUI set the “Metadata cache folder” option; in the CLI add `--cache-dir /path/to/cache`. Each root receives its own subfolder inside that cache so you can move or pre-seed hash maps on faster storage.

Ignored folders are persisted as prefixes inside `.rct/ignore.json`. The GUI tree view exposes a context menu to add directories to the ignore list; ignored entries remain visible with an “ignored” flag but do not affect the summary counts.

A CLI is available via `python -m mirror_verifier --source SRC --mirror MIR`. The CLI supports the same verification modes as the GUI and can emit either human readable text or JSON (`--out JSON`). Use `--cache-dir` to share manifest/hash data with the GUI or to point the cache at a faster disk. The exit code is `0` when every problem is ignored (or none exist) and `2` otherwise.
