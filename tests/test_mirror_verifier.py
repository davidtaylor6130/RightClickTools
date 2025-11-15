from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.mirror_verifier_core import (
    DirectoryManifest,
    HashPool,
    IgnoreRules,
    ManifestEntry,
    MirrorCatalog,
    MirrorVerifierConfig,
    MirrorVerifierCore,
    VerificationMode,
)


def _is_relative_to(path: Path, other: Path) -> bool:
    try:
        path.relative_to(other)
        return True
    except ValueError:
        return False


def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_manifest_read_write(tmp_path: Path):
    cache_root = tmp_path / "cache"
    manifest = DirectoryManifest(tmp_path, cache_root)
    entry = ManifestEntry("foo.txt", 3, 42.0, "abc", ".txt", None)
    manifest.record(entry)
    manifest.close()

    manifest_reloaded = DirectoryManifest(tmp_path, cache_root)
    cached = manifest_reloaded.get("foo.txt")
    assert cached is not None
    assert cached.sha256 == "abc"
    assert _is_relative_to(manifest_reloaded.path, cache_root)
    manifest_reloaded.close()


def test_ignore_rules_persist(tmp_path: Path):
    rules = IgnoreRules(tmp_path)
    rules.add("photos/holiday")
    assert rules.matches("photos/holiday/image.jpg")
    rules2 = IgnoreRules(tmp_path)
    assert rules2.matches("photos/holiday/video.mp4")


def test_hash_pool_pause_resume(tmp_path: Path):
    stop_event = threading.Event()
    pause_event = threading.Event()
    pause_event.clear()
    pool = HashPool(1, stop_event, pause_event)
    data_path = tmp_path / "file.bin"
    _write_file(data_path, b"0" * (1024 * 256))

    future = pool.submit(data_path)
    time.sleep(0.2)
    assert not future.done(), "hash should wait while paused"
    pause_event.set()
    digest = future.result(timeout=5)
    assert len(digest) == 64
    pool.shutdown()


def test_signature_index(tmp_path: Path):
    mirror_root = tmp_path / "mirror"
    file_path = mirror_root / "folder" / "A.TXT"
    _write_file(file_path, b"payload")
    stop_event = threading.Event()
    pause_event = threading.Event()
    pause_event.set()
    manifest = DirectoryManifest(mirror_root)
    catalog = MirrorCatalog(
        mirror_root,
        manifest,
        follow_symlinks=False,
        status_callback=lambda msg: None,
        stop_event=stop_event,
        pause_event=pause_event,
        disconnection_callback=lambda root, message, flag: None,
    )
    catalog.ensure_index()
    entry = catalog.get_rel_entry("folder/A.TXT")
    assert entry is not None
    matches = catalog.get_signature_matches(("txt", len(b"payload")))
    assert any(m.rel == "folder/A.TXT" for m in matches)


def test_cli_json_output_schema(tmp_path: Path):
    source = tmp_path / "src"
    mirror = tmp_path / "mirror"
    _write_file(source / "file.txt", b"hello")
    _write_file(mirror / "file.txt", b"hello")

    cmd = [
        sys.executable,
        "-m",
        "mirror_verifier",
        "--source",
        str(source),
        "--mirror",
        str(mirror),
        "--cache-dir",
        str(tmp_path / "cache"),
        "--out",
        "JSON",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    payload = json.loads(proc.stdout)
    assert set(payload.keys()) == {"summary", "items"}
    assert payload["summary"]["missing"] == 0
    assert payload["summary"]["mismatch"] == 0
    assert proc.returncode == 0


def test_core_respects_ignore(tmp_path: Path):
    source = tmp_path / "src"
    mirror = tmp_path / "mirror"
    _write_file(source / "ignore" / "file.txt", b"hello")
    _write_file(mirror / "ignore" / "file.txt", b"hello")

    rules = IgnoreRules(source)
    rules.add("ignore")

    stop_event = threading.Event()
    pause_event = threading.Event()
    pause_event.set()

    collected = []

    def _record(item):
        collected.append(item)

    config = MirrorVerifierConfig(
        sources=[source],
        mirrors=[mirror],
        mode=VerificationMode.SIZE_ONLY,
        ignore_structure=False,
        follow_symlinks=False,
        thread_count=1,
    )
    core = MirrorVerifierCore(
        config,
        stop_event,
        pause_event,
        progress_callback=lambda msg: None,
        result_callback=_record,
        status_callback=lambda msg: None,
        disconnection_callback=lambda root, message, flag: None,
        telemetry_callback=None,
    )
    summary = core.run()
    assert summary.total == 0
    assert all(item.ignored for item in collected)
