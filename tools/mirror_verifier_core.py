from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Tuple


_CHUNK_SIZE = 4 * 1024 * 1024
_MAX_HASH_WORKERS = 32
_HASH_RETRY_ATTEMPTS = 5
_RETRY_BASE_DELAY = 0.5


class VerificationMode(str, Enum):
    SIZE_ONLY = "size"
    SIZE_AND_MTIME = "size_mtime"
    ADAPTIVE_HASH = "adaptive"
    FULL_HASH = "hash"


@dataclass
class ManifestEntry:
    rel: str
    size: int
    mtime: float
    sha256: Optional[str]
    ext: str
    error: Optional[str]

    def signature(self) -> Tuple[str, int]:
        return (self.ext.lstrip(".").lower(), self.size)


def _cache_dir_for(root: Path, override: Optional[Path]) -> Optional[Path]:
    if not override:
        return None
    root_text = str(root)
    digest = hashlib.sha1(root_text.encode("utf-8", errors="ignore")).hexdigest()[:12]
    label = root.name or root.drive or root_text
    sanitized = [ch if ch.isalnum() else "_" for ch in label]
    collapsed = "".join(sanitized).strip("_") or "root"
    collapsed = collapsed[-32:]
    return override / f"{collapsed}-{digest}"


class DirectoryManifest:
    """JSONL manifest describing files under a root directory."""

    def __init__(self, root: Path, cache_dir: Optional[Path] = None):
        self.root = root
        self._lock = threading.Lock()
        self._cache_override = cache_dir
        self._dir = root / ".rct"
        self._path = self._resolve_manifest_path()
        self._handle = None
        self._entries: Dict[str, ManifestEntry] = {}
        self._load_existing()
        self._open_append()

    @property
    def path(self) -> Path:
        return self._path

    def _resolve_manifest_path(self) -> Path:
        if self._cache_override:
            candidate = _cache_dir_for(self.root, self._cache_override)
            if candidate:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    self._dir = candidate
                    return candidate / "manifest.jsonl"
                except OSError:
                    pass
        self._dir = self.root / ".rct"
        target = self._dir / "manifest.jsonl"
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
            return target
        except OSError:
            fallback = self.root / "mirror_hashes.rcthash"
            try:
                fallback.parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
            return fallback

    def _load_existing(self) -> None:
        manifest_path = self._path
        if manifest_path.exists():
            try:
                with manifest_path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            payload = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        rel = payload.get("rel")
                        size = payload.get("size")
                        mtime = payload.get("mtime")
                        sha256 = payload.get("sha256")
                        ext = payload.get("ext", "")
                        error = payload.get("error")
                        if rel is None or size is None or mtime is None:
                            continue
                        self._entries[rel] = ManifestEntry(rel, int(size), float(mtime), sha256, str(ext), error)
            except OSError:
                pass
    def _open_append(self) -> None:
        try:
            self._handle = self._path.open("a", encoding="utf-8")
        except OSError:
            self._handle = None

    def get(self, rel: str) -> Optional[ManifestEntry]:
        return self._entries.get(rel)

    def match(self, rel: str, size: int, mtime: float) -> Optional[ManifestEntry]:
        entry = self._entries.get(rel)
        if not entry:
            return None
        if entry.size == size and abs(entry.mtime - mtime) <= 0.01:
            return entry
        return None

    def record(self, entry: ManifestEntry) -> None:
        with self._lock:
            current = self._entries.get(entry.rel)
            if current and current == entry:
                return
            self._entries[entry.rel] = entry
            if not self._handle:
                return
            payload = {
                "rel": entry.rel,
                "size": entry.size,
                "mtime": entry.mtime,
                "sha256": entry.sha256,
                "ext": entry.ext,
                "error": entry.error,
            }
            self._handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._handle.flush()
            try:
                os.fsync(self._handle.fileno())
            except OSError:
                pass

    def iter_entries(self) -> Iterator[ManifestEntry]:
        yield from self._entries.values()

    def close(self) -> None:
        handle = self._handle
        if handle:
            try:
                handle.flush()
            except OSError:
                pass
            try:
                handle.close()
            finally:
                self._handle = None


class IgnoreRules:
    def __init__(self, root: Path, cache_dir: Optional[Path] = None):
        self.root = root
        self._lock = threading.Lock()
        self._cache_override = cache_dir
        self._dir = self._determine_dir()
        self._path = self._dir / "ignore.json"
        self.patterns: List[str] = []
        self._load()

    def _determine_dir(self) -> Path:
        if self._cache_override:
            candidate = _cache_dir_for(self.root, self._cache_override)
            if candidate:
                try:
                    candidate.mkdir(parents=True, exist_ok=True)
                    return candidate
                except OSError:
                    pass
        directory = self.root / ".rct"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            return directory
        except OSError:
            return self.root

    def _ensure_dir(self) -> None:
        try:
            self._dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _load(self) -> None:
        self._ensure_dir()
        try:
            with self._path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except OSError:
            payload = []
        except json.JSONDecodeError:
            payload = []
        if isinstance(payload, list):
            self.patterns = [str(p) for p in payload]

    def save(self) -> None:
        self._ensure_dir()
        try:
            with self._path.open("w", encoding="utf-8") as handle:
                json.dump(sorted(set(self.patterns)), handle, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def add(self, rel_prefix: str) -> None:
        with self._lock:
            if rel_prefix not in self.patterns:
                self.patterns.append(rel_prefix)
                self.save()

    def matches(self, rel: str) -> bool:
        for prefix in self.patterns:
            if rel == prefix or rel.startswith(prefix.rstrip("/") + "/"):
                return True
        return False


class HashPool:
    def __init__(
        self,
        max_workers: Optional[int],
        stop_event: threading.Event,
        pause_event: threading.Event,
    ) -> None:
        worker_count = max_workers or min(_MAX_HASH_WORKERS, max(1, os.cpu_count() or 1) * 2)
        self._executor = ThreadPoolExecutor(max_workers=worker_count, thread_name_prefix="mirror-hash")
        self._stop_event = stop_event
        self._pause_event = pause_event
        self._lock = threading.Lock()
        self._futures: Dict[Path, Future] = {}

    def _hash_file(self, path: Path) -> str:
        import hashlib

        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                if self._stop_event.is_set():
                    raise RuntimeError("hash cancelled")
                while not self._pause_event.is_set():
                    if self._stop_event.is_set():
                        raise RuntimeError("hash cancelled")
                    self._pause_event.wait(0.1)
                chunk = handle.read(_CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()

    def submit(self, path: Path) -> Future:
        with self._lock:
            future = self._futures.get(path)
            if future is None or (future.done() and future.cancelled()):
                future = self._executor.submit(self._hash_file, path)
                self._futures[path] = future
            return future

    def shutdown(self) -> None:
        with self._lock:
            futures = list(self._futures.values())
            self._futures.clear()
        for future in futures:
            future.cancel()
        self._executor.shutdown(wait=False, cancel_futures=True)


@dataclass
class ProgressEntry:
    status: str
    detail: str


class ProgressLog:
    def __init__(self, root: Path):
        self.root = root
        self.path = root / "mirror_verifier_progress.rctresume"
        self._lock = threading.Lock()
        self._handle = None
        self._entries: Dict[str, ProgressEntry] = {}
        self._status_counts: Dict[str, int] = {}
        self._load()
        self._open()

    def _load(self) -> None:
        try:
            with self.path.open("r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        payload = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    rel = payload.get("rel")
                    status = payload.get("status")
                    detail = payload.get("detail", "")
                    if rel and status:
                        self._entries[rel] = ProgressEntry(status, detail)
        except OSError:
            return
        self._recount()

    def _open(self) -> None:
        try:
            self._handle = self.path.open("a", encoding="utf-8")
        except OSError:
            self._handle = None

    def _recount(self) -> None:
        counts: Dict[str, int] = {}
        for entry in self._entries.values():
            counts[entry.status] = counts.get(entry.status, 0) + 1
        self._status_counts = counts

    @property
    def status_counts(self) -> Dict[str, int]:
        return dict(self._status_counts)

    def is_processed(self, rel: str) -> bool:
        return rel in self._entries

    def iter_entries(self) -> Iterator[Tuple[str, str, str]]:
        for rel in sorted(self._entries):
            entry = self._entries[rel]
            yield rel, entry.status, entry.detail

    def total_processed(self) -> int:
        return len(self._entries)

    def record(self, rel: str, status: str, detail: str) -> None:
        with self._lock:
            previous = self._entries.get(rel)
            if previous and previous.status == status and previous.detail == detail:
                return
            if previous:
                prev_status = previous.status
                if prev_status in self._status_counts:
                    self._status_counts[prev_status] -= 1
                    if self._status_counts[prev_status] <= 0:
                        self._status_counts.pop(prev_status, None)
            self._entries[rel] = ProgressEntry(status, detail)
            self._status_counts[status] = self._status_counts.get(status, 0) + 1
            if not self._handle:
                return
            payload = {"rel": rel, "status": status, "detail": detail}
            self._handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
            self._handle.flush()

    def close(self) -> None:
        if self._handle:
            try:
                self._handle.close()
            finally:
                self._handle = None

    def clear_file(self) -> None:
        try:
            self.path.unlink()
        except OSError:
            pass


@dataclass
class VerificationItem:
    status: str
    source_rel: str
    detail: str
    ignored: bool
    source_root: Path


@dataclass
class VerificationSummary:
    total: int = 0
    matched: int = 0
    missing: int = 0
    mismatch: int = 0

    def as_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "matched": self.matched,
            "missing": self.missing,
            "mismatch": self.mismatch,
        }


@dataclass
class MirrorVerifierConfig:
    sources: Sequence[Path]
    mirrors: Sequence[Path]
    mode: VerificationMode
    ignore_structure: bool
    follow_symlinks: bool
    thread_count: Optional[int] = None
    cache_dir: Optional[Path] = None


def _mtimes_close(left: float, right: float, tolerance: float = 2.0) -> bool:
    return abs(left - right) <= tolerance


class MirrorCatalog:
    def __init__(
        self,
        root: Path,
        manifest: DirectoryManifest,
        follow_symlinks: bool,
        status_callback: Callable[[str], None],
        stop_event: threading.Event,
        pause_event: threading.Event,
        disconnection_callback: Callable[[Path, str, bool], None],
    ) -> None:
        self.root = root
        self.manifest = manifest
        self.follow_symlinks = follow_symlinks
        self.status_callback = status_callback
        self.stop_event = stop_event
        self.pause_event = pause_event
        self.disconnection_callback = disconnection_callback
        self._index_lock = threading.Lock()
        self._indexed = False
        self.index_duration = 0.0
        self.by_rel: Dict[str, ManifestEntry] = {entry.rel: entry for entry in manifest.iter_entries()}
        self.by_signature: Dict[Tuple[str, int], List[str]] = {}
        for entry in manifest.iter_entries():
            signature = (entry.ext.lstrip(".").lower(), entry.size)
            self.by_signature.setdefault(signature, []).append(entry.rel)

    def ensure_index(self) -> None:
        if self._indexed:
            return
        with self._index_lock:
            if self._indexed:
                return
            self._scan_root()
            self._indexed = True

    def _scan_root(self) -> None:
        start = time.perf_counter()
        stack = [self.root]
        root_str = str(self.root)
        while stack:
            if self.stop_event.is_set():
                return
            while not self.pause_event.is_set():
                if self.stop_event.is_set():
                    return
                self.pause_event.wait(0.1)
            current = stack.pop()
            try:
                iterator = self._retry(lambda: os.scandir(current))
            except OSError as exc:
                self.disconnection_callback(self.root, str(exc), True)
                continue
            self.disconnection_callback(self.root, "", False)
            with iterator as entries:
                for entry in entries:
                    if self.stop_event.is_set():
                        return
                    name = entry.name
                    if name == ".rct" or name in {"mirror_verifier_progress.rctresume", "mirror_hashes.rcthash"}:
                        continue
                    if entry.is_symlink() and not self.follow_symlinks:
                        continue
                    try:
                        if entry.is_dir(follow_symlinks=self.follow_symlinks):
                            if name == ".rct" or name in {"mirror_verifier_progress.rctresume", "mirror_hashes.rcthash"}:
                                continue
                            stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=self.follow_symlinks):
                            continue
                    except OSError:
                        continue
                    rel = os.path.relpath(entry.path, root_str)
                    if rel.startswith(".."):
                        continue
                    rel = rel.replace(os.sep, "/")
                    if rel.startswith(".rct/"):
                        continue
                    stat_result = self._retry(lambda: entry.stat(follow_symlinks=self.follow_symlinks))
                    if not stat.S_ISREG(stat_result.st_mode):
                        continue
                    manifest_entry = ManifestEntry(
                        rel=rel,
                        size=int(stat_result.st_size),
                        mtime=float(stat_result.st_mtime),
                        sha256=None,
                        ext=Path(entry.path).suffix.lower(),
                        error=None,
                    )
                    self.by_rel[rel] = manifest_entry
                    signature = (manifest_entry.ext.lstrip(".").lower(), manifest_entry.size)
                    self.by_signature.setdefault(signature, []).append(rel)
                    self.manifest.record(manifest_entry)
        self.index_duration += time.perf_counter() - start

    def _retry(self, operation: Callable[[], Any]) -> Any:
        delay = _RETRY_BASE_DELAY
        last_exc: Optional[OSError] = None
        for attempt in range(_HASH_RETRY_ATTEMPTS):
            if self.stop_event.is_set():
                raise OSError("cancelled")
            try:
                return operation()
            except OSError as exc:
                if isinstance(exc, FileNotFoundError):
                    raise
                last_exc = exc
                self.disconnection_callback(self.root, str(exc), True)
                time.sleep(delay)
                delay *= 2
        if last_exc:
            raise last_exc
        raise OSError("operation failed")

    def stat_path(self, path: Path) -> os.stat_result:
        return self._retry(lambda: path.stat())

    def get_rel_entry(self, rel: str) -> Optional[ManifestEntry]:
        entry = self.by_rel.get(rel)
        if entry:
            return entry
        self.ensure_index()
        return self.by_rel.get(rel)

    def get_signature_matches(self, signature: Tuple[str, int]) -> List[ManifestEntry]:
        self.ensure_index()
        rels = self.by_signature.get(signature, [])
        results: List[ManifestEntry] = []
        for rel in rels:
            entry = self.by_rel.get(rel)
            if entry:
                results.append(entry)
        return results


class MirrorVerifierCore:
    def __init__(
        self,
        config: MirrorVerifierConfig,
        stop_event: threading.Event,
        pause_event: threading.Event,
        progress_callback: Callable[[str], None],
        result_callback: Callable[[VerificationItem], None],
        status_callback: Callable[[str], None],
        disconnection_callback: Callable[[Path, str, bool], None],
        telemetry_callback: Optional[Callable[[Dict[str, float]], None]] = None,
    ) -> None:
        self.config = config
        self.stop_event = stop_event
        self.pause_event = pause_event
        self.progress_callback = progress_callback
        self.result_callback = result_callback
        self.status_callback = status_callback
        self.disconnection_callback = disconnection_callback
        self.telemetry_callback = telemetry_callback
        self.hash_pool = HashPool(config.thread_count, stop_event, pause_event)
        self.summary = VerificationSummary()
        self._hash_time = 0.0
        self._index_time = 0.0
        self._hashed_bytes = 0
        self._hashed_files = 0

    def _wait_for_resume(self) -> bool:
        if self.stop_event.is_set():
            return False
        if self.pause_event.is_set():
            return True
        while not self.pause_event.wait(0.1):
            if self.stop_event.is_set():
                return False
        return True

    def run(self) -> VerificationSummary:
        try:
            self._run_internal()
        finally:
            self.hash_pool.shutdown()
        return self.summary

    def _run_internal(self) -> None:
        sources = [Path(p) for p in self.config.sources]
        mirrors = [Path(p) for p in self.config.mirrors]
        follow_symlinks = self.config.follow_symlinks
        ignore_structure = self.config.ignore_structure
        cache_dir = self.config.cache_dir

        if not sources or not mirrors:
            return

        progress_logs = {root: ProgressLog(root) for root in sources}
        manifests = {root: DirectoryManifest(root, cache_dir) for root in sources + mirrors}
        ignore_rules = {root: IgnoreRules(root, cache_dir) for root in sources}
        catalogs = {}
        for mirror in mirrors:
            catalogs[mirror] = MirrorCatalog(
                mirror,
                manifests[mirror],
                follow_symlinks,
                self.status_callback,
                self.stop_event,
                self.pause_event,
                self.disconnection_callback,
            )

        expected = 0
        for src_root in sources:
            expected += sum(1 for _ in self._iter_source_files(src_root, follow_symlinks))
        prep_message = f"Preparing – queued {expected} files"
        self.status_callback(prep_message)
        self.progress_callback(prep_message)

        for src_root in sources:
            if self.stop_event.is_set():
                break
            log = progress_logs[src_root]
            ignore = ignore_rules[src_root]
            manifest = manifests[src_root]
            for entry in self._iter_source_files(src_root, follow_symlinks):
                if self.stop_event.is_set():
                    break
                if not self._wait_for_resume():
                    break
                rel = entry[0]
                abs_path = entry[1]
                stat_result = entry[2]
                display_root = src_root.name or src_root.drive or str(src_root)
                self.progress_callback(f"Checking {display_root}/{rel}")
                if ignore.matches(rel):
                    item = VerificationItem("OK", rel, "Ignored", True, src_root)
                    self.result_callback(item)
                    continue
                if log.is_processed(rel):
                    continue
                status, detail = self._process_file(
                    src_root,
                    rel,
                    abs_path,
                    stat_result,
                    manifest,
                    catalogs,
                    ignore_structure,
                    follow_symlinks,
                )
                item = VerificationItem(status, rel, detail, False, src_root)
                if status == "OK":
                    self.summary.matched += 1
                elif status == "MISSING":
                    self.summary.missing += 1
                elif status == "MISMATCH":
                    self.summary.mismatch += 1
                self.summary.total += 1
                log.record(rel, status, detail)
                self.result_callback(item)
                self.progress_callback(f"Processed {self.summary.total}/{expected} files")
            log.close()
        if not self.stop_event.is_set():
            for log in progress_logs.values():
                log.clear_file()
        self._index_time = sum(c.index_duration for c in catalogs.values())
        for manifest in manifests.values():
            manifest.close()
        if self.telemetry_callback and self.summary.total:
            telemetry = {
                "hash_time": self._hash_time,
                "index_time": self._index_time,
                "hashed_bytes": self._hashed_bytes,
                "hashed_files": self._hashed_files,
                "total_files": self.summary.total,
            }
            self.telemetry_callback(telemetry)

    def _iter_source_files(self, root: Path, follow_symlinks: bool) -> Iterator[Tuple[str, Path, os.stat_result]]:
        stack = [root]
        root_str = str(root)
        while stack:
            if self.stop_event.is_set():
                return
            while not self.pause_event.is_set():
                if self.stop_event.is_set():
                    return
                self.pause_event.wait(0.1)
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        name = entry.name
                        if name == ".rct" or name in {"mirror_verifier_progress.rctresume", "mirror_hashes.rcthash"}:
                            continue
                        if entry.is_symlink() and not follow_symlinks:
                            continue
                        try:
                            if entry.is_dir(follow_symlinks=follow_symlinks):
                                if name == ".rct" or name in {"mirror_verifier_progress.rctresume", "mirror_hashes.rcthash"}:
                                    continue
                                stack.append(Path(entry.path))
                                continue
                            if not entry.is_file(follow_symlinks=follow_symlinks):
                                continue
                        except OSError:
                            continue
                        rel = os.path.relpath(entry.path, root_str)
                        if rel.startswith(".."):
                            continue
                        rel = rel.replace(os.sep, "/")
                        if rel.startswith(".rct/"):
                            continue
                        try:
                            stat_result = entry.stat(follow_symlinks=follow_symlinks)
                        except OSError:
                            continue
                        if not stat.S_ISREG(stat_result.st_mode):
                            continue
                        yield rel, Path(entry.path), stat_result
            except OSError:
                time.sleep(0.1)
                continue

    def _process_file(
        self,
        src_root: Path,
        rel: str,
        abs_path: Path,
        stat_result: os.stat_result,
        manifest: DirectoryManifest,
        catalogs: Dict[Path, MirrorCatalog],
        ignore_structure: bool,
        follow_symlinks: bool,
    ) -> Tuple[str, str]:
        size = int(stat_result.st_size)
        mtime = float(stat_result.st_mtime)
        ext = abs_path.suffix.lower()
        cached = manifest.match(rel, size, mtime)
        sha256 = cached.sha256 if cached else None
        manifest.record(ManifestEntry(rel, size, mtime, sha256, ext, None))

        signature = (ext.lstrip(".").lower(), size)
        src_hash: Optional[str] = None
        for mirror, catalog in catalogs.items():
            entry = catalog.get_rel_entry(rel)
            result = self._compare_entry(
                abs_path,
                rel,
                size,
                mtime,
                sha256,
                entry,
                catalog,
                signature,
                ignore_structure,
            )
            if result:
                status, detail, src_hash = result
                if status == "OK":
                    manifest.record(ManifestEntry(rel, size, mtime, src_hash, ext, None))
                    return status, detail
                if status == "MISMATCH":
                    return status, detail
        return "MISSING", "No mirror file found"

    def _compare_entry(
        self,
        abs_path: Path,
        rel: str,
        src_size: int,
        src_mtime: float,
        cached_hash: Optional[str],
        entry: Optional[ManifestEntry],
        catalog: MirrorCatalog,
        signature: Tuple[str, int],
        ignore_structure: bool,
    ) -> Optional[Tuple[str, str, Optional[str]]]:
        src_hash = cached_hash
        candidates: List[ManifestEntry] = []
        if entry:
            candidates.append(entry)
        if ignore_structure:
            for idx_entry in catalog.get_signature_matches(signature):
                if idx_entry.rel != rel:
                    candidates.append(idx_entry)
        seen: set = set()
        for candidate in candidates:
            if candidate.rel in seen:
                continue
            seen.add(candidate.rel)
            result = self._evaluate_candidate(abs_path, src_size, src_mtime, src_hash, candidate, catalog)
            if result:
                status, detail, src_hash = result
                if status == "OK":
                    return status, detail, src_hash
                if status == "MISMATCH":
                    return status, detail, src_hash
        return None

    def _evaluate_candidate(
        self,
        abs_path: Path,
        src_size: int,
        src_mtime: float,
        src_hash: Optional[str],
        candidate: ManifestEntry,
        catalog: MirrorCatalog,
    ) -> Optional[Tuple[str, str, Optional[str]]]:
        rel = candidate.rel
        mirror_path = catalog.root / rel
        try:
            stat_result = catalog.stat_path(mirror_path)
        except FileNotFoundError:
            return None
        except OSError as exc:
            return "MISMATCH", f"Cannot stat mirror file {mirror_path}: {exc}", src_hash
        if int(stat_result.st_size) != src_size:
            return "MISMATCH", f"Size mismatch in {mirror_path}", src_hash
        if mirror_path.suffix.lower() != abs_path.suffix.lower():
            return "MISMATCH", f"Extension mismatch in {mirror_path}", src_hash
        if self.config.mode == VerificationMode.SIZE_ONLY:
            return "OK", f"Size match in {mirror_path}", src_hash
        mtimes_close = _mtimes_close(float(stat_result.st_mtime), src_mtime)
        if self.config.mode == VerificationMode.SIZE_AND_MTIME:
            if mtimes_close:
                return "OK", f"Size+mtime match in {mirror_path}", src_hash
            return "MISMATCH", f"Timestamp mismatch in {mirror_path}", src_hash
        if self.config.mode == VerificationMode.ADAPTIVE_HASH and mtimes_close:
            return "OK", f"Metadata match in {mirror_path}", src_hash
        # Need hash comparison
        start = time.perf_counter()
        if src_hash is None:
            self._hashed_bytes += src_size
            self._hashed_files += 1
            src_hash = self.hash_pool.submit(abs_path).result()
        mirror_hash = catalog.manifest.match(rel, src_size, float(stat_result.st_mtime))
        if mirror_hash and mirror_hash.sha256:
            dest_hash = mirror_hash.sha256
        else:
            dest_size = int(stat_result.st_size)
            self._hashed_bytes += dest_size
            self._hashed_files += 1
            dest_hash = self.hash_pool.submit(mirror_path).result()
            catalog.manifest.record(
                ManifestEntry(rel, int(stat_result.st_size), float(stat_result.st_mtime), dest_hash, mirror_path.suffix.lower(), None)
            )
        self._hash_time += time.perf_counter() - start
        if dest_hash != src_hash:
            return "MISMATCH", f"Hash mismatch in {mirror_path}", src_hash
        return "OK", f"Hash match in {mirror_path}", src_hash


__all__ = [
    "DirectoryManifest",
    "HashPool",
    "IgnoreRules",
    "ManifestEntry",
    "MirrorVerifierCore",
    "MirrorVerifierConfig",
    "ProgressLog",
    "VerificationItem",
    "VerificationMode",
    "VerificationSummary",
]
