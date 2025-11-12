from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path
from typing import List, Sequence

from tools.mirror_verifier_core import (
    MirrorVerifierConfig,
    MirrorVerifierCore,
    VerificationItem,
    VerificationMode,
)


def _parse_mode(value: str) -> VerificationMode:
    if isinstance(value, VerificationMode):
        return value
    mapping = {
        "size": VerificationMode.SIZE_ONLY,
        "size_mtime": VerificationMode.SIZE_AND_MTIME,
        "adaptive": VerificationMode.ADAPTIVE_HASH,
        "hash": VerificationMode.FULL_HASH,
    }
    key = value.lower()
    if key not in mapping:
        raise argparse.ArgumentTypeError(f"Unknown mode: {value}")
    return mapping[key]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Mirror Verifier CLI")
    parser.add_argument("--source", dest="sources", action="append", default=[], help="Source directory to verify")
    parser.add_argument("--mirror", dest="mirrors", action="append", default=[], help="Mirror directory to compare against")
    parser.add_argument(
        "--mode",
        default=VerificationMode.ADAPTIVE_HASH,
        type=_parse_mode,
        help="Verification mode: size|size_mtime|adaptive|hash",
    )
    parser.add_argument("--ignore-structure", action="store_true", help="Match files by name and size across mirrors")
    parser.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks when scanning")
    parser.add_argument("--threads", type=int, default=None, help="Hashing thread pool size")
    parser.add_argument("--out", choices=["JSON", "TEXT"], default="TEXT", help="Output format")
    return parser


def _validate_paths(paths: Sequence[str], kind: str) -> List[Path]:
    resolved = []
    for raw in paths:
        path = Path(raw).expanduser()
        if not path.exists():
            raise SystemExit(f"{kind} path does not exist: {path}")
        resolved.append(path)
    if not resolved:
        raise SystemExit(f"Provide at least one {kind.lower()} path")
    return resolved


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    sources = _validate_paths(args.sources, "Source")
    mirrors = _validate_paths(args.mirrors, "Mirror")

    stop_event = threading.Event()
    pause_event = threading.Event()
    pause_event.set()

    results: List[VerificationItem] = []

    def _on_result(item: VerificationItem) -> None:
        results.append(item)

    config = MirrorVerifierConfig(
        sources=sources,
        mirrors=mirrors,
        mode=args.mode,
        ignore_structure=args.ignore_structure,
        follow_symlinks=args.follow_symlinks,
        thread_count=args.threads,
    )
    core = MirrorVerifierCore(
        config,
        stop_event,
        pause_event,
        progress_callback=lambda msg: None,
        result_callback=_on_result,
        status_callback=lambda msg: None,
        disconnection_callback=lambda root, message, flag: None,
        telemetry_callback=None,
    )
    summary = core.run().as_dict()

    output = {
        "summary": summary,
        "items": [
            {
                "status": item.status,
                "source_rel": item.source_rel,
                "detail": item.detail,
                "ignored": item.ignored,
            }
            for item in results
        ],
    }

    has_unignored = any(
        item["status"] in {"MISSING", "MISMATCH"} and not item["ignored"] for item in output["items"]
    )

    if args.out == "JSON":
        json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        print(
            f"Processed {summary['total']} files – {summary['matched']} matched, {summary['missing']} missing, {summary['mismatch']} mismatch"
        )
        for entry in output["items"]:
            flag = " (ignored)" if entry["ignored"] else ""
            print(f"{entry['status']:<8} {entry['source_rel']} – {entry['detail']}{flag}")

    return 0 if not has_unignored else 2


if __name__ == "__main__":
    sys.exit(main())
