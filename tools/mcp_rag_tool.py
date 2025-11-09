from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from string import Template
from typing import Optional

import tkinter as tk
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText as TkScrolledText

import ttkbootstrap as tb

from plugins.base import AppContext


SCRIPT_TEMPLATE = Template('''#!/usr/bin/env python3
"""Auto-generated MCP Retrieval-Augmented Generation server.

Directory indexed: $source_dir

This script exposes a local Retrieval-Augmented Generation (RAG) workflow
over the Model Context Protocol (MCP). All components referenced here are
permissively licensed and can be swapped for equally permissive models:
  - Embeddings: $embed_model (Apache-2.0 licence via SentenceTransformers)
  - Generator: Suggested phi-2 4-bit GGUF for llama.cpp / llama-cpp-python (MIT)

The defaults target laptops with roughly 4 GB of GPU VRAM by relying on a
quantised model. Adjust the parameters if you have more capacity.

Requirements (install once):
    pip install "modelcontextprotocol[fastmcp]" sentence-transformers numpy llama-cpp-python safetensors accelerate

Usage examples:
    # Rebuild the vector index
    python $script_name --reindex

    # Launch the MCP server (stdio transport)
    python $script_name --serve --model-path "$default_model_path"

    # Ask a single question without starting the server
    python $script_name --query "What does the documentation cover?"

"""
from __future__ import annotations

import argparse
import json
import os
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple

import numpy as np

try:
    from sentence_transformers import SentenceTransformer
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "Install sentence-transformers: pip install sentence-transformers"
    ) from exc

try:
    from llama_cpp import Llama
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        "Install llama-cpp-python: pip install llama-cpp-python"
    ) from exc

try:
    from mcp.server.fastmcp import FastMCPServer
except ImportError as exc:  # pragma: no cover - dependency guard
    raise SystemExit(
        'Install the MCP Python SDK: pip install "modelcontextprotocol[fastmcp]"'
    ) from exc

ALLOWED_EXTENSIONS = $allowed_extensions
SOURCE_DIR = Path($source_dir_repr)
INDEX_DIR = Path($index_dir_repr)
DEFAULT_CHUNK_SIZE = $chunk_size
DEFAULT_CHUNK_OVERLAP = $chunk_overlap
DEFAULT_EMBED_MODEL = "$embed_model"
DEFAULT_MODEL_PATH = "$default_model_path"
DEFAULT_TOP_K = $default_top_k
DEFAULT_MAX_TOKENS = $default_max_tokens
DEFAULT_TEMPERATURE = $default_temperature


@dataclass
class Chunk:
    path: str
    chunk_id: int
    text: str

    def short_ref(self) -> str:
        return f"{self.path}#chunk-{self.chunk_id}"


class RAGIndex:
    """Manage chunking, embedding, and similarity search for local files."""

    def __init__(
        self,
        base_dir: Path,
        index_dir: Path,
        chunk_size: int,
        chunk_overlap: int,
        allowed_exts: Sequence[str],
        embed_model_name: str,
    ) -> None:
        self.base_dir = base_dir
        self.index_dir = index_dir
        self.chunk_size = max(1, chunk_size)
        self.chunk_overlap = max(0, min(chunk_overlap, self.chunk_size - 1))
        self.allowed_exts = tuple(sorted({ext.lower() for ext in allowed_exts}))
        self.embed_model_name = embed_model_name

        self.index_dir.mkdir(parents=True, exist_ok=True)
        self._chunks_path = self.index_dir / "chunks.json"
        self._emb_path = self.index_dir / "unit_embeddings.npy"
        self._chunks: List[Chunk] = []
        self._unit_embeddings: Optional[np.ndarray] = None
        self._embedder: Optional[SentenceTransformer] = None

    def _ensure_embedder(self) -> SentenceTransformer:
        if self._embedder is None:
            self._embedder = SentenceTransformer(self.embed_model_name)
        return self._embedder

    def _iter_text_files(self) -> Iterable[Tuple[Path, str]]:
        for path in sorted(self.base_dir.rglob("*")):
            if not path.is_file():
                continue
            if self.allowed_exts and path.suffix.lower() not in self.allowed_exts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                try:
                    text = path.read_text(encoding="latin-1")
                except Exception:
                    continue
            except Exception:
                continue
            yield path, text

    def _chunk_text(self, text: str) -> List[str]:
        if not text:
            return []
        tokens = text.split()
        if not tokens:
            return []
        chunks: List[str] = []
        step = self.chunk_size - self.chunk_overlap
        if step <= 0:
            step = self.chunk_size
        for start in range(0, len(tokens), step):
            end = start + self.chunk_size
            chunk_tokens = tokens[start:end]
            if chunk_tokens:
                chunks.append(" ".join(chunk_tokens))
        return chunks

    def build(self) -> Tuple[int, int]:
        files_indexed = 0
        all_chunks: List[Chunk] = []
        for path, text in self._iter_text_files():
            chunks = self._chunk_text(text)
            if not chunks:
                continue
            for idx, chunk_text in enumerate(chunks):
                all_chunks.append(Chunk(path=str(path), chunk_id=idx, text=chunk_text))
            files_indexed += 1

        if not all_chunks:
            raise RuntimeError(
                f"No text content found in {self.base_dir} (extensions: {', '.join(self.allowed_exts) or 'any'})"
            )

        embedder = self._ensure_embedder()
        embeddings = embedder.encode(
            [chunk.text for chunk in all_chunks],
            convert_to_numpy=True,
            show_progress_bar=True,
            batch_size=32,
        )
        embeddings = embeddings.astype(np.float32)
        norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
        norms[norms == 0.0] = 1.0
        unit = embeddings / norms

        np.save(self._emb_path, unit)
        with self._chunks_path.open("w", encoding="utf-8") as fh:
            json.dump([chunk.__dict__ for chunk in all_chunks], fh, indent=2, ensure_ascii=False)

        self._chunks = all_chunks
        self._unit_embeddings = unit
        return files_indexed, len(all_chunks)

    def load(self) -> None:
        if not self._chunks_path.exists() or not self._emb_path.exists():
            raise FileNotFoundError("Index files missing; run with --reindex first.")
        with self._chunks_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        self._chunks = [Chunk(**item) for item in data]
        self._unit_embeddings = np.load(self._emb_path)

    def ensure_ready(self, rebuild: bool = False) -> Tuple[int, int]:
        if rebuild or not (self._chunks_path.exists() and self._emb_path.exists()):
            return self.build()
        if not self._chunks:
            self.load()
        return len({chunk.path for chunk in self._chunks}), len(self._chunks)

    def search(self, query: str, top_k: int) -> List[Tuple[float, Chunk]]:
        if not query.strip():
            raise ValueError("Query is empty.")
        if self._unit_embeddings is None or not self._chunks:
            self.load()
        assert self._unit_embeddings is not None
        embedder = self._ensure_embedder()
        q_vec = embedder.encode([query], convert_to_numpy=True)[0].astype(np.float32)
        q_norm = np.linalg.norm(q_vec)
        if q_norm == 0.0:
            raise ValueError("Embedding for query is zero; refine the query.")
        q_unit = q_vec / q_norm
        scores = self._unit_embeddings @ q_unit
        top_k = max(1, min(top_k, len(scores)))
        top_indices = np.argsort(scores)[-top_k:][::-1]
        return [(float(scores[idx]), self._chunks[idx]) for idx in top_indices]


_LLM_CACHE: dict[str, Llama] = {}


def get_llm(model_path: Path, max_tokens: int) -> Llama:
    key = str(model_path.resolve())
    llm = _LLM_CACHE.get(key)
    if llm is None:
        llm = Llama(
            model_path=str(model_path),
            n_ctx=max(2048, max_tokens * 4),
            n_threads=os.cpu_count() or 4,
            n_gpu_layers=-1,
        )
        _LLM_CACHE[key] = llm
    return llm


SYSTEM_PROMPT = (
    "You are a meticulous retrieval-augmented assistant. Use the provided context to answer the question. "
    "If the answer is not contained in the context, say you do not know. Cite file names when relevant."
)


def format_context(results: List[Tuple[float, Chunk]]) -> str:
    lines = []
    for score, chunk in results:
        header = f"Source: {chunk.path} (chunk {chunk.chunk_id}, score {score:.3f})"
        lines.append(header)
        lines.append("-" * len(header))
        lines.append(chunk.text.strip())
        lines.append("")
    return "\n".join(lines).strip()


def generate_answer(
    query: str,
    results: List[Tuple[float, Chunk]],
    model_path: Path,
    max_tokens: int,
    temperature: float,
) -> str:
    llm = get_llm(model_path, max_tokens=max_tokens)
    context_block = format_context(results)
    user_prompt = textwrap.dedent(
        f"""
        Context:
        {context_block}

        Question: {query}

        Instructions:
        - Base your answer strictly on the context above.
        - Cite files and chunk numbers when referencing information.
        - If the context is insufficient, state that you do not know.
        """
    ).strip()
    completion = llm.create_chat_completion(
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=max_tokens,
        temperature=temperature,
    )
    return completion["choices"][0]["message"]["content"].strip()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Local MCP RAG server")
    parser.add_argument("--directory", default=str(SOURCE_DIR), help="Directory to index")
    parser.add_argument("--index-dir", default=str(INDEX_DIR), help="Where to store the vector index")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="Token chunk size (words)")
    parser.add_argument("--chunk-overlap", type=int, default=DEFAULT_CHUNK_OVERLAP, help="Word overlap between chunks")
    parser.add_argument("--allowed-exts", default=",".join(sorted(ALLOWED_EXTENSIONS)), help="Comma separated list of allowed extensions")
    parser.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL, help="SentenceTransformer model name")
    parser.add_argument("--model-path", default=DEFAULT_MODEL_PATH, help="Path to GGUF model for llama.cpp")
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K, help="Number of chunks to retrieve")
    parser.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS, help="Max tokens for generation")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE, help="Sampling temperature for generation")
    parser.add_argument("--reindex", action="store_true", help="Force rebuilding the vector index")
    parser.add_argument("--serve", action="store_true", help="Start the MCP server")
    parser.add_argument("--query", help="Ask a single question and print the answer")

    args = parser.parse_args(argv)

    base_dir = Path(args.directory).expanduser().resolve()
    if not base_dir.exists():
        raise SystemExit(f"Directory not found: {base_dir}")

    allowed_exts = [
        ext.strip().lower() if ext.strip().startswith('.') else f".{ext.strip().lower()}"
        for ext in args.allowed_exts.split(',')
        if ext.strip()
    ]

    index = RAGIndex(
        base_dir=base_dir,
        index_dir=Path(args.index_dir).expanduser().resolve(),
        chunk_size=args.chunk_size,
        chunk_overlap=args.chunk_overlap,
        allowed_exts=allowed_exts,
        embed_model_name=args.embed_model,
    )

    files, chunks = index.ensure_ready(rebuild=args.reindex)

    if args.query:
        results = index.search(args.query, args.top_k)
        answer = generate_answer(
            query=args.query,
            results=results,
            model_path=Path(args.model_path).expanduser().resolve(),
            max_tokens=args.max_tokens,
            temperature=args.temperature,
        )
        print(answer)
        return 0

    if not args.serve:
        print(
            "Index ready (files: {files}, chunks: {chunks}). Use --serve to start the MCP server or --query to run an ad-hoc question.".format(
                files=files,
                chunks=chunks,
            )
        )
        return 0

    server = FastMCPServer("rag-directory")

    @server.tool()
    def rag_query(
        query: str,
        top_k: int = args.top_k,
        max_tokens: int = args.max_tokens,
        temperature: float = args.temperature,
    ) -> dict:
        """Answer a question using retrieval augmented generation over the indexed directory."""
        results = index.search(query, top_k)
        answer = generate_answer(
            query=query,
            results=results,
            model_path=Path(args.model_path).expanduser().resolve(),
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return {
            "answer": answer,
            "results": [
                {
                    "score": score,
                    "path": chunk.path,
                    "chunk_id": chunk.chunk_id,
                    "preview": chunk.text[:400],
                }
                for score, chunk in results
            ],
        }

    @server.tool()
    def rag_reindex() -> dict:
        """Rebuild the RAG index from disk."""
        files_built, chunks_built = index.ensure_ready(rebuild=True)
        return {
            "files": files_built,
            "chunks": chunks_built,
        }

    print(f"Starting MCP server for directory: {base_dir}")
    server.run()
    return 0


if __name__ == "__main__":  # pragma: no cover - script entry
    raise SystemExit(main())
''')


class MCPRAGTool:
    key = "mcp_rag"
    title = "MCP RAG Server Generator"
    description = (
        "Create a ready-to-run Model Context Protocol server that performs retrieval-"
        "augmented generation over a chosen directory using lightweight, commercially"
        "permissive models."
    )

    def __init__(self) -> None:
        self.ctx: Optional[AppContext] = None
        self.panel: Optional[tb.Frame] = None

        self.source_var: Optional[tk.StringVar] = None
        self.output_var: Optional[tk.StringVar] = None
        self.index_var: Optional[tk.StringVar] = None
        self.chunk_size_var: Optional[tk.IntVar] = None
        self.chunk_overlap_var: Optional[tk.IntVar] = None
        self.embed_model_var: Optional[tk.StringVar] = None
        self.llm_path_var: Optional[tk.StringVar] = None
        self.allowed_exts_var: Optional[tk.StringVar] = None
        self.top_k_var: Optional[tk.IntVar] = None
        self.max_tokens_var: Optional[tk.IntVar] = None
        self.temperature_var: Optional[tk.DoubleVar] = None

        self.status_var: Optional[tk.StringVar] = None
        self.output_text: Optional[TkScrolledText] = None
        self.advanced_frame: Optional[tb.LabelFrame] = None

    def make_panel(self, master, context: AppContext):
        self.ctx = context
        self.panel = tb.Frame(master, padding=8)

        self.source_var = tk.StringVar()
        self.output_var = tk.StringVar(value="rag_mcp_server.py")
        self.index_var = tk.StringVar(value=".rag_index")
        self.chunk_size_var = tk.IntVar(value=600)
        self.chunk_overlap_var = tk.IntVar(value=150)
        self.embed_model_var = tk.StringVar(value="sentence-transformers/all-MiniLM-L6-v2")
        self.llm_path_var = tk.StringVar(value="models/phi-2-q4.gguf")
        self.allowed_exts_var = tk.StringVar(value=".txt,.md,.markdown,.rst,.json,.py,.cfg,.ini")
        self.top_k_var = tk.IntVar(value=4)
        self.max_tokens_var = tk.IntVar(value=512)
        self.temperature_var = tk.DoubleVar(value=0.1)
        self.status_var = tk.StringVar(value="Select a directory then click Generate.")

        dir_row = tb.Frame(self.panel)
        dir_row.pack(fill="x", pady=(0, 8))
        tb.Label(dir_row, text="Source directory:").pack(side="left")
        dir_entry = tb.Entry(dir_row, textvariable=self.source_var)
        dir_entry.pack(side="left", fill="x", expand=True, padx=(6, 6))
        tb.Button(dir_row, text="Browse", command=self._choose_directory, bootstyle="secondary").pack(side="left")

        out_row = tb.Frame(self.panel)
        out_row.pack(fill="x", pady=(0, 8))
        tb.Label(out_row, text="Output script:").pack(side="left")
        out_entry = tb.Entry(out_row, textvariable=self.output_var)
        out_entry.pack(side="left", fill="x", expand=True, padx=(6, 6))
        tb.Label(out_row, text="(relative paths resolve inside the source folder)", bootstyle="secondary").pack(side="left")

        opts = tb.Frame(self.panel)
        opts.pack(fill="x", pady=(0, 8))
        tb.Label(opts, text="Chunk size:").grid(row=0, column=0, sticky="w")
        tb.Spinbox(opts, from_=100, to=2000, increment=50, textvariable=self.chunk_size_var, width=6).grid(row=0, column=1, sticky="w", padx=(4, 12))
        tb.Label(opts, text="Overlap:").grid(row=0, column=2, sticky="w")
        tb.Spinbox(opts, from_=0, to=1000, increment=25, textvariable=self.chunk_overlap_var, width=6).grid(row=0, column=3, sticky="w", padx=(4, 12))
        tb.Label(opts, text="Top K:").grid(row=0, column=4, sticky="w")
        tb.Spinbox(opts, from_=1, to=20, textvariable=self.top_k_var, width=4).grid(row=0, column=5, sticky="w", padx=(4, 0))

        self.advanced_frame = tb.LabelFrame(self.panel, text="Advanced", padding=8)
        if context.ui_mode == "pro":
            self.advanced_frame.pack(fill="x", pady=(0, 8))
        self._populate_advanced()

        action_row = tb.Frame(self.panel)
        action_row.pack(fill="x", pady=(6, 6))
        tb.Button(action_row, text="Generate MCP Server", bootstyle="success", command=self._generate).pack(side="left")
        tb.Label(action_row, textvariable=self.status_var, bootstyle="secondary").pack(side="left", padx=(12, 0))

        self.output_text = TkScrolledText(self.panel, height=14, wrap="word")
        self.output_text.pack(fill="both", expand=True)
        self.output_text.insert("1.0", "Generated script output will appear here.")
        self.output_text.configure(state="disabled")

        return self.panel

    def _populate_advanced(self):
        if not self.advanced_frame:
            return
        for child in list(self.advanced_frame.winfo_children()):
            child.destroy()

        tb.Label(self.advanced_frame, text="Index directory:").grid(row=0, column=0, sticky="w")
        tb.Entry(self.advanced_frame, textvariable=self.index_var).grid(row=0, column=1, sticky="we", padx=(6, 6))
        tb.Label(self.advanced_frame, text="Allowed extensions:").grid(row=1, column=0, sticky="w")
        tb.Entry(self.advanced_frame, textvariable=self.allowed_exts_var).grid(row=1, column=1, sticky="we", padx=(6, 6))

        tb.Label(self.advanced_frame, text="Embedding model:").grid(row=2, column=0, sticky="w")
        tb.Entry(self.advanced_frame, textvariable=self.embed_model_var).grid(row=2, column=1, sticky="we", padx=(6, 6))
        tb.Label(self.advanced_frame, text="LLM model path:").grid(row=3, column=0, sticky="w")
        tb.Entry(self.advanced_frame, textvariable=self.llm_path_var).grid(row=3, column=1, sticky="we", padx=(6, 6))

        tb.Label(self.advanced_frame, text="Max tokens:").grid(row=4, column=0, sticky="w")
        tb.Spinbox(self.advanced_frame, from_=128, to=2048, textvariable=self.max_tokens_var, width=6).grid(row=4, column=1, sticky="w")
        tb.Label(self.advanced_frame, text="Temperature:").grid(row=5, column=0, sticky="w")
        tb.Spinbox(self.advanced_frame, from_=0.0, to=1.5, increment=0.05, textvariable=self.temperature_var, width=6).grid(row=5, column=1, sticky="w")

        self.advanced_frame.columnconfigure(1, weight=1)

    def _choose_directory(self):
        path = filedialog.askdirectory()
        if path and self.source_var is not None:
            self.source_var.set(path)

    def _generate(self):
        if not all([
            self.source_var,
            self.output_var,
            self.index_var,
            self.chunk_size_var,
            self.chunk_overlap_var,
            self.embed_model_var,
            self.llm_path_var,
            self.allowed_exts_var,
            self.top_k_var,
            self.max_tokens_var,
            self.temperature_var,
            self.status_var,
        ]):
            return

        source = Path(self.source_var.get()).expanduser()
        if not source.exists():
            self.status_var.set(f"Directory not found: {source}")
            return

        output_path = Path(self.output_var.get()).expanduser()
        if not output_path.is_absolute():
            output_path = source / output_path
        output_path.parent.mkdir(parents=True, exist_ok=True)

        index_dir = Path(self.index_var.get()).expanduser()
        if not index_dir.is_absolute():
            index_dir = source / index_dir

        allowed_exts = [ext.strip() for ext in self.allowed_exts_var.get().split(',') if ext.strip()]
        allowed_exts_repr = "{" + ", ".join(repr(ext if ext.startswith('.') else f".{ext}") for ext in allowed_exts) + "}"
        if allowed_exts_repr == "{}":
            allowed_exts_repr = "set()"

        script_text = SCRIPT_TEMPLATE.substitute(
            source_dir=str(source),
            script_name=output_path.name,
            embed_model=self.embed_model_var.get().strip(),
            default_model_path=self.llm_path_var.get().strip(),
            chunk_size=self.chunk_size_var.get(),
            chunk_overlap=self.chunk_overlap_var.get(),
            allowed_extensions=allowed_exts_repr,
            source_dir_repr=repr(str(source)),
            index_dir_repr=repr(str(index_dir)),
            default_top_k=self.top_k_var.get(),
            default_max_tokens=self.max_tokens_var.get(),
            default_temperature=self.temperature_var.get(),
        )

        output_path.write_text(script_text, encoding="utf-8")
        mode = output_path.stat().st_mode
        output_path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        if self.output_text:
            self.output_text.configure(state="normal")
            self.output_text.delete("1.0", "end")
            self.output_text.insert("1.0", script_text)
            self.output_text.configure(state="disabled")

        self.status_var.set(f"Generated: {output_path}")

    def start(self, context: AppContext, targets, argv) -> None:
        if targets and self.source_var:
            self.source_var.set(str(targets[0]))

    def cleanup(self) -> None:  # pragma: no cover - GUI lifecycle hook
        pass

    def on_mode_changed(self, ui_mode: str) -> None:
        if not self.advanced_frame:
            return
        if ui_mode == "pro":
            if not self.advanced_frame.winfo_ismapped():
                self.advanced_frame.pack(fill="x", pady=(0, 8))
        else:
            if self.advanced_frame.winfo_ismapped():
                self.advanced_frame.pack_forget()


PLUGIN = MCPRAGTool()
