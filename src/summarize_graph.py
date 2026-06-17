#!/usr/bin/env python3
"""
Recursively summarizes a directed graph (CFG) using an OpenAI-compatible API.

Leaf nodes (no outgoing edges) have their instructions summarized directly.
Non-leaf nodes have their outgoing branches replaced by summaries of the
target nodes, then the combined instructions + branch summaries are summarized.

Handles cycles by treating back-edges (to already-visited nodes) as references
to a placeholder summary rather than recursing infinitely.
"""

import json
import os
import asyncio
import logging
import time
from pathlib import Path
from typing import Optional

import networkx as nx
from openai import AsyncOpenAI
from tqdm import tqdm

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

LEAF_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant. "
    "You are given a code block's aarch64 assembly instructions"
    "Summarize the following assembly instructions concisely. "
    "Describe what the code block does at a high level."
    "Your audience is an expert reverse engineer who is combining these summaries to understand higher level functions"
    "If a function follows standard ABI calling conventions don't reexplain them"
)

NODE_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant. "
    "You are given a code block's aarch64 assembly instructions followed by summaries "
    "of the blocks it branches to. Summarize the overall behavior of this code "
    "block, incorporating what its branches do. Be concise and to the point. "
    "your audience is an expert reverse engineer "
    "If a function follows standard ABI calling conventions don't reexplain them "
)


class GraphSummarizer:
    """Walks a directed graph and recursively summarizes each node via an
    OpenAI-compatible chat completions API."""

    def __init__(
        self,
        graph: nx.DiGraph,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        max_concurrent: int = 10,
        use_ollama: bool = False,
    ):
        self.graph = graph
        if use_ollama:
            base_url = base_url or os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_BASE_URL)
            # Ensure the URL ends with /v1 for OpenAI compatibility
            if not base_url.rstrip("/").endswith("/v1"):
                base_url = base_url.rstrip("/") + "/v1"
            api_key = api_key or "ollama"  # Ollama ignores the key but OpenAI client requires one
            model = model if model != DEFAULT_MODEL else "short-context-model"
        self.model = model
        self.client = AsyncOpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY", "unused"),
            base_url=base_url or os.environ.get("OPENAI_BASE_URL"),
        )
        self.max_concurrent = max_concurrent
        self._semaphore: Optional[asyncio.Semaphore] = None
        # node_id -> summary string
        self._summaries: dict[str, str] = {}
        self._active_requests = 0
        self._t0 = time.perf_counter()
        self._cache_path: Optional[Path] = None
        self._pbar: Optional[tqdm] = None

    def _ensure_semaphore(self):
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_concurrent)

    async def _call_llm(self, system: str, user: str, node_id: str = "?") -> str:
        """Send an async chat completion request, limited by semaphore."""
        self._ensure_semaphore()
        async with self._semaphore:
            self._active_requests += 1
            start = time.perf_counter()
            try:
                response = await self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                )
                return response.choices[0].message.content.strip()
            finally:
                elapsed = time.perf_counter() - start
                self._active_requests -= 1

    def _node_is_ready(self, node_id) -> bool:
        """Check if all successors of a node are summarized (or are back-edges in cycles)."""
        for succ in self.graph.successors(node_id):
            if succ not in self._summaries:
                return False
        return True

    async def _summarize_single_node(self, node_id) -> str:
        """Summarize a single node whose successors are all already summarized
        (or treated as cycle placeholders)."""
        node_data = self.graph.nodes[node_id]
        instrs = node_data.get("instrs", [])
        instrs_text = "\n".join(instrs) if instrs else "(no instructions)"
        successors = list(self.graph.successors(node_id))

        if not successors:
            # Leaf node – summarize instructions directly
            logger.info("Summarizing leaf node %s", node_id)
            if len(instrs) < 10:
                logger.info("Leaf node %s has few instructions, skipping LLM call", node_id)
                summary = f"Leaf node {node_id}:\n{instrs_text}"
            else:
                summary = await self._call_llm(LEAF_SYSTEM_PROMPT, instrs_text, node_id=str(node_id))
        else:
            branches_text = ""
            for succ in successors:
                succ_label = self.graph.nodes[succ].get("label", str(succ))
                edge_data = self.graph.get_edge_data(node_id, succ) or {}
                edge_type = edge_data.get("type", "unknown")
                conditional = edge_data.get("conditional", False)
                branch_header = f"Branch to {succ_label} (type={edge_type}, conditional={conditional})"
                branch_summary = self._summaries.get(succ, f"[recursive reference to {succ_label}]")
                branches_text += f"\n--- {branch_header} ---\n{branch_summary}\n"

            user_content = (
                f"=== Instructions ===\n{instrs_text}\n\n"
                f"=== Branch Summaries ==={branches_text}"
            )
            logger.info("Summarizing non-leaf node %s with %d branches", node_id, len(successors))
            summary = await self._call_llm(NODE_SYSTEM_PROMPT, user_content, node_id=str(node_id))

        self._summaries[node_id] = summary
        self._save_cache()
        if self._pbar is not None:
            self._pbar.update(1)
        return summary

    async def summarize_node(self, node_id) -> str:
        """Public entry point – summarizes a single node (successors must already be done)."""
        return await self._summarize_single_node(node_id)

    def _load_cache(self) -> None:
        """Load cached summaries from disk if available."""
        if self._cache_path and self._cache_path.exists():
            try:
                with open(self._cache_path, "r") as f:
                    cached = json.load(f)
                self._summaries.update(cached)
                logger.info("Loaded %d cached summaries from %s", len(cached), self._cache_path)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load cache from %s: %s", self._cache_path, e)
    def _clear_recursive(self) -> None:

        self._summaries = {k: v for k, v in self._summaries.items() if not isinstance(v, str) or "[recursive reference to " not in v}

    def _save_cache(self) -> None:
        """Persist current summaries to disk."""
        if self._cache_path is None:
            return
        try:
            # Convert keys to strings for JSON serialization
            data = {str(k): v for k, v in self._summaries.items()}
            tmp = self._cache_path.with_suffix(".tmp")
            with open(tmp, "w") as f:
                json.dump(data, f)
            tmp.replace(self._cache_path)
        except OSError as e:
            logger.warning("Failed to save cache to %s: %s", self._cache_path, e)

    async def summarize_all(self, root: Optional[object] = None, cache_path: Optional[str | Path] = None) -> dict:
        """Summarize the entire graph using a bottom-up wave strategy.

        Processes nodes in waves: first all nodes whose successors are
        already summarized (leaves in the first wave), then nodes that
        become unblocked as their successors complete, and so on.

        Cycles are broken by inserting placeholder summaries for back-edge
        targets once no more nodes can be unblocked naturally.

        Returns a dict mapping node ids to their summaries.
        """
        # Determine which nodes to summarize
        if root is not None:
            # Collect all nodes reachable from root
            nodes_to_summarize = set(nx.descendants(self.graph, root)) | {root}
        else:
            nodes_to_summarize = set(self.graph.nodes())

        # Set up disk cache
        if cache_path is not None:
            self._cache_path = Path(cache_path)
            self._load_cache()
            self._clear_recursive()

        # Remove already-cached nodes from remaining
        remaining = set(nodes_to_summarize) - set(self._summaries.keys())
        total = len(nodes_to_summarize)
        already_cached = total - len(remaining)

        self._pbar = tqdm(total=total, initial=already_cached, desc="Summarizing nodes", unit="node")

        while remaining:
            # Find all nodes in remaining whose successors are all summarized
            ready = [n for n in remaining if self._node_is_ready(n)]

            if not ready:
                # No progress possible – break cycles by adding placeholders
                # for the node in remaining with the most unsummarized predecessors
                # (heuristic: pick nodes involved in cycles)
                # Insert placeholders for all remaining nodes' unsummarized successors
                # that are also in remaining (i.e., cycle edges)
                for n in remaining:
                    for succ in self.graph.successors(n):
                        if succ in remaining and succ not in self._summaries:
                            label = self.graph.nodes[succ].get("label", str(succ))
                            self._summaries[succ] = f"[recursive reference to {label}]"
                # Now find ready nodes again (all should be ready since we filled placeholders)
                ready = [n for n in remaining if self._node_is_ready(n)]
                if not ready:
                    break  # safety: should not happen

            # Summarize all ready nodes concurrently (overwrites any placeholders)
            logger.info("Wave: summarizing %d nodes concurrently", len(ready))
            tasks = [self._summarize_single_node(n) for n in ready]
            await asyncio.gather(*tasks)
            remaining -= set(ready)

        self._pbar.close()
        self._pbar = None
        return dict(self._summaries)

    @property
    def summaries(self) -> dict:
        return dict(self._summaries)


def summarize_graph(
    graph: nx.DiGraph,
    *,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    model: str = DEFAULT_MODEL,
    root: Optional[object] = None,
    max_concurrent: int = 10,
    use_ollama: bool = False,
    cache_path: Optional[str] = None,
) -> dict:
    """Convenience wrapper around :class:`GraphSummarizer`.

    Works both from regular scripts (``asyncio.run``) and from within
    a running event loop such as Jupyter notebooks (via ``nest_asyncio``).

    Parameters
    ----------
    graph : nx.DiGraph
        The directed graph to summarize. Nodes should have an ``instrs``
        attribute (list of instruction strings).
    api_key : str, optional
        OpenAI API key. Falls back to ``OPENAI_API_KEY`` env var.
        Ignored when ``use_ollama`` is True.
    base_url : str, optional
        Base URL for an OpenAI-compatible API. Falls back to
        ``OPENAI_BASE_URL`` env var.  For Ollama, defaults to
        ``http://localhost:11434/v1`` (or ``OLLAMA_HOST`` env var).
    model : str
        Model name to use for completions.  When ``use_ollama`` is
        True and no model is specified, defaults to ``llama3.2``.
    root : optional
        A specific root node to start summarization from.
    max_concurrent : int
        Maximum number of concurrent API requests.
    use_ollama : bool
        If True, connect to a local Ollama instance instead of OpenAI.
    cache_path : str, optional
        Path to a JSON file for caching summaries to disk. If provided,
        completed summaries are saved after each node so that progress
        survives interruptions. On restart, cached summaries are loaded
        and already-summarized nodes are skipped.

    Returns
    -------
    dict
        Mapping of node ids to summary strings.
    """
    summarizer = GraphSummarizer(
        graph,
        api_key=api_key,
        base_url=base_url,
        model=model,
        max_concurrent=max_concurrent,
        use_ollama=use_ollama,
    )
    coro = summarizer.summarize_all(root=root, cache_path=cache_path)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        # Running inside Jupyter or another async context.
        # Create a new event loop in a background thread so that
        # asyncio.gather can actually run tasks concurrently.
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result()
    else:
        return asyncio.run(coro)
