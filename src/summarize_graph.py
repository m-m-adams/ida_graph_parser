#!/usr/bin/env python3
"""
Recursively summarizes a directed graph (CFG) using an OpenAI-compatible API.

Leaf nodes (no outgoing edges) have their instructions summarized directly.
Non-leaf nodes have their outgoing branches replaced by summaries of the
target nodes, then the combined instructions + branch summaries are summarized.

Handles cycles by treating back-edges (to already-visited nodes) as references
to a placeholder summary rather than recursing infinitely.
"""

import jsonlines
import asyncio
import logging
import sys
import time
from pathlib import Path
from typing import Optional

import networkx as nx
from tqdm import tqdm

import llm_interface
from extract_cfg import extract_cfg_from_db
from llm_interface import LLMInterface
from visualize_cfg import load_cfg, prune_graph

logger = logging.getLogger(__name__)


FUNC_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant. "
    "You are given all basic blocks of a single function's aarch64 assembly, "
    "along with the control flow between them. "
    "Summarize what this function does. Be concise. "
    "Your audience is an expert reverse engineer. "
    "If a function follows standard ABI calling conventions don't reexplain them."
)

FUNC_WITH_DEPS_SYSTEM_PROMPT = (
    "You are a reverse-engineering assistant. "
    "you are given a list of function summaries, one for each called/referenced function. "
    "You are then given all basic blocks of a single function's aarch64 assembly "
    "along with the control flow between them. "
    "Summarize what this function does at a high level, incorporating "
    "what the called/referenced functions do. Be concise. "
    "If a summary is not yet available for a called/referenced function, just note how that funtion is called or jumped to. "
    "Focus on how inputs are used and transformed into outputs. "
    "Your audience is an expert reverse engineer. You need to provide them"
    " an accurate understanding of the function's behavior. "
    "If a function follows standard ABI calling conventions don't reexplain them. "
    "Be concise and to the point. Do not add markdown or other fluff to the summary. "
    "The summary should include inputs, outputs, and any points of interest. "
    "Ensure that the summary is accurate and complete."
)


class GraphSummarizer:
    """Walks a directed graph and recursively summarizes each node via an
    OpenAI-compatible chat completions API."""

    def __init__(
        self,
        graph: nx.DiGraph,
        llm: LLMInterface,
    ):
        self.graph = graph
        self.llm = llm
        # func_name -> summary string
        self._summaries: dict[str, str] = {}
        self._t0 = time.perf_counter()
        self._cache_path: Optional[Path] = None
        self._pbar: Optional[tqdm] = None
        # Build function groupings: func_name -> list of node_ids
        self._func_nodes: dict[str, list] = {}
        self._needs_recheck: set[str] = set()
        for node_id, data in self.graph.nodes(data=True):
            func_name = data.get("func", str(node_id))
            self._func_nodes.setdefault(func_name, []).append(node_id)
        # Build inter-function dependency graph: func_name -> set of func_names it depends on
        self._func_deps: dict[str, set[str]] = {func: set() for func in self._func_nodes}
        for src, dst, edata in self.graph.edges(data=True):
            edge_type = edata.get("type", "")
            if edge_type in ("inter-function", "non-call"):
                src_func = self.graph.nodes[src].get("func", str(src))
                dst_func = self.graph.nodes[dst].get("func", str(dst))
                if src_func != dst_func:
                    self._func_deps[src_func].add(dst_func)

    def _func_is_ready(self, func_name: str) -> bool:
        """Check if all inter-function dependencies of a function are summarized."""
        for dep in self._func_deps.get(func_name, set()):
            if dep not in self._summaries:
                return False
        return True

    async def _summarize_function(self, func_name: str) -> str:
        """Summarize an entire function by passing all its blocks in one LLM call.

        Inter-function / non-call dependency summaries are appended when available."""
        nodes = self._func_nodes[func_name]

        # Build blocks text with intra-function control flow
        blocks_text = ""
        total_instrs = 0
        for nid in nodes:
            ndata = self.graph.nodes[nid]
            instrs = ndata.get("instrs", [])
            total_instrs += len(instrs)
            label = ndata.get("label", str(nid))
            instrs_text = "\n".join(instrs) if instrs else "(no instructions)"
            blocks_text += f"\n--- Block {label} ---\n{instrs_text}\n"

            # Add intra-function edges info
            for succ in self.graph.successors(nid):
                edge_data = self.graph.get_edge_data(nid, succ) or {}
                edge_type = edge_data["type"]
                if edge_type != "call":
                    succ_label = self.graph.nodes[succ].get("label", str(succ))
                    type = edge_data["type"]
                    blocks_text += f"  -> {succ_label} (type: {type})\n"

        # Check for inter-function dependencies
        deps = self._func_deps.get(func_name, set())
        deps_text = ""
        needs_recheck = False
        for dep_func in deps:
            try:
                dep_summary = self._summaries.get(dep_func)
                if "[unsummarized reference to " in dep_summary:
                    needs_recheck = True
                    dep_summary = f"[dependency summary not yet available for {dep_func}]"
                    self._needs_recheck.add(dep_func)
            except KeyError:
                needs_recheck = True
                dep_summary = f"[dependency summary not available for {dep_func}]"
                self._needs_recheck.add(dep_func)
            deps_text += f"\n--- Called function: {dep_func} ---\n{dep_summary}\n"

        if total_instrs == 0 and not deps_text:
            summary = f"Function {func_name}: (no instructions)"
        elif total_instrs < 10 and not deps_text:
            summary = f"Function {func_name}:\n{blocks_text.strip()}"
        elif deps_text:
            user_content = (
                f"=== Called/Referenced Function Summaries ==={deps_text}"
                f"=== Function: {func_name} ===\n"
                f"=== Basic Blocks ==={blocks_text}\n"
                f"Summarize function {func_name}, including all points of interest. "
            )
            summary = await self.llm.call_llm(FUNC_WITH_DEPS_SYSTEM_PROMPT, user_content, node_id=func_name)
        else:
            user_content = (
                f"=== Function: {func_name} ===\n"
                f"=== Basic Blocks ==={blocks_text}"
            )
            summary = await self.llm.call_llm(FUNC_SYSTEM_PROMPT, user_content, node_id=func_name)

        self._summaries[func_name] = summary
        if self._cache_path is not None:
            with jsonlines.open(self._cache_path, mode='a') as writer:
                logger.info("Writing summary for %s to cache", func_name)
                writer.write({func_name: summary})
        if self._pbar is not None and not needs_recheck:
            self._pbar.update(1)
        return summary

    async def summarize_function(self, func_name: str) -> str:
        """Public entry point – summarizes a single function (dependencies must already be done)."""
        return await self._summarize_function(func_name)

    def _load_cache(self) -> None:
        """Load cached summaries from disk if available."""
        if self._cache_path and self._cache_path.exists():
            try:
                with jsonlines.open(self._cache_path, "r") as f:
                    for line in f:
                        self._summaries.update(line)
                logger.info("Loaded %d cached summaries from %s", len(self._summaries), self._cache_path)
                self._summaries = {k: v for k, v in self._summaries.items() if not isinstance(v, str) or "unsummarized" not in v}
                with jsonlines.open(self._cache_path, "w") as f:
                    for k, v in self._summaries.items():
                        f.write({k: v})
            except (jsonlines.Error, OSError) as e:
                logger.warning("Failed to load cache from %s: %s", self._cache_path, e)


    def _clear_recursive(self) -> None:

        self._summaries = {k: v for k, v in self._summaries.items() if not isinstance(v, str) or "[unsummarized reference to " not in v}


    async def summarize_all(self, root: Optional[object] = None, cache_path: Optional[str | Path] = None) -> dict:
        """Summarize the entire graph using a queue-based worker strategy.

        Processes functions as they become ready (all dependencies summarized).
        """
        # Determine which functions to summarize
        if root is not None:
            reachable_nodes = set(nx.descendants(self.graph, root)) | {root}
            funcs_to_summarize = set()
            for nid in reachable_nodes:
                func_name = self.graph.nodes[nid].get("func", str(nid))
                if func_name in self._func_nodes:
                    funcs_to_summarize.add(func_name)
        else:
            funcs_to_summarize = set(self._func_nodes.keys())

        # Set up disk cache
        if cache_path is not None:
            self._cache_path = Path(cache_path)
            self._load_cache()
            self._clear_recursive()

        # Remove already-cached functions from remaining
        remaining = funcs_to_summarize - set(self._summaries.keys())
        total = len(funcs_to_summarize)
        already_cached = total - len(remaining)

        self._pbar = tqdm(file=sys.stdout, total=total, initial=already_cached, desc="Summarizing functions", unit="func")

        # Map: func_name -> set of functions that depend on it
        dependents = {f: set() for f in funcs_to_summarize}
        for f, deps in self._func_deps.items():
            if f in funcs_to_summarize:
                for d in deps:
                    if d in dependents:
                        dependents[d].add(f)

        queue = asyncio.Queue()
        for f in remaining:
            if self._func_is_ready(f):
                queue.put_nowait(f)

        async def worker():
            while True:
                f = await queue.get()
                try:
                    await self._summarize_function(f)
                    # Check if any functions that depend on f are now ready
                    # handles things that need a resummary because they had a stub
                    for dep_func in dependents.get(f, set()):
                        if dep_func not in self._summaries:
                            if self._func_is_ready(dep_func):
                                queue.put_nowait(dep_func)
                    remaining.discard(f)
                    logger.info("Finished summarizing %s", f)
                finally:
                    queue.task_done()

        # Start workers
        workers = [asyncio.create_task(worker()) for _ in range(self.llm.max_concurrent)]

        while remaining:
            await queue.join()

            if remaining and queue.empty():
                # Cycle breaking
                logger.info("remaining: %d functions but nothing ready, breaking cycles", len(remaining))
                broken = False
                for f in remaining:
                    if f not in self._summaries:
                        for dep in self._func_deps.get(f, set()):
                            if dep in remaining and dep not in self._summaries:
                                self._summaries[dep] = f"[unsummarized reference to {dep}]"

                # After breaking cycles, some functions might be ready
                for f in remaining:
                    if self._func_is_ready(f):
                        broken = True
                        queue.put_nowait(f)

                if not broken:
                    logging.error("Could not break cycles, giving up. Remaining functions: %s", remaining)
                    # whelp I think we're screwed
                    break
        logger.info("done")
        for w in workers:
            w.cancel()

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
    model: str = llm_interface.DEFAULT_MODEL,
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
    llm = LLMInterface(
        api_key=api_key,
        base_url=base_url,
        model=model,
        max_concurrent=max_concurrent,
        use_ollama=use_ollama,
    )
    summarizer = GraphSummarizer(
        graph,
        llm=llm,
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

if __name__ == "__main__":
    logger.setLevel(logging.INFO)
    logger.addHandler(logging.StreamHandler(stream=sys.stdout))
    db_path = "/Users/mark/windows_share/test/reorder_and_pad.exe.i64"
    json_path = "parsed_xref_graph.json"
    cfg = extract_cfg_from_db(db_path, output_path=json_path)
    G = load_cfg(cfg)
    pruned = prune_graph(G)
    summaries = summarize_graph(pruned, base_url="http://192.168.1.101:8000/v1", max_concurrent=256,
                                   model="qwen3-coder-next", cache_path="./cache_temp_temp.json")
    print("done")