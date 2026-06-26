import asyncio
import json
import os
from collections import defaultdict
from pathlib import Path
from tqdm.asyncio import tqdm
import networkx as nx
from typing import Optional
from openai import AsyncOpenAI


DEFAULT_MODEL = "qwen3.5:4b"
DEFAULT_OLLAMA_BASE_URL = "http://192.168.1.101:8000"

TREE_ROLLUP_SYSTEM_PROMPT = """
You are a reverse-engineering assistant building a hierarchical summary of a function call graph.
You are given one parent function summary and summaries of callee functions that have already been summarized.
Rewrite the parent summary so it explicitly accounts for the child/callee behavior.
For each callee, consider how the edge type shapes the relationship:
  - Direct Call: parent explicitly invokes callee and may use its return value
  - Indirect Call: parent calls callee via function pointer or vtable; note uncertainty
  - Tail Call: parent transfers control entirely to callee; callee's return is the parent's return
  - Conditional Call: callee is only invoked on a specific branch; describe the condition if inferable
  - Data Flow: callee produces data consumed by parent without a direct call (e.g. shared buffer, global)
Focus on how the parent uses child results, prepares child inputs, branches on outcomes, mutates state, and exposes side effects.
Be concise, precise, and useful to an expert reverse engineer. Do not invent behavior.
""".strip()

CYCLE_SYSTEM_PROMPT = """
You are a reverse-engineering assistant summarizing a strongly connected component (SCC)
that has been collapsed into a single callable unit.
You are given the internal members and their intra-cycle relationships.
Write the summary from the perspective of an EXTERNAL caller:
  - What does calling into this component do?
  - What inputs does it consume, what outputs or side effects does it produce?
  - What is its termination condition or exit behavior?
Do NOT describe internal recursion mechanics — those are implementation details.
The summary will be used by parent functions to understand what this unit does, not how.
Be concise and precise. Do not invent behavior.
""".strip()

GLOBAL_ROOT_SYSTEM_PROMPT = """
You are a lead reverse engineer synthesizing a global profile of an entire software binary call graph.
Review the summaries of the top-level operational modules (isolated utilities, shared dependencies,
cyclic engines, and main entry workflows).
Provide a high-level architectural overview explaining the core mission, input/output channels,
and subsystem layout of the program. Identify likely program category (e.g. network daemon, CLI tool,
cryptographic library, loader/unpacker, etc.) and highlight any suspicious or notable patterns.
""".strip()


class HierarchicalGraphSummarizer:
    def __init__(
        self,
        graph: nx.DiGraph,
        *,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_OLLAMA_BASE_URL
    ):
        self.graph = graph.copy()
        self.model = model
        self.client = AsyncOpenAI(
            api_key=api_key or "ollama",
            base_url= base_url,
        )

        # Final community output map: community_id -> community dict
        self.community_sum: dict = {}

        # Registry of per-node nested detail blobs built during tree processing.
        # Keyed by str(node). Consulted when a node is referenced as a callee
        # after its own subtree has already been collapsed.
        self.node_registry: dict = {}

        # Tracks how many times a node has been embedded as a full source_detail
        # inside another node's community. Once >= 1 the node is retroactively
        # promoted to a shared community and subsequent parents only get a ref.
        self.embed_count: defaultdict = defaultdict(int)

    # ------------------------------------------------------------------
    # LLM
    # ------------------------------------------------------------------

    async def call_llm(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.2,
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"[LLM Error: {str(e)}]"

    # ------------------------------------------------------------------
    # Graph helpers
    # ------------------------------------------------------------------

    def find_scc(self) -> list[set]:
        """Return SCCs that are actually cyclic (size > 1 or self-loop)."""
        sccs = list(nx.strongly_connected_components(self.graph))
        cyclic = [
            s for s in sccs
            if len(s) > 1 or self.graph.has_edge(list(s)[0], list(s)[0])
        ]
        print(f"SCCs total: {len(sccs)}  |  Cyclic: {len(cyclic)}")
        return cyclic

    def _node_label(self, node) -> str:
        return self.graph.nodes[node].get("name", str(node))

    def _node_summary(self, node) -> str:
        return self.graph.nodes[node].get("summary", "No summary available.")

    def _edge_type(self, src, dst) -> str:
        return self.graph.edges.get((src, dst), {}).get("edge_type", "Direct Call")

    # ------------------------------------------------------------------
    # Isolated node handling
    # ------------------------------------------------------------------

    def remove_isolated_nodes(self, label_suffix: str = "initial"):
        """
        Collect truly isolated nodes into a single flat community bucket,
        then remove them from the live graph. Safe to call multiple times.
        """
        isolated = list(nx.isolates(self.graph))
        if not isolated:
            return

        key = f"isolated_func_{label_suffix}"
        entry = {
            "community_id": key,
            "level": 1,
            "summary": (
                f"Cluster of {len(isolated)} unreferenced / post-collapse "
                "isolated functions with no caller or callee edges."
            ),
            "source_ids": [],
            "source_details": [],
        }

        for node in isolated:
            node_str = str(node)
            detail = self.node_registry.get(node_str, {
                "id": node_str,
                "name": self._node_label(node),
                "summary": self._node_summary(node),
            })
            entry["source_ids"].append(node_str)
            entry["source_details"].append(detail)

        self.community_sum[key] = entry
        self.graph.remove_nodes_from(isolated)
        print(f"[{label_suffix}] Removed {len(isolated)} isolated node(s)")

    # ------------------------------------------------------------------
    # Shared-node promotion (idempotent, callable at any time)
    # ------------------------------------------------------------------

    def promote_shared_node(self, node):
        """
        Promote a node to its own level-1 shared-dependency community.
        Idempotent: safe to call multiple times for the same node.
        """
        node_str = str(node)
        comp_id = f"component_shared_{node_str}"
        if comp_id in self.community_sum:
            return  # already promoted

        detail = self.node_registry.get(node_str, {
            "id": node_str,
            "name": self._node_label(node),
            "summary": self._node_summary(node),
        })
        self.community_sum[comp_id] = {
            "community_id": comp_id,
            "level": 1,
            "summary": detail.get("summary", ""),
            "source_ids": [node_str],
            "source_details": [detail],
            "shared": True,
        }
        print(f"  → Promoted shared node {node_str} ({self._node_label(node)}) to {comp_id}")

    def _is_shared(self, node_str: str) -> bool:
        return f"component_shared_{node_str}" in self.community_sum

    # ------------------------------------------------------------------
    # Tree root promotion
    # ------------------------------------------------------------------

    def promote_tree_roots(self, cyclic_nodes: set):
        """
        After tree collapse + orphan sweep, any surviving non-cyclic, non-shared
        node with in-degree 0 is a true tree root. Give it its own level-1 community.
        """
        promoted = 0
        for node in list(self.graph.nodes()):
            if node in cyclic_nodes:
                continue
            node_str = str(node)
            if self._is_shared(node_str):
                continue
            if self.graph.in_degree(node) == 0:
                comp_id = f"component_tree_root_{node_str}"
                detail = self.node_registry.get(node_str, {
                    "id": node_str,
                    "name": self._node_label(node),
                    "summary": self._node_summary(node),
                })
                self.community_sum[comp_id] = {
                    "community_id": comp_id,
                    "level": 1,
                    "summary": detail.get("summary", ""),
                    "source_ids": [node_str],
                    "source_details": [detail],
                }
                promoted += 1
        print(f"Promoted {promoted} tree root(s) to level-1 communities")

    # ------------------------------------------------------------------
    # Acyclic tree processing (bottom-up, dynamic shared detection)
    # ------------------------------------------------------------------

    async def process_acyclic_trees(self, cyclic_nodes: set):
        acyclic_nodes = [n for n in self.graph.nodes() if n not in cyclic_nodes]
        acyclic_subgraph = self.graph.subgraph(acyclic_nodes).copy()

        if not acyclic_subgraph.nodes:
            print("No acyclic tree nodes found.")
            return

        # Seed embed_count with static in-degree so obvious shared nodes
        # are caught before the first parent tries to embed them.
        for node in acyclic_subgraph.nodes():
            indeg = acyclic_subgraph.in_degree(node)
            if indeg > 1:
                # Pre-flag: will be promoted on first embedding attempt
                self.embed_count[str(node)] = 1

        bottom_up_order = list(nx.topological_sort(acyclic_subgraph))[::-1]
        print(f"Processing {len(bottom_up_order)} acyclic nodes bottom-up...")

        for node in tqdm(bottom_up_order, desc="Tree nodes"):
            node_data = self.graph.nodes[node]
            node_str = str(node)

            callees = list(self.graph.successors(node))

            source_ids = []
            source_details = []
            callee_summary_lines = []

            for callee in callees:
                callee_str = str(callee)
                callee_data = self.graph.nodes[callee]
                edge_type = self._edge_type(node, callee)

                source_ids.append(callee_str)

                # Build the full detail blob for this callee
                full_detail = self.node_registry.get(callee_str, {
                    "id": callee_str,
                    "name": callee_data.get("name", callee_str),
                    "summary": callee_data.get("summary", "No summary available."),
                })

                # Decide: embed fully or reference only
                if self.embed_count[callee_str] >= 1:
                    # Already embedded elsewhere (or pre-flagged as multi-parent)
                    # → promote to shared community if not already done
                    self.promote_shared_node(callee)
                    source_details.append({
                        "id": callee_str,
                        "name": callee_data.get("name", callee_str),
                        "edge_type": edge_type,
                        "shared_dependency": True,
                        "ref": f"component_shared_{callee_str}",
                    })
                else:
                    # First (and so far only) embedding — include full subtree
                    detail_with_edge = {**full_detail, "edge_type": edge_type}
                    source_details.append(detail_with_edge)
                    self.embed_count[callee_str] += 1

                callee_summary_lines.append(
                    f"- Target: {callee_data.get('name', callee_str)}\n"
                    f"  Edge Type: [{edge_type}]\n"
                    f"  Summary: {callee_data.get('summary', 'No summary available.')}"
                )

            # Build LLM prompt
            user_prompt = (
                f"Parent Function: {node_data.get('name', node_str)}\n"
                f"Existing Summary: {node_data.get('summary', '')}\n\n"
            )
            if callee_summary_lines:
                user_prompt += "### Callee Subroutines:\n"
                user_prompt += "\n---\n".join(callee_summary_lines)
            else:
                user_prompt += "(Terminal leaf / sink node — no callees.)"

            updated_summary = await self.call_llm(TREE_ROLLUP_SYSTEM_PROMPT, user_prompt)
            self.graph.nodes[node]["summary"] = updated_summary

            # Register this node's full nested blob for future parents
            node_component = {
                "id": node_str,
                "name": node_data.get("name", node_str),
                "summary": updated_summary,
            }
            if source_ids:
                node_component["source_ids"] = source_ids
                node_component["source_details"] = source_details
            self.node_registry[node_str] = node_component

            # Emit level-2 community only for non-shared nodes that have children
            # Shared nodes get their community from promote_shared_node instead.
            if source_ids and not self._is_shared(node_str):
                comp_id = f"component_tree_{node_str}"
                self.community_sum[comp_id] = {
                    "community_id": comp_id,
                    "level": 2,
                    "summary": updated_summary,
                    "source_ids": source_ids,
                    "source_details": source_details,
                }
                # Prune edges so this node can become isolated (leaf-like) for
                # the orphan sweep to catch if no cyclic node points to it.
                self.graph.remove_edges_from([(node, c) for c in callees])

            # If this node was just promoted to shared (by a sibling pass above
            # or by pre-flagging), update its community summary now that we have
            # a fresh LLM summary for it.
            comp_shared_id = f"component_shared_{node_str}"
            if comp_shared_id in self.community_sum:
                self.community_sum[comp_shared_id]["summary"] = updated_summary
                # Also refresh the source_details inside the shared community
                refreshed_detail = self.node_registry[node_str]
                self.community_sum[comp_shared_id]["source_details"] = [refreshed_detail]

    # ------------------------------------------------------------------
    # Cyclic SCC processing
    # ------------------------------------------------------------------

    async def process_cyclic_components(self, sccs_cleaned: list[set]):
        """Summarize each SCC as a level-2 cyclic community."""
        for cycle_idx, scc in enumerate(tqdm(sccs_cleaned, desc="SCC groups"), start=1):
            comp_id = f"component_cycle_{cycle_idx}"
            print(f"  Summarizing {comp_id} ({len(scc)} members)...")

            source_ids = []
            source_details = []
            member_lines = []

            for member in scc:
                member_str = str(member)
                member_data = self.graph.nodes[member]

                source_ids.append(member_str)

                detail = self.node_registry.get(member_str, {
                    "id": member_str,
                    "name": member_data.get("name", member_str),
                    "summary": member_data.get("summary", ""),
                })
                source_details.append(detail)

                # Collect intra-SCC edge types for the prompt
                intra_edges = []
                for other in scc:
                    if other == member:
                        continue
                    if self.graph.has_edge(member, other):
                        et = self._edge_type(member, other)
                        intra_edges.append(
                            f"  → {self.graph.nodes[other].get('name', str(other))} [{et}]"
                        )

                edge_block = (
                    "\n".join(intra_edges) if intra_edges else "  (no direct intra-SCC edges)"
                )
                member_lines.append(
                    f"Function: {member_data.get('name', member_str)}\n"
                    f"Summary: {member_data.get('summary', '')}\n"
                    f"Intra-cycle calls:\n{edge_block}"
                )

            cycle_prompt = (
                "The following functions form a mutually recursive cycle:\n\n"
                + "\n---\n".join(member_lines)
            )
            cycle_summary = await self.call_llm(CYCLE_SYSTEM_PROMPT, cycle_prompt)

            self.community_sum[comp_id] = {
                "community_id": comp_id,
                "level": 2,
                "summary": cycle_summary,
                "source_ids": source_ids,
                "source_details": source_details,
            }

    # ------------------------------------------------------------------
    # Global root
    # ------------------------------------------------------------------

    async def generate_global_root(self):
        """Assemble the level-0 global architectural overview."""
        print("Synthesizing global root (level 0)...")

        source_ids = list(self.community_sum.keys())
        source_details = list(self.community_sum.values())

        summary_blocks = [
            f"Module: {cid}\nLevel: {cdata.get('level')}\nSummary: {cdata.get('summary', '')}"
            for cid, cdata in self.community_sum.items()
        ]
        global_prompt = (
            "Synthesize a core application profile from these subsystem modules:\n\n"
            + "\n===\n".join(summary_blocks)
        )
        global_summary = await self.call_llm(GLOBAL_ROOT_SYSTEM_PROMPT, global_prompt)

        self.community_sum = {
            "global_root": {
                "community_id": "global_root",
                "level": 0,
                "summary": global_summary,
                "source_ids": source_ids,
                "source_details": source_details,
            },
            **self.community_sum,
        }
    
    async def collapse_sccs_into_metanodes(self, sccs_cleaned: list[set], pass_idx: int):
        """
        Summarize each SCC and replace it with a single meta-node in the graph.
        The meta-node inherits all external edges of the SCC members so the next
        tree pass can reason over it correctly.
        """
        for cycle_idx, scc in enumerate(sccs_cleaned, start=1):
            comp_id = f"component_cycle_p{pass_idx}_{cycle_idx}"
            print(f"  Collapsing {comp_id} ({len(scc)} members)...")

            source_ids = []
            source_details = []
            member_lines = []

            for member in scc:
                member_str = str(member)
                member_data = self.graph.nodes[member]
                source_ids.append(member_str)

                detail = self.node_registry.get(member_str, {
                    "id": member_str,
                    "name": member_data.get("name", member_str),
                    "summary": member_data.get("summary", ""),
                })
                source_details.append(detail)

                intra_edges = []
                for other in scc:
                    if other != member and self.graph.has_edge(member, other):
                        et = self._edge_type(member, other)
                        intra_edges.append(
                            f"  → {self.graph.nodes[other].get('name', str(other))} [{et}]"
                        )
                edge_block = "\n".join(intra_edges) or "  (no direct intra-SCC edges)"
                member_lines.append(
                    f"Function: {member_data.get('name', member_str)}\n"
                    f"Summary: {member_data.get('summary', '')}\n"
                    f"Intra-cycle calls:\n{edge_block}"
                )

            cycle_prompt = (
                "The following functions form a mutually recursive cycle:\n\n"
                + "\n---\n".join(member_lines)
            )
            cycle_summary = await self.call_llm(CYCLE_SYSTEM_PROMPT, cycle_prompt)

            self.community_sum[comp_id] = {
                "community_id": comp_id,
                "level": 2,
                "summary": cycle_summary,
                "source_ids": source_ids,
                "source_details": source_details,
            }

            # Collect all external edges (edges crossing SCC boundary)
            external_preds = []
            external_succs = []
            for member in scc:
                for pred in self.graph.predecessors(member):
                    if pred not in scc:
                        external_preds.append((pred, member))
                for succ in self.graph.successors(member):
                    if succ not in scc:
                        external_succs.append((member, succ))

            # Add meta-node to graph
            self.graph.add_node(
                comp_id,
                name=comp_id,
                summary=cycle_summary,
            )
            self.node_registry[comp_id] = {
                "id": comp_id,
                "name": comp_id,
                "summary": cycle_summary,
                "source_ids": source_ids,
                "source_details": source_details,
            }

            # Rewire external edges to/from meta-node
            for pred, _ in external_preds:
                et = self._edge_type(pred, _)
                self.graph.add_edge(pred, comp_id, edge_type=et)
            for _, succ in external_succs:
                et = self._edge_type(_, succ)
                self.graph.add_edge(comp_id, succ, edge_type=et)

            # Remove original SCC members
            self.graph.remove_nodes_from(scc)

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def generate_json_comm_file(self, path: str = "hierarchical_summaries.json"):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.community_sum, f, ensure_ascii=False, indent=4)
        print(f"Summaries written to {path}")

    async def emit_remainder(self):
        """
        If the graph stops reducing (e.g. two meta-nodes pointing at each other
        with no further collapsible structure), emit whatever remains as a
        catch-all community so the global root still has something to reason over.
        """
        remaining = list(self.graph.nodes())
        if not remaining:
            return
        source_ids = []
        source_details = []
        member_lines = []
        for node in remaining:
            node_str = str(node)
            source_ids.append(node_str)
            detail = self.node_registry.get(node_str, {
                "id": node_str,
                "name": self._node_label(node),
                "summary": self._node_summary(node),
            })
            source_details.append(detail)
            member_lines.append(f"Module: {node_str}\nSummary: {detail.get('summary', '')}")

        summary = await self.call_llm(CYCLE_SYSTEM_PROMPT, "\n---\n".join(member_lines))
        self.community_sum["remainder"] = {
            "community_id": "remainder",
            "level": 1,
            "summary": summary,
            "source_ids": source_ids,
            "source_details": source_details,
        }

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def execute_pipeline(self):
        self.remove_isolated_nodes(label_suffix="initial")

        pass_idx = 0
        while True:
            pass_idx += 1
            print(f"\n=== Pass {pass_idx} ===")
            nodes_before = self.graph.number_of_nodes()

            # 1. Tree pass
            sccs_cleaned = self.find_scc()
            cyclic_nodes = set()
            for scc in sccs_cleaned:
                cyclic_nodes.update(scc)

            await self.process_acyclic_trees(cyclic_nodes)
            self.promote_tree_roots(cyclic_nodes)
            self.remove_isolated_nodes(label_suffix=f"pass_{pass_idx}_post_tree")

            # 2. Cycle collapse — replace each SCC with a single meta-node
            sccs_cleaned = self.find_scc()
            if sccs_cleaned:
                await self.collapse_sccs_into_metanodes(sccs_cleaned, pass_idx)
                self.remove_isolated_nodes(label_suffix=f"pass_{pass_idx}_post_cycle")

            nodes_after = self.graph.number_of_nodes()
            print(f"Pass {pass_idx}: {nodes_before} → {nodes_after} nodes")

            # Stop when graph is fully reduced
            if nodes_after == 0:
                print("Graph fully collapsed.")
                break
            if nodes_after == nodes_before:
                # No progress made — emit whatever remains as a final community
                print("No progress — emitting remaining nodes as final root.")
                await self.emit_remainder()
                break

            await self.generate_global_root()
            self.generate_json_comm_file()