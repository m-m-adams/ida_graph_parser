import asyncio
import json
import os
from pathlib import Path
from openai import AsyncOpenAI
from tqdm.notebook import tqdm
import networkx as nx
from typing import Optional

DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434/v1"

TREE_ROLLUP_SYSTEM_PROMPT = """
You are a reverse-engineering assistant building a hierarchical summary of a function call graph.
You are given one parent function summary and summaries of callee functions that have already been summarized.
Rewrite the parent summary so it explicitly accounts for the child/callee behavior.
Focus on how the parent uses child results, prepares child inputs, branches on outcomes, mutates state, and exposes side effects.
Be concise, precise, and useful to an expert reverse engineer. Do not invent behavior.
""".strip()

CYCLE_SYSTEM_PROMPT = """
You are a reverse-engineering assistant building a summary for a collection of mutually recursive functions (a cycle).
These functions closely call each other to form a state engine or core execution loop.
Synthesize a single overarching component description explaining how this structural loop functions collectively.
""".strip()

GLOBAL_ROOT_SYSTEM_PROMPT = """
You are a lead reverse engineer synthesizing a global profile of an entire software binary call graph.
Review the summaries of the top-level operational modules (both cyclic engines and main entry workflows).
Provide a high-level architectural overview explaining the core mission, input/output channels, and subsystem layout of the program.
""".strip()


class HierarchicalGraphSummarizer:
    def __init__(
        self,
        graph: nx.DiGraph,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: str = DEFAULT_MODEL,
        use_ollama: bool = False,
    ):
        self.graph = graph.copy()
        if use_ollama:
            base_url = base_url or os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_BASE_URL)
            if not base_url.rstrip("/").endswith("/v1"):
                base_url = base_url.rstrip("/") + "/v1"
            api_key = api_key or "ollama"
            model = model if model != DEFAULT_MODEL else "short-context-model"
        self.model = model
        self.client = AsyncOpenAI(
            api_key=api_key or os.environ.get("OPENAI_API_KEY", "unused"),
            base_url=base_url or os.environ.get("OPENAI_BASE_URL"),
        )

        self.community_sum = {}
        # Tracks active state components to build deep recursive JSON nests
        self.node_registry = {}

    async def call_llm(self, system_prompt: str, user_prompt: str) -> str:
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            return f"LLM Generation Error: {str(e)}"
        
    def find_scc(self):
        sccs = list(nx.strongly_connected_components(self.graph))
        sccs_cleaned = [cycle for cycle in sccs if len(cycle) > 1 or self.graph.has_edge(list(cycle)[0], list(cycle)[0])]
        print(f"Number of SCCs: {len(sccs)}")
        print(f"Number of SCCs with more than 1 value: {len(sccs_cleaned)}")
        return sccs_cleaned

    def remove_isolated_nodes(self, label_suffix: str = "initial"):
        """Removes isolated nodes. Can be run multiple times to catch post-collapse orphans."""
        isolated_nodes = list(nx.isolates(self.graph))
        if not isolated_nodes:
            return

        key_name = f'isolated_func_{label_suffix}'
        isolated_summary = {
            "community_id": f"isolated_{label_suffix}",
            "level": 1,
            "summary": f"Cluster containing {len(isolated_nodes)} unreferenced or post-collapse isolated functions.",
            "source_ids": [],
            "source_details": []
        }

        for node in isolated_nodes:
            node_str = str(node)
            # Fetch existing nested details from registry if it was a collapsed tree root
            cached_data = self.node_registry.get(node_str, {
                "id": node_str,
                "name": self.graph.nodes[node].get("name", node_str),
                "summary": self.graph.nodes[node].get("summary", "")
            })

            isolated_summary["source_ids"].append(node_str)
            isolated_summary["source_details"].append(cached_data)

        self.community_sum[key_name] = isolated_summary
        self.graph.remove_nodes_from(isolated_nodes)
        print(f"[{label_suffix}] Clear: Removed {len(isolated_nodes)} isolated node(s)")

    async def execute_pipeline(self):
        """Runs the upgraded sequential pipeline."""
        # 1. Strip natural isolated nodes
        self.remove_isolated_nodes(label_suffix="initial")
        
        # 2. Extract cycle landmarks
        sccs_cleaned = self.find_scc()
        cyclic_nodes = set()
        for scc in sccs_cleaned:
            cyclic_nodes.update(scc)

        # 3. Collapse trees (populates deep recursive maps)
        await self.process_acyclic_trees(cyclic_nodes)

        # 4. SWEEP: Catch nodes that became isolated AFTER their child subtrees were deleted
        self.remove_isolated_nodes(label_suffix="post_collapse_orphans")

        # 5. Process Cyclic Elements
        await self.process_cyclic_components(sccs_cleaned)
        
        # 6. Generate the global overview capping Level 0
        await self.generate_global_root()
        
        # 7. Flush to file
        self.generate_json_comm_file()

    async def process_acyclic_trees(self, cyclic_nodes: set):
        """Processes trees bottom-up, generating deep nested recursive component lists."""
        acyclic_nodes = [n for n in self.graph.nodes() if n not in cyclic_nodes]
        acyclic_subgraph = self.graph.subgraph(acyclic_nodes).copy()

        if not acyclic_subgraph.nodes:
            print("No external acyclic tree formations found.")
            return

        bottom_up_order = list(nx.topological_sort(acyclic_subgraph))[::-1]
        print(f"Processing {len(bottom_up_order)} acyclic tree nodes bottom-up...")

        for node in bottom_up_order:
            node_data = self.graph.nodes[node]
            node_str = str(node)
            
            callees = list(self.graph.successors(node))
            
            source_ids = []
            source_details = []
            callee_summaries = []

            for callee in callees:
                callee_data = self.graph.nodes[callee]
                callee_str = str(callee)
                
                source_ids.append(callee_str)
                
                # RECURSIVE LOOKUP: If the child has its own nested tree, embed it directly here!
                if callee_str in self.node_registry:
                    source_details.append(self.node_registry[callee_str])
                else:
                    source_details.append({
                        "id": callee_str,
                        "name": callee_data.get("name", callee_str),
                        "summary": callee_data.get("summary", "No summary available.")
                    })
                
                edge_data = self.graph.edges.get((node, callee), {})
                edge_type = edge_data.get('edge_type', 'Direct Call') 
                
                callee_summaries.append(
                    f"- Target Function: {callee_data.get('name', callee_str)}\n"
                    f"  Relationship Type: [{edge_type}]\n"
                    f"  Target Summary: {callee_data.get('summary', 'No summary available.')}"
                )

            user_prompt = f"Parent Function: {node_data.get('name', node_str)}\n"
            user_prompt += f"Base Code Context / Existing Summary: {node_data.get('summary', '')}\n\n"
            if callee_summaries:
                user_prompt += "### Discovered Callee Subroutine Information:\n"
                user_prompt += "\n---\n".join(callee_summaries)
            else:
                user_prompt += "(This function acts as a terminal tree leaf/sink node.)"

            updated_summary = await self.call_llm(TREE_ROLLUP_SYSTEM_PROMPT, user_prompt)
            self.graph.nodes[node]['summary'] = updated_summary

            # Track this node's registry metadata block recursively
            node_component = {
                "id": node_str,
                "name": node_data.get("name", node_str),
                "summary": updated_summary
            }
            if source_ids:
                node_component["source_ids"] = source_ids
                node_component["source_details"] = source_details

            self.node_registry[node_str] = node_component

            # If it has children, also surface it as a wave summary on level 2
            if source_ids:
                comp_id = f"component_tree_{node_str}"
                self.community_sum[comp_id] = {
                    "community_id": comp_id,
                    "level": 2,
                    "summary": updated_summary,
                    "source_ids": source_ids,
                    "source_details": source_details
                }
                
                # Prune leaf edges so parent can become an isolated node if it has no other connections
                edges_to_remove = [(node, c) for c in callees]
                self.graph.remove_edges_from(edges_to_remove)

    async def process_cyclic_components(self, sccs_cleaned):
        """Summarizes each complex cyclic network group matching level 2 expectations."""
        cycle_idx = 0
        for scc in sccs_cleaned:
            cycle_idx += 1
            comp_id = f"component_cycle_{cycle_idx}"
            
            print(f"Summarizing Cyclic Component Group {comp_id} with {len(scc)} members...")
            
            source_ids = []
            source_details = []
            member_payloads = []

            for member in scc:
                member_data = self.graph.nodes[member]
                member_str = str(member)
                
                source_ids.append(member_str)
                
                # If this cycle member absorbed a tree earlier, pull its full recursive details
                if member_str in self.node_registry:
                    source_details.append(self.node_registry[member_str])
                else:
                    source_details.append({
                        "id": member_str,
                        "name": member_data.get("name", member_str),
                        "summary": member_data.get("summary", "")
                    })
                
                member_payloads.append(
                    f"Function: {member_data.get('name', member_str)}\n"
                    f"Context/Summary: {member_data.get('summary', '')}"
                )

            cycle_user_prompt = "The following functions mutually loop or recurse within each other:\n\n"
            cycle_user_prompt += "\n---\n".join(member_payloads)
            
            cycle_group_summary = await self.call_llm(CYCLE_SYSTEM_PROMPT, cycle_user_prompt)

            self.community_sum[comp_id] = {
                "community_id": comp_id,
                "level": 2,
                "summary": cycle_group_summary,
                "source_ids": source_ids,
                "source_details": source_details
            }

    async def generate_global_root(self):
        """Assembles the ultimate top-level Level 0 global context component."""
        print("Synthesizing Ultimate Level 0 Global Root Component...")
        
        source_ids = []
        source_details = []
        summary_payloads = []

        for comp_id, comp_data in self.community_sum.items():
            source_ids.append(comp_id)
            source_details.append(comp_data)
            summary_payloads.append(f"Module ID: {comp_id}\nSummary: {comp_data.get('summary', '')}")

        global_prompt = "Synthesize a core application profile from these subsystem modules:\n\n"
        global_prompt += "\n===\n".join(summary_payloads)

        global_summary = await self.call_llm(GLOBAL_ROOT_SYSTEM_PROMPT, global_prompt)

        # Prepend the ultimate structural layer to the file
        self.community_sum = {
            "global_root": {
                "community_id": "global_root",
                "level": 0,
                "summary": global_summary,
                "source_ids": source_ids,
                "source_details": source_details
            },
            **self.community_sum
        }

    def generate_json_comm_file(self):
        with open("hierarchical_summaries.json", "w", encoding="utf-8") as f:
            json.dump(self.community_sum, f, ensure_ascii=False, indent=4)