#!/usr/bin/env python3
import ida_domain.functions
import json
import argparse
import os
import hashlib
from typing import Hashable, Dict
import ida_domain.types as ida_types
import networkx as nx
from matplotlib import colormaps
import matplotlib.colors as mcolors
from networkx import DiGraph, k_core


def get_function_color(func_name, func_colors=None):
    """
    Generates a color for a function name.
    If func_colors mapping is provided, uses it for continuous coloring.
    Otherwise falls back to deterministic MD5 hash.
    """
    if func_name == "unknown":
        return "gray"

    if func_colors and func_name in func_colors:
        return func_colors[func_name]

    # Fallback to MD5 to get a consistent hash for the function name
    hash_object = hashlib.md5(func_name.encode())
    return "#" + hash_object.hexdigest()[:6]

def read_json(json_path: str) -> Dict:
    """
    Reads a JSON file and returns its content as a dictionary.
    """
    if not os.path.exists(json_path):
        print(f"Error: File {json_path} not found.")
        return None

    with open(json_path, 'r') as f:
        return json.load(f)

def load_cfg(data: Dict) -> nx.DiGraph:
    #

    G = nx.DiGraph()

    # Pre-calculate continuous colors based on function addresses
    sorted_func_eas = sorted(data['functions'].keys(), key=lambda x: int(x, 16))
    cmap = colormaps['turbo']

    func_colors = {}
    num_funcs = len(sorted_func_eas)
    for i, ea in enumerate(sorted_func_eas):
        name = data['functions'][ea]['name']
        if name not in func_colors:
            val = i / max(1, num_funcs - 1)
            func_colors[name] = mcolors.to_hex(cmap(val))

    # Add nodes (basic blocks)
    for func_ea_str in sorted(data['functions'].keys(), key=lambda x: int(x, 16), reverse=True):
        func_data = data['functions'][func_ea_str]
        func_name = func_data['name']
        node_color = get_function_color(func_name, func_colors)
        for block in func_data['blocks']:
            block_label = f"{func_name} @ {block['start']}"
            G.add_node(
                block['start'],
                label=block_label,
                func=func_name,
                color=node_color,
                entry_point=func_data['entry_point'],
                non_call_links=func_data['non_call_links'],
                flags=func_data['flags'],
                id=block['id'],
                instrs=[instr['disasm'] for instr in block.get('instructions', [])],
                detailed_info=block.get('instructions', [])
            )

    # Add edges
    for edge in data['edges']:
        src = edge['src']
        dst = edge['dst']

        # Ensure nodes exist
        for node_ea in [src, dst]:
            if node_ea not in G:
                node_ea_str = str(node_ea)
                if node_ea_str in data['functions']:
                    func_name = data['functions'][node_ea_str]['name']
                    # Use the function name for label if it's a known function start
                    label = f"{func_name} @ {hex(node_ea)}"
                    color = get_function_color(func_name, func_colors)
                    G.add_node(node_ea, label=label, func=func_name, color=color)
                else:
                    G.add_node(node_ea, label=f"unknown @ {hex(node_ea)}", func="unknown",
                               color=get_function_color("unknown", func_colors))

        G.add_edge(src, dst, type=edge['type'], conditional=edge.get('conditional', False))
        if edge['type'] == 'non-call':
            G.nodes[src]['non_call_links'] = True
            G.nodes[dst]['non_call_links'] = True
    return G

def prune_graph(og: DiGraph[Hashable]) -> DiGraph[Hashable]:
    to_return = og.copy()
    print(f"Graph loaded: {len(to_return.nodes)} nodes, {len(to_return.edges)} edges")
    entrypoint = [x for x in to_return.nodes() if to_return.nodes[x]['entry_point'] == True]
    print(f"entrypoint is {entrypoint}")

    # remove self loops
    to_return.remove_edges_from(nx.selfloop_edges(to_return))

    to_return = collapse_thunks(to_return)
    to_return = collapse_chains(to_return)

    # remove nodes with degree <= 1
    to_return = k_core(to_return, 2)
    entrypoint = [x for x in to_return.nodes() if to_return.nodes[x]['entry_point'] == True]
    print(f"entrypoint is {entrypoint}")
    # to_be_removed = [x for  x in G.nodes() if G.degree()[x] <= 1]
    # print(f"Number of nodes to be removed: {len(to_be_removed)}")
    # G.remove_nodes_from(to_be_removed)
    # # Basic info
    # print(f"Number of functions after removing degree <= 1: {len(G.nodes)}")
    #
    # print(f"Number of nodes after collapsing chains: {len(G.nodes)}")
    # entrypoint = [x for x in G.nodes() if G.nodes[x]['entry_point'] == True]
    # if not entrypoint:
    #     print("No entrypoint found. Please check the graph.")
    #     raise ValueError("No entrypoint found")
    print(f"Graph pruned: {len(to_return.nodes)} nodes, {len(to_return.edges)} edges")
    return to_return

def collapse_thunks(G: nx.DiGraph):
    collapsed_G = G.copy()
    nodes_to_process = list(collapsed_G.nodes())

    for node in nodes_to_process:

        thunk = collapsed_G.nodes[node].get('thunk')
        if thunk:
            preds = list(collapsed_G.predecessors(node))
            succs = list(collapsed_G.successors(node))
            if len(succs) == 1:
                collapsed_G.remove_node(node)
                for pred in preds:
                    collapsed_G.add_edge(pred, succs[0], type="inter-function")
    return collapsed_G

def collapse_chains(G):
    """
    Collapses nodes that have exactly one predecessor and one successor.
    The node is removed, and an edge is created between its predecessor and successor.
    """
    collapsed_G = G.copy()
    nodes_to_process = list(collapsed_G.nodes())

    while True:
        changed = False
        for node in nodes_to_process:
            if node not in collapsed_G:
                continue

            # Check if node has exactly one predecessor and one successor
            if collapsed_G.out_degree(node) == 1:
                preds = list(collapsed_G.predecessors(node))
                succs = list(collapsed_G.successors(node))
                if len(succs) == 1:
                    succs_preds = list(collapsed_G.predecessors(succs[0]))
                    if len(succs_preds) == 1:
                        succ = succs[0]
                        for pred in preds:
                            if pred != node and succ != node and pred != succ:
                                # Transfer edge attributes and combine conditionality
                                edge1_data = collapsed_G.get_edge_data(pred, node)
                                edge2_data = collapsed_G.get_edge_data(node, succ)

                                new_attrs = edge1_data.copy()
                                new_attrs['conditional'] = edge1_data.get('conditional', False) or edge2_data.get('conditional',
                                                                                                                  False)

                                # If any part of the collapsed chain was an inter-function call,
                                # keep it marked as such.
                                if edge2_data.get('type') == 'inter-function':
                                    new_attrs['type'] = 'inter-function'

                                collapsed_G.add_edge(pred, succ, **new_attrs)
                                collapsed_G.remove_node(node)
                                changed = True
                                break  # Restart to avoid issues with iterator after modification

        if not changed:
            break

    return collapsed_G




def visualize_cfg(json_path):
    G = load_cfg(json_path)
    G = prune_graph(G)
    if G is None:
        return

    print(f"Graph loaded: {len(G.nodes)} nodes, {len(G.edges)} edges")
    print("ipysigma is designed for interactive environments (Jupyter).")
    print("To visualize this graph, use the provided wip.ipynb.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualize CFG exported from IDA")
    parser.add_argument("json_file", help="Path to the exported CFG JSON file")
    args = parser.parse_args()

    visualize_cfg(args.json_file)
