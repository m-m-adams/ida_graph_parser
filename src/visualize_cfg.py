#!/usr/bin/env python3
import json
import argparse
import os
import hashlib
import networkx as nx
from matplotlib import colormaps
import matplotlib.colors as mcolors


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


def load_cfg(json_path) -> nx.DiGraph:
    """
    Loads CFG from JSON and returns a networkx DiGraph.
    """
    if not os.path.exists(json_path):
        print(f"Error: File {json_path} not found.")
        return None

    with open(json_path, 'r') as f:
        data = json.load(f)

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
            if collapsed_G.in_degree(node) == 1 and collapsed_G.out_degree(node) == 1:
                preds = list(collapsed_G.predecessors(node))
                succs = list(collapsed_G.successors(node))

                pred = preds[0]
                succ = succs[0]

                # Avoid creating self-loops
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
