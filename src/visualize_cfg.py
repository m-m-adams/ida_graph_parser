#!/usr/bin/env python3
import json
import argparse
import os
import networkx as nx

def load_cfg(json_path):
    """
    Loads CFG from JSON and returns a networkx DiGraph.
    """
    if not os.path.exists(json_path):
        print(f"Error: File {json_path} not found.")
        return None

    with open(json_path, 'r') as f:
        data = json.load(f)

    G = nx.DiGraph()

    # Add nodes (basic blocks)
    for func_ea_str, func_data in data['functions'].items():
        for block in func_data['blocks']:
            block_label = f"{func_data['name']} @ {hex(block['start'])}"
            G.add_node(
                block['start'],
                label=block_label,
                func=func_data['name'],
                color="skyblue"
            )

    # Add edges
    for edge in data['edges']:
        src = edge['src']
        dst = edge['dst']
        
        # Ensure nodes exist
        if src not in G:
            G.add_node(src, label=hex(src), func="unknown", color="gray")
        if dst not in G:
            G.add_node(dst, label=hex(dst), func="unknown", color="gray")
            
        G.add_edge(src, dst, type=edge['type'])

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
                
                # Avoid creating self-loops if not desired, or handle them
                if pred != node and succ != node:
                    # Optional: transfer edge attributes if needed
                    # Here we just create a simple edge
                    collapsed_G.add_edge(pred, succ)
                    collapsed_G.remove_node(node)
                    changed = True
                    break # Restart to avoid issues with iterator after modification
        
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
