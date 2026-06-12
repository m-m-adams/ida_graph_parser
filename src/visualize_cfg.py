#!/usr/bin/env python3
import json
import networkx as nx
import matplotlib.pyplot as plt
import argparse
import os

def load_cfg(json_path):
    if not os.path.exists(json_path):
        print(f"Error: File {json_path} not found.")
        return None

    with open(json_path, 'r') as f:
        data = json.load(f)

    G = nx.DiGraph()

    # Add nodes (basic blocks)
    for func_ea_str, func_data in data['functions'].items():
        func_ea = int(func_ea_str)
        for block in func_data['blocks']:
            block_label = f"{func_data['name']}\n{hex(block['start'])}"
            G.add_node(block['start'], label=block_label, func=func_data['name'])

    # Add edges
    for edge in data['edges']:
        src = edge['src']
        dst = edge['dst']
        
        # Ensure nodes exist
        if not G.has_node(src):
            G.add_node(src, label=hex(src), func="unknown")
        if not G.has_node(dst):
            G.add_node(dst, label=hex(dst), func="unknown")
            
        G.add_edge(src, dst, type=edge['type'])

    return G

def visualize_cfg(json_path):
    G = load_cfg(json_path)
    if not G:
        return

    print(f"Graph loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    # Simple visualization for small graphs
    if G.number_of_nodes() < 100:
        pos = nx.spring_layout(G)
        labels = nx.get_node_attributes(G, 'label')
        nx.draw(G, pos, labels=labels, with_labels=True, node_size=2000, node_color="skyblue", font_size=8)
        plt.show()
    else:
        print("Graph too large for simple spring layout visualization. Consider exporting to Graphviz.")
        
    # Export to DOT for better visualization
    try:
        from networkx.drawing.nx_pydot import write_dot
        dot_path = os.path.splitext(json_path)[0] + ".dot"
        write_dot(G, dot_path)
        print(f"Graph exported to {dot_path}")
    except ImportError:
        print("pydot not installed, skipping DOT export.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualize CFG exported from IDA")
    parser.add_argument("json_file", help="Path to the exported CFG JSON file")
    args = parser.parse_args()
    
    visualize_cfg(args.json_file)
