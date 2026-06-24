import math
from collections import defaultdict

# Get a position for every block within the same function and create a circular call graph visualization
def function_cluster_layout(G, radius=10, spacing=80):
    funcs = defaultdict(list)
    for n, d in G.nodes(data=True):
        funcs[d.get("func")].append(n)

    layout = {}
    func_names = sorted(funcs)

    # Get grid size depending on the number of functions
    cols = math.ceil(math.sqrt(len(func_names)))


    for i, func in enumerate(func_names):
        # Get grid position
        cx = (i % cols) * spacing
        cy = (i // cols) * spacing

        # Order blocks by their adresses (since circular, maybe not very useful, but could try linear)
        blocks = sorted(funcs[func])

        for j, node in enumerate(blocks):
            # Create circle with blocks within the same function
            angle = 2 * math.pi * j / max(1, len(blocks))
            layout[node] = {
                "x": cx + radius * math.cos(angle),
                "y": cy + radius * math.sin(angle),
            }

    return layout

# Make intra-function edges weight higher so that ForceAtlas keeps the function together when visualizing
def add_force_weights(G, intra_weight=80.0, inter_weight=0.001):
    H = G.copy()

    for u, v, d in H.edges(data=True):
        edge_type = d.get("type")

        u_funcs = set(H.nodes[u].get("funcs", [H.nodes[u].get("func")]))
        v_funcs = set(H.nodes[v].get("funcs", [H.nodes[v].get("func")]))
        same_function = bool(u_funcs & v_funcs)

        if edge_type == "intra-function" and same_function:
            d["weight"] = intra_weight
        elif edge_type in {"inter-function", "non-call", "imported-function"}:
            d["weight"] = inter_weight

    return H