
def greedy_feedback_arc_set(G):
    feedback_edges = set()
    visited = set()
    rec_stack = set()
    
    def dfs(node):
        visited.add(node)
        rec_stack.add(node)
        
        for neighbor in G.successors(node):
            if neighbor not in visited:
                dfs(neighbor)
            elif neighbor in rec_stack:
                # Back edge found - add to feedback arc set
                feedback_edges.add((node, neighbor))
        
        rec_stack.remove(node)
    
    for node in G.nodes():
        if node not in visited:
            dfs(node)
    
    return feedback_edges


def digraph_to_dag(G):
    # Apply greedy FAS
    fas_edges = greedy_feedback_arc_set(G)

    # Create DAG by removing FAS edges
    G_dag = G.copy()
    G_dag.remove_edges_from(fas_edges)
    
    return G_dag
