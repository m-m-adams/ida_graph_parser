import networkx as nx
from src.visualize_cfg import collapse_chains

def test_collapse():
    # Create a simple chain: 1 -> 2 -> 3
    G = nx.DiGraph()
    G.add_edge(1, 2)
    G.add_edge(2, 3)
    
    print(f"Original nodes: {G.nodes()}")
    collapsed = collapse_chains(G)
    print(f"Collapsed nodes: {collapsed.nodes()}")
    
    assert 2 not in collapsed
    assert collapsed.has_edge(1, 3)
    print("Test 1 (simple chain) passed!")

    # Test longer chain: 1 -> 2 -> 3 -> 4
    G = nx.DiGraph()
    G.add_edge(1, 2)
    G.add_edge(2, 3)
    G.add_edge(3, 4)
    
    collapsed = collapse_chains(G)
    print(f"Collapsed nodes (long chain): {collapsed.nodes()}")
    assert 2 not in collapsed
    assert 3 not in collapsed
    assert collapsed.has_edge(1, 4)
    print("Test 2 (long chain) passed!")

    # Test branching: 1 -> 2, 1 -> 3, 2 -> 4, 3 -> 4
    # Node 2 and 3 should NOT be collapsed because 1 has out-degree 2 and 4 has in-degree 2?
    # Wait, my logic was: node has exactly one predecessor and one successor.
    # Node 2 has one pred (1) and one succ (4). So it should be collapsed!
    # Result: 1 -> 4 (two edges if it was a MultiDiGraph, but it's a DiGraph)
    G = nx.DiGraph()
    G.add_edge(1, 2)
    G.add_edge(1, 3)
    G.add_edge(2, 4)
    G.add_edge(3, 4)
    
    collapsed = collapse_chains(G)
    print(f"Collapsed nodes (diamond): {collapsed.nodes()}")
    assert 2 not in collapsed
    assert 3 not in collapsed
    assert collapsed.has_edge(1, 4)
    print("Test 3 (diamond) passed!")

if __name__ == "__main__":
    test_collapse()
