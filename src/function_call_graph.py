# Visualize Level0 summaries - which are summaries for each function
import networkx as nx

def get_level0_summary_graph(G, *, include_non_call=False, include_unknown=False):
    function_graph = nx.DiGraph()
    call_edge_types = {"call", "imported-function"}
    if include_non_call:
        call_edge_types.add("non-call")
    if include_unknown:
        call_edge_types.add("unknown")

    # Collapse CFG block nodes into one node per function.
    for block_id, block_data in G.nodes(data=True):
        func = block_data.get("func", str(block_id))
        if func not in function_graph:
            function_graph.add_node(
                func,
                name=func,
                summary=block_data.get("summary", ""),
                color=block_data.get("color"),
                entry_point=False,
                block_ids=[],
                block_count=0,
                instruction_count=0,
                callers=[],
                callees=[],
                incoming_calls=[],
                outgoing_calls=[],
            )

        func_data = function_graph.nodes[func]
        func_data["block_ids"].append(block_id)
        func_data["block_count"] += 1
        func_data["instruction_count"] += len(block_data.get("instrs", []))
        func_data["entry_point"] = func_data["entry_point"] or block_data.get("entry_point", False)
        if not func_data.get("summary") and block_data.get("summary"):
            func_data["summary"] = block_data["summary"]

    # Keep only edges that cross function boundaries.
    # Some CFG edges are marked intra-function even when chain/block collapsing
    # leaves them connecting two different functions. At the function-summary
    # layer those are still cross-function relationships, so normalize them.
    for src_block, dst_block, edge_data in G.edges(data=True):
        edge_type = edge_data.get("type", "unknown")

        src_func = G.nodes[src_block].get("func", str(src_block))
        dst_func = G.nodes[dst_block].get("func", str(dst_block))
        if src_func == dst_func:
            continue
        if edge_type == "intra-function":
            edge_type = "inter-function"
        if edge_type not in call_edge_types:
            continue

        call = {
            "src_block": src_block,
            "dst_block": dst_block,
            "src_func": src_func,
            "dst_func": dst_func,
            "type": edge_type,
            "conditional": edge_data.get("conditional", False),
        }

        if function_graph.has_edge(src_func, dst_func):
            func_edge = function_graph.edges[src_func, dst_func]
            func_edge["call_count"] += 1
            func_edge["call_sites"].append(call)
            func_edge["edge_types"] = sorted(set(func_edge["edge_types"]) | {edge_type})
            func_edge["conditional"] = func_edge["conditional"] or edge_data.get("conditional", False)
        else:
            function_graph.add_edge(
                src_func,
                dst_func,
                type=edge_type,
                edge_types=[edge_type],
                call_count=1,
                call_sites=[call],
                conditional=edge_data.get("conditional", False),
            )

    # Add caller/callee metadata after all edges have been collapsed.
    for func in function_graph.nodes():
        callers = sorted(function_graph.predecessors(func))
        callees = sorted(function_graph.successors(func))
        function_graph.nodes[func]["callers"] = callers
        function_graph.nodes[func]["callees"] = callees
        function_graph.nodes[func]["incoming_calls"] = [
            call
            for caller in callers
            for call in function_graph.edges[caller, func]["call_sites"]
        ]
        function_graph.nodes[func]["outgoing_calls"] = [
            call
            for callee in callees
            for call in function_graph.edges[func, callee]["call_sites"]
        ]

    return function_graph
