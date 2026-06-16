#!/usr/bin/env python3
import ida_domain
import idaapi
import json
import os
import sys

def extract_cfg_from_db(db_path, output_path=None):
    """
    Opens an IDA database from disk and extracts the CFG using ida_domain.
    """
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} not found.")
        return None

    print(f"Opening database: {db_path}")
    
    try:
        # Using ida_domain.Database as a context manager ensures proper cleanup
        # save_on_close=False avoids modifying the original .i64/.idb file
        with ida_domain.Database.open(db_path, save_on_close=False) as db:

            entry_points = db.entries.get_all()
            entry_addresses = {info.address for info in entry_points}

            cfg = {
                "functions": {},
                "edges": []
            }

            print(f"Number of functions found: {len(db.functions)}")

            print("Extracting functions and intra-function edges...")
            functions_found = 0
            entry_found = False
            for func in db.functions:
                functions_found += 1
                func_ea = func.start_ea
                func_name = db.functions.get_name(func)
                func_node_info = {
                    "name": func_name,
                    "start_ea": func.start_ea,
                    "end_ea": func.end_ea,
                    "entry_point": func_ea in entry_addresses,
                    "non_call_links": False,
                    "blocks": [],
                    "edges": []
                }
                # Use string representation of EA for JSON keys
                cfg["functions"][str(func_ea)] = func_node_info
                if func_node_info["entry_point"]:
                    entry_found = True


                # Get flowchart for the function
                fc = db.functions.get_flowchart(func)
                if not fc:
                    # If no flowchart, still add the function start as a block 
                    # so it's not missing from the graph nodes.
                    cfg["functions"][str(func_ea)]["blocks"].append({
                        "start": func.start_ea,
                        "end": func.end_ea,
                        "id": 0
                    })
                    continue
                
                for block in fc:
                    cfg["functions"][str(func_ea)]["blocks"].append({
                        "start": block.start_ea,
                        "end": block.end_ea,
                        "id": block.id
                    })
                    
                    # Determine if the exit from this block is conditional
                    num_succs = block.count_successors()
                    is_cond = (num_succs > 1)

                    for succ in block.get_successors():
                        cfg["edges"].append({
                            "src": block.start_ea,
                            "dst": succ.start_ea,
                            "type": "intra-function",
                            "conditional": bool(is_cond)
                        })

            print(f"Found {functions_found} functions.")
            if not entry_found:
                print("Warning: No entry points found among the functions. Check if the database is properly analyzed.")
            # Add inter-function edges (calls)
            print("Extracting inter-function calls...")
            for func in db.functions:

                for xref in db.xrefs.to_ea(func.start_ea):
                    source = xref.from_ea
                    source_func = db.functions.get_at(source)
                    source_chunk = db.functions.get_chunk_at(source)
                    if not source_func or not source_chunk:
                        continue

                    if xref.is_call:
                        # Find the specific block that contains the call for more accurate CFG
                        src_block_ea = source_chunk.start_ea
                        source_fc = db.functions.get_flowchart(source_func)
                        if source_fc:
                            for b in source_fc:
                                if b.start_ea <= source < b.end_ea:
                                    src_block_ea = b.start_ea
                                    break

                        cfg["edges"].append({
                            "src": src_block_ea,
                            "dst": xref.to_ea,
                            "type": "inter-function",
                            "conditional": False
                        })
                    else:
                        if "main" in func.name.lower():
                            print(f"Found non-call link to main {xref.to_ea} from {source_func.name} @ {hex(source_func.start_ea)}")
                        cfg["edges"].append({
                            "src": src_block_ea,
                            "dst": xref.to_ea,
                            "type": "non-call",
                            "conditional": False
                        })
                        cfg["functions"][str(xref.to_ea)]["non_call_links"] = True
                        cfg["functions"][str(src_block_ea)]["non_call_links"] = True


            # Save to file
            if output_path is None:
                output_path = os.path.splitext(db_path)[0] + "_cfg.json"
                
            with open(output_path, "w") as f:
                json.dump(cfg, f, indent=4)
            
            print(f"CFG exported to {output_path}")
            return output_path

    except Exception as e:
        print(f"Error during extraction: {e}")
        import traceback
        traceback.print_exc()
        return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_cfg.py <path_to_idb_or_i64>")
        sys.exit(1)
    
    db_path = sys.argv[1]
    extract_cfg_from_db(db_path)
