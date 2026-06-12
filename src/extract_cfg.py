#!/usr/bin/env python3
import idautils
import idc
import idaapi
import json
import os

def extract_cfg():
    """
    Extracts the full program control flow graph.
    Returns a dictionary with functions, basic blocks, and edges.
    """
    # Wait for auto-analysis to finish
    idaapi.auto_wait()

    cfg = {
        "functions": {},
        "edges": []
    }

    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        # Use string representation of EA for JSON keys
        cfg["functions"][str(func_ea)] = {
            "name": func_name,
            "blocks": []
        }

        # Get function flow chart
        f = idaapi.get_func(func_ea)
        if not f:
            continue
            
        fc = idaapi.FlowChart(f)
        
        for block in fc:
            cfg["functions"][str(func_ea)]["blocks"].append({
                "start": block.start_ea,
                "end": block.end_ea,
                "id": block.id
            })
            
            # Successors
            for succ in block.succs():
                cfg["edges"].append({
                    "src": block.start_ea,
                    "dst": succ.start_ea,
                    "type": "intra-function"
                })

    # Add inter-function edges (calls)
    print("Extracting inter-function calls...")
    for func_ea in idautils.Functions():
        for head in idautils.FuncItems(func_ea):
            for xref in idautils.XrefsFrom(head, 0):
                if xref.type in [idaapi.fl_CN, idaapi.fl_CF]: # Call Near, Call Far
                    # Find which block contains 'head'
                    # For simplicity, we can just use the head address as src
                    # But if we want it to be block-based, we'd need to map head to block
                    cfg["edges"].append({
                        "src": head,
                        "dst": xref.to,
                        "type": "inter-function"
                    })

    # Save to file
    output_path = os.path.splitext(idaapi.get_input_file_path())[0] + "_cfg.json"
    with open(output_path, "w") as f:
        json.dump(cfg, f, indent=4)
    
    print(f"CFG exported to {output_path}")

if __name__ == "__main__":
    extract_cfg()
    # If running in headless mode, you might want to exit
    # qexit(0)
