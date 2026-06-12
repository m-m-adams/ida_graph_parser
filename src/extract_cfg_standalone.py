#!/usr/bin/env python3
import idapro
# After idapro module was loaded, you can simply import IDA Python modules
import ida_entry
import ida_nalt
import idaapi
import idc
import idautils
import ida_ida
import ida_funcs
import ida_name
import ida_bytes
import ida_typeinf
import json
import os
import sys

def extract_cfg_from_db(db_path, output_path=None):
    """
    Opens an IDA database from disk and extracts the CFG.
    """
    if not os.path.exists(db_path):
        print(f"Error: Database file {db_path} not found.")
        return None

    print(f"Opening database: {db_path}")
    
    # Initialize IDA in headless mode
    # For idapro >= 9.0, we use idapro.open_database
    try:
        print("Attempting to open database...")
        db_handle = idapro.open_database(db_path, run_auto_analysis=True)
        if db_handle != 0:
            print("Failed to open database: open_database returned 0")
            return None
            
        print(f"Database opened with handle: {db_handle}")


        cfg = {
            "functions": {},
            "edges": []
        }

        functions = list(idautils.Functions())
        print(f"Number of functions found: {len(functions)}")

        print("Extracting functions and intra-function edges...")
        functions_found = 0
        for func_ea in functions:
            functions_found += 1
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
        
        print(f"Found {functions_found} functions.")

        # Add inter-function edges (calls)
        print("Extracting inter-function calls...")
        for func_ea in functions:
            for head in idautils.FuncItems(func_ea):
                for xref in idautils.XrefsFrom(head, 0):
                    if xref.type in [idaapi.fl_CN, idaapi.fl_CF]: # Call Near, Call Far
                        cfg["edges"].append({
                            "src": head,
                            "dst": xref.to,
                            "type": "inter-function"
                        })

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

def extract_cfg_from_db_old(db_path, output_path=None):
    # Keeping the old one just in case as a fallback
    pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_cfg_standalone.py <path_to_idb_or_i64>")
        sys.exit(1)
    
    db_path = sys.argv[1]
    extract_cfg_from_db(db_path)
