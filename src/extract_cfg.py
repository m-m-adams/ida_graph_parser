#!/usr/bin/env python3
import ida_domain
import idaapi
import json
import os
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Any

from ida_domain import Database
from ida_domain.flowchart import FlowChartFlags
from ida_ua import insn_t


@dataclass
class FuncNodeInfo:
    name: str
    start_ea: int
    end_ea: int
    entry_point: bool = False
    imported: bool = False
    module: Optional[str] = None
    non_call_links: bool = False
    blocks: List[dict] = field(default_factory=list)
    edges: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "start_ea": hex(self.start_ea),
            "end_ea": hex(self.end_ea),
            "entry_point": self.entry_point,
            "imported": self.imported,
            "module": self.module,
            "non_call_links": self.non_call_links,
            "blocks": self.blocks,
            "edges": self.edges,
        }


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

            print("Extracting imported functions...")
            import_addresses = {}
            for imp in db.imports.get_all_imports():
                imp_name = imp.name if imp.has_name() else f"{imp.module_name}!#{imp.ordinal}"
                import_addresses[imp.address] = imp_name
                cfg["functions"][hex(imp.address)] = FuncNodeInfo(
                    name=imp_name,
                    start_ea=imp.address,
                    end_ea=imp.address,
                    entry_point=False,
                    imported=True,
                    module=imp.module_name,
                ).to_dict()
            print(f"Found {len(import_addresses)} imported functions.")

            print("Extracting functions and intra-function edges...")
            functions_found = 0
            entry_found = False
            for func in db.functions:
                functions_found += 1
                func_ea = func.start_ea
                func_name = func.name
                func_node_info = FuncNodeInfo(
                    name=func_name,
                    start_ea=func.start_ea,
                    end_ea=func.end_ea,
                    entry_point=func_ea in entry_addresses,
                ).to_dict()
                # Use string representation of EA for JSON keys
                cfg["functions"][hex(func_ea)] = func_node_info
                if func_node_info["entry_point"]:
                    entry_found = True

                # Get flowchart for the function
                fc = db.functions.get_flowchart(func, flags=FlowChartFlags.NOEXT)
                if not fc:
                    # If no flowchart, still add the function start as a block 
                    # so it's not missing from the graph nodes.
                    cfg["functions"][hex(func_ea)]["blocks"].append({
                        "start": hex(func.start_ea),
                        "end": hex(func.end_ea),
                        "id": 0
                    })
                    continue
                
                for block in fc:
                    instrs = list(db.instructions.get_between(block.start_ea, block.end_ea))
                    cfg["functions"][hex(func_ea)]["blocks"].append({
                        "start": hex(block.start_ea),
                        "end": hex(block.end_ea),
                        "id": block.id,
                        "instructions": [
                            get_instr_info(db, insn)
                            for insn in instrs
                        ]
                    })
                    retrieved = db.functions.get_at(block.start_ea)
                    if not retrieved == func:
                        continue
                    #assert retrieved == func, f"Block {hex(block.start_ea)} belongs to {retrieved.name} @ {hex(retrieved.start_ea)} not {func_name} @ {hex(func_ea)}"
                    
                    # Determine if the exit from this block is conditional
                    num_succs = block.count_successors()
                    is_cond = (num_succs > 1)

                    for succ in block.get_successors():
                        cfg["edges"].append({
                            "src": hex(block.start_ea),
                            "dst": hex(succ.start_ea),
                            "type": "intra-function",
                            "conditional": bool(is_cond)
                        })

            print(f"Found {functions_found} functions.")
            if not entry_found:
                print("Warning: No entry points found among the functions. Check if the database is properly analyzed.")

            # Add inter-function edges (calls)
            print("Extracting inter-function calls...")

            # Also check xrefs to imported function addresses
            import_target_eas = list(import_addresses.keys())

            for func in db.functions:

                for xref in db.xrefs.to_ea(func.start_ea):
                    source = xref.from_ea
                    source_func = db.functions.get_at(source)
                    source_chunk = db.functions.get_chunk_at(source)
                    if not source_func or not source_chunk:
                        continue
                    # Find the specific block that contains the call for more accurate CFG
                    src_block_ea = source_chunk.start_ea
                    source_fc = db.functions.get_flowchart(source_func)
                    if source_fc:
                        for b in source_fc:
                            if b.start_ea <= source < b.end_ea:
                                src_block_ea = b.start_ea
                                break
                    if xref.is_call:
                        cfg["edges"].append({
                            "src": hex(src_block_ea),
                            "dst": hex(xref.to_ea),
                            "type": "inter-function",
                            "conditional": False
                        })
                    else:
                        if "main" in func.name.lower():
                            print(f"Found non-call link to main {xref.to_ea} from {source_func.name} @ {hex(source_func.start_ea)}")
                        cfg["edges"].append({
                            "src": hex(src_block_ea),
                            "dst": hex(xref.to_ea),
                            "type": "non-call",
                            "conditional": False
                        })
            # Add edges for calls to imported functions
            print("Extracting calls to imported functions...")
            for imp_ea in import_target_eas:
                for xref in db.xrefs.to_ea(imp_ea):
                    if not xref.is_call:
                        continue
                    source = xref.from_ea
                    source_func = db.functions.get_at(source)
                    source_chunk = db.functions.get_chunk_at(source)
                    if not source_func or not source_chunk:
                        continue
                    src_block_ea = source_chunk.start_ea
                    source_fc = db.functions.get_flowchart(source_func)
                    if source_fc:
                        for b in source_fc:
                            if b.start_ea <= source < b.end_ea:
                                src_block_ea = b.start_ea
                                break
                    cfg["edges"].append({
                        "src": hex(src_block_ea),
                        "dst": hex(imp_ea),
                        "type": "imported-function",
                        "conditional": False
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


def get_instr_info(db: Database, insn: insn_t) -> dict[str, str | None | bool | Any]:
    xrefs = [x for x in db.xrefs.from_ea(insn.ea)]
    call_target = None
    disas = db.instructions.get_disassembly(insn)
    if db.instructions.is_call_instruction(insn):
        if len(xrefs) == 2:
            call_target = xrefs[1].to_ea
        elif db.instructions.get_operand(insn, 0).type == idaapi.o_reg:
            call_target = "computed"
            print(f"Computed call target for {hex(insn.ea)}: {disas}")

    dic = {"addr": insn.ea,
            "disasm": disas,
            "call": db.instructions.is_call_instruction(insn),
            "call_target": call_target,
            }

    return dic


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python extract_cfg.py <path_to_idb_or_i64>")
        sys.exit(1)
    
    db_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    extract_cfg_from_db(db_path, out_path)
