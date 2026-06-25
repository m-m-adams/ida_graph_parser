import json
import argparse
import requests
import ida_funcs
import ida_kernwin
import ida_name
import idaapi


def sanitize_func_name(name):
    """Sanitize a function name for use in IDA.
    
    Removes/replaces invalid characters, handles spaces and special chars.
    Valid IDA function name chars: alphanumeric, underscore, and some special chars.
    """
    # Replace spaces and dashes with underscores
    name = name.replace(' ', '_').replace('-', '_')
    
    # Keep only alphanumeric, underscore, and a few safe special chars
    sanitized = ''
    for char in name:
        if char.isalnum() or char == '_' or char == ':' or char == '?':
            sanitized += char
        else:
            # Replace other special chars with underscore
            if sanitized and sanitized[-1] != '_':
                sanitized += '_'
    
    # Remove trailing underscores
    sanitized = sanitized.rstrip('_')
    
    # Ensure name doesn't start with a digit (invalid in IDA)
    if sanitized and sanitized[0].isdigit():
        sanitized = '_' + sanitized
    
    return sanitized if sanitized else 'func'


def ask_for_json_file(description="JSON file with function summaries"):
    """Prompt user to select a JSON file using IDA's native file dialog."""
    file_path = ida_kernwin.ask_file(False, "*.json", f"Select {description}")
    return file_path


def ask_for_jsonl_file(description="JSONL file with one-line descriptions and function names"):
    file_path = ida_kernwin.ask_file(False, "*.jsonl", f"Select {description}")
    return file_path


def wrap_text(text, width=80):
    """Wrap text to width with newlines, preserving existing paragraph breaks"""
    paragraphs = text.split('\n')
    wrapped_paragraphs = []
    
    for paragraph in paragraphs:
        words = paragraph.split()
        if not words:
            wrapped_paragraphs.append('')
            continue
        
        lines = []
        current_line = []
        
        for word in words:
            if sum(len(w) for w in current_line) + len(current_line) + len(word) <= width:
                current_line.append(word)
            else:
                if current_line:
                    lines.append(" ".join(current_line))
                current_line = [word]
        
        if current_line:
            lines.append(" ".join(current_line))
        
        wrapped_paragraphs.append("\n".join(lines))
    
    return "\n".join(wrapped_paragraphs)


def annotate_functions(json_path=None, repeatable=False, save=False):
    """Annotate the open database with summaries from a JSON file.

    Call from the IDA Python console, e.g.:
        annotate_functions()  # will prompt for file
        annotate_functions("path_to_summaries.json")

    Args:
        json_path: Path to summaries JSON file (if None, prompts user)
        repeatable: True => show at call sites; False => only at function definition
        save: Save database after annotation

    """
    if json_path is None:
        json_path = ask_for_json_file("function summaries JSON file")
        if not json_path:
            print("[annotate_functions] cancelled")
            return
    
    with open(json_path) as f:
        data = json.load(f)

    if isinstance(data, dict):
        records = data.items()
    else:
        records = ((e["name"], e.get("summary", e.get("comment", "")))
                   for e in data)

    applied = skipped = missing = 0
    
    for name, summary in records:
        if not summary:
            skipped += 1
            continue

        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            print(f"[summaries] name not found: {name}")
            missing += 1
            continue

        func = ida_funcs.get_func(ea)
        if func is None:
            print(f"[summaries] not a function: {name} @ {ea:#x}")
            missing += 1
            continue

        # Set full summary at function definition
        wrapped_summary = "\n" + wrap_text(summary)
        if ida_funcs.set_func_cmt(func, wrapped_summary, False):
            applied += 1
        else:
            skipped += 1

    print(f"[summaries] applied={applied} skipped={skipped} missing={missing}")

    if not ida_kernwin.cvar.batch:
        ida_kernwin.refresh_idaview_anyway()

    if save:
        idc_save = idaapi.save_database
        idc_save("")   # "" => save to the current database path
        print("[summaries] database saved")


def update_func_names(jsonl_path=None, save=False):
    """Update function names in the open database from a JSONL file.
    
    Takes a JSONL file with objects containing "original_name" (current name) and "title" (new name).
    
    Args:
        jsonl_path: Path to JSONL file (if None, prompts user)
        save: Save database after annotation
    
    Example JSONL entry:
        {"original_name": "sub_140002C1C", "title": "Conditional Memory Alignment Helper", ...}
    """
    if jsonl_path is None:
        jsonl_path = ask_for_jsonl_file("function titles JSONL file")
        if not jsonl_path:
            print("[update_func_names] cancelled")
            return
    
    applied = skipped = missing = 0
    
    with open(jsonl_path) as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            original_name = entry.get("original_name")
            title = entry.get("title")
            
            if not original_name or not title:
                skipped += 1
                continue
            
            ea = ida_name.get_name_ea(idaapi.BADADDR, original_name)
            if ea == idaapi.BADADDR:
                print(f"[update_func_names] name not found: {original_name}")
                missing += 1
                continue
            
            sanitized_title = sanitize_func_name(title)
            if ida_name.set_name(ea, sanitized_title):
                applied += 1
            else:
                skipped += 1
    
    print(f"[update_func_names] applied={applied} skipped={skipped} missing={missing}")
    
    if not ida_kernwin.cvar.batch:
        ida_kernwin.refresh_idaview_anyway()
    
    if save:
        idaapi.save_database("")
        print("[update_func_names] database saved")


def annotate_calls(jsonl_path=None, repeatable=False, save=False):
    """Annotate call sites in the open database from a JSONL file.
    
    Updates comments at call instructions (xrefs) to functions, not at function definitions.
    Only annotates the places where the function is called, not the definition itself.
    
    Args:
        jsonl_path: Path to JSONL file (if None, prompts user)
        repeatable: True => repeatable comment; False => non-repeatable comment
        save: Save database after annotation
    
    Example JSONL entry:
        {"original_name": "memcpy", "title": "...", "one_line_summary": "Indirect call to system memcpy via imported function pointer"}
    """
    if jsonl_path is None:
        jsonl_path = ask_for_jsonl_file("function titles JSONL file")
        if not jsonl_path:
            print("[annotate_calls] cancelled")
            return
    
    applied = skipped = missing = 0
    
    with open(jsonl_path) as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            original_name = entry.get("original_name")
            summary = entry.get("one_line_summary", "")
            
            if not original_name or not summary:
                skipped += 1
                continue
            
            ea = ida_name.get_name_ea(idaapi.BADADDR, original_name)
            if ea == idaapi.BADADDR:
                print(f"[annotate_calls] name not found: {original_name}")
                missing += 1
                continue
            
            func = ida_funcs.get_func(ea)
            if func is None:
                print(f"[annotate_calls] not a function: {original_name} @ {ea:#x}")
                missing += 1
                continue
            
            wrapped_summary = "\n" + wrap_text(summary)
            
            # Iterate through all code xrefs (call sites) to this function
            xref = idaapi.get_first_cref_to(ea)
            while xref != idaapi.BADADDR:
                # Check if this is a call instruction
                if idaapi.is_call_insn(xref):
                    if idaapi.set_cmt(xref, wrapped_summary, repeatable):
                        applied += 1
                    else:
                        skipped += 1
                xref = idaapi.get_next_cref_to(ea, xref)
    
    print(f"[annotate_calls] applied={applied} skipped={skipped} missing={missing}")
    
    if not ida_kernwin.cvar.batch:
        ida_kernwin.refresh_idaview_anyway()
    
    if save:
        idaapi.save_database("")
        print("[annotate_calls] database saved")


def annotate_all(json_path=None, jsonl_path=None, repeatable=False, save=False):
    """Run all three annotation functions in sequence.
    
    Performs a complete annotation pass:
    1. Annotates function definitions with summaries from JSON
    2. Annotates call sites with one-line summaries from JSONL
    3. Updates function names from JSONL (done last so lookups still work)
    """
    if json_path is None:
        json_path = ask_for_json_file("function summaries JSON file")
        if not json_path:
            print("[annotate_all] cancelled")
            return
    
    if jsonl_path is None:
        jsonl_path = ask_for_jsonl_file("function titles JSONL file")
        if not jsonl_path:
            print("[annotate_all] cancelled")
            return
    
    print("[annotate_all] starting annotation pipeline...")
    
    print("\n[annotate_all] Step 1: Annotating function definitions...")
    annotate_functions(json_path, repeatable=repeatable, save=False)
    
    print("\n[annotate_all] Step 2: Annotating call sites...")
    annotate_calls(jsonl_path, repeatable=repeatable, save=False)
    
    print("\n[annotate_all] Step 3: Updating function names...")
    update_func_names(jsonl_path, save=False)
    
    if not ida_kernwin.cvar.batch:
        ida_kernwin.refresh_idaview_anyway()
    
    if save:
        idaapi.save_database("")
        print("[annotate_all] database saved")
