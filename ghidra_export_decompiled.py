from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Function
import os
import re
import time
import json


# =============================================================================
# Configuration - Adjust these before running
# =============================================================================

DECOMPILE_TIMEOUT = 30        # seconds per function
ORGANIZE_BY_CATEGORY = True   # group files into subfolders by type
INCLUDE_THUNKS = True         # export thunk/stub functions?
INCLUDE_EXTERNAL = True       # export external (imported) functions?
INCLUDE_AUTO_NAMED = True     # export FUN_xxxxx auto-named functions?
MIN_FUNCTION_SIZE = 0         # skip functions smaller than N bytes (0 = all)
GENERATE_INDEX_MD = True      # create INDEX.md with links to all functions
GENERATE_VSCODE_WS = True     # create .code-workspace file


# =============================================================================
# Helpers
# =============================================================================

def sanitize_filename(name, max_len=180):
    """Convert a function name to a filesystem-safe filename."""
    s = name
    s = s.replace('-[', '').replace('+[', '').replace(']', '')
    s = re.sub(r'[<>:"/\\|?*\x00-\x1f()@#$%^&{}~`\']', '_', s)
    s = s.replace(' ', '_').replace(',', '_').replace(';', '_')
    s = s.replace('::', '__').replace(':', '_').replace('.', '_')
    s = re.sub(r'_+', '_', s)
    s = s.strip('_. ')
    if len(s) > max_len:
        s = s[:max_len]
    return s if s else 'unnamed'


def get_category(func):
    """Classify a function into a category/subfolder."""
    name = func.getName()
    ns = func.getParentNamespace()

    if ns and ns.getName() != "Global":
        ns_name = ns.getName()
        if ns_name and not ns_name.startswith("FUN_"):
            return sanitize_filename(ns_name, 80)

    if name.startswith("-[") or name.startswith("+[") or name.startswith("_objc_"):
        return "objc_runtime"
    if "_swift_" in name.lower() or name.startswith("$s") or name.startswith("_$s"):
        return "swift"
    if name.startswith("Java_"):
        return "jni"
    if name.startswith("JNI_"):
        return "jni_internal"
    if func.isThunk():
        return "_thunks"
    if name.startswith("FUN_") or name.startswith("thunk_FUN_"):
        return "_auto_named"
    if name.startswith("sub_"):
        return "_auto_named"
    if name.startswith("__"):
        return "_compiler_generated"
    if name.startswith("_"):
        return "_crt_system"

    return "functions"


def build_header_comment(func, program_name, seq):
    """Build a C comment block with function metadata."""
    lines = []
    lines.append("/*")
    lines.append(" * " + "=" * 56)
    lines.append(" * #{:<5d} Function : {}".format(seq, func.getName()))
    lines.append(" * Address  : {}".format(func.getEntryPoint()))
    lines.append(" * Size     : {} bytes".format(func.getBody().getNumAddresses()))

    sig = func.getSignature()
    if sig:
        lines.append(" * Signature: {}".format(sig.getPrototypeString()))

    cc = func.getCallingConventionName()
    if cc:
        lines.append(" * CallConv : {}".format(cc))

    src = func.getSymbol().getSource()
    lines.append(" * Source   : {}".format(src))

    if func.isThunk():
        thunked = func.getThunkedFunction(False)
        if thunked:
            lines.append(" * Thunk -> : {}".format(thunked.getName()))

    comment = func.getComment()
    if comment:
        for cl in comment.split('\n'):
            lines.append(" * Comment  : {}".format(cl))

    try:
        callers = list(func.getCallingFunctions(None))
        if callers:
            caller_names = [c.getName() for c in callers[:5]]
            lines.append(" * Called by: {}".format(", ".join(caller_names)))
            if len(callers) > 5:
                lines.append(" *            ... and {} more".format(len(callers) - 5))
    except:
        pass

    try:
        callees = list(func.getCalledFunctions(None))
        if callees:
            callee_names = [c.getName() for c in callees[:5]]
            lines.append(" * Calls    : {}".format(", ".join(callee_names)))
            if len(callees) > 5:
                lines.append(" *            ... and {} more".format(len(callees) - 5))
    except:
        pass

    lines.append(" * Binary   : {}".format(program_name))
    lines.append(" * " + "=" * 56)
    lines.append(" */")
    return "\n".join(lines)


def should_skip(func):
    """Decide whether to skip exporting this function."""
    name = func.getName()

    if not INCLUDE_THUNKS and func.isThunk():
        return True
    if not INCLUDE_EXTERNAL and func.isExternal():
        return True
    if not INCLUDE_AUTO_NAMED:
        if name.startswith("FUN_") or name.startswith("sub_"):
            return True
    if MIN_FUNCTION_SIZE > 0:
        if func.getBody().getNumAddresses() < MIN_FUNCTION_SIZE:
            return True

    return False


# =============================================================================
# Main Export Logic
# =============================================================================

def run_export():
    program = currentProgram
    if program is None:
        print("[!] No program is open in Ghidra!")
        return

    program_name = program.getName()
    lang = program.getLanguage().getLanguageID().toString()
    compiler_spec = program.getCompilerSpec().getCompilerSpecID().toString()
    exe_format = program.getExecutableFormat()

    print("")
    print("=" * 65)
    print("  GHIDRA DECOMPILED CODE EXPORTER")
    print("=" * 65)
    print("  Program  : {}".format(program_name))
    print("  Language : {}".format(lang))
    print("  Compiler : {}".format(compiler_spec))
    print("  Format   : {}".format(exe_format))
    print("=" * 65)
    print("")

    # --- Pick output directory ---
    from javax.swing import JFileChooser, JOptionPane
    chooser = JFileChooser()
    chooser.setDialogTitle("Select Output Directory for Decompiled Code")
    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)

    if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
        print("[*] Cancelled.")
        return

    base_dir = os.path.join(
        chooser.getSelectedFile().getAbsolutePath(),
        sanitize_filename(program_name, 100) + "_decompiled"
    )

    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    print("[+] Output directory: {}".format(base_dir))
    print("")

    # --- Initialize the decompiler ---
    decomp = DecompInterface()
    opts = DecompileOptions()
    opts.setEliminateUnreachable(True)
    decomp.setOptions(opts)

    if not decomp.openProgram(program):
        print("[!] Failed to initialize the decompiler!")
        return

    monitor = ConsoleTaskMonitor()
    fm = program.getFunctionManager()
    total = fm.getFunctionCount()

    print("[*] Total functions in binary: {}".format(total))
    print("[*] Starting decompilation & export...")
    print("-" * 65)

    # --- Tracking ---
    exported = 0
    failed = 0
    skipped = 0
    seq = 0             # sequential counter — preserves Ghidra address order
    index_data = []
    categories_count = {}
    # Per-category sequential counter so files sort correctly inside each folder
    cat_seq = {}

    start = time.time()
    count = 0

    # --- Iterate functions in address order (Ghidra default) ---
    functions = fm.getFunctions(True)  # True = forward / ascending address

    for func in functions:
        count += 1

        if monitor.isCancelled():
            print("\n[!] Export cancelled by user!")
            break

        name = func.getName()
        addr = func.getEntryPoint().toString()

        # Progress every 200 functions
        if count % 200 == 0 or count == total:
            elapsed = time.time() - start
            rate = count / elapsed if elapsed > 0 else 0
            pct = (count * 100.0) / total if total > 0 else 0
            display_name = name[:42] + "..." if len(name) > 42 else name
            print("  [{:>6}/{:<6}] {:5.1f}%  ({:.0f}/s)  {}".format(
                count, total, pct, rate, display_name))

        # Filter
        if should_skip(func):
            skipped += 1
            continue

        # Decompile
        try:
            result = decomp.decompileFunction(func, DECOMPILE_TIMEOUT, monitor)

            if result is None or not result.decompileCompleted():
                failed += 1
                err = result.getErrorMessage() if result else "null"
                index_data.append({
                    'name': name, 'addr': addr, 'seq': seq,
                    'status': 'FAIL', 'error': err[:80],
                    'category': '', 'file': '', 'size': 0
                })
                continue

            decomp_func = result.getDecompiledFunction()
            if decomp_func is None:
                failed += 1
                continue

            c_code = decomp_func.getC()
            if c_code is None or len(c_code.strip()) == 0:
                skipped += 1
                continue

            # ---- Exported ----
            seq += 1

            # Category subfolder
            cat = get_category(func) if ORGANIZE_BY_CATEGORY else "all"
            cat_dir = os.path.join(base_dir, cat)
            if not os.path.exists(cat_dir):
                os.makedirs(cat_dir)
            categories_count[cat] = categories_count.get(cat, 0) + 1

            # Per-category sequence number
            cat_seq[cat] = cat_seq.get(cat, 0) + 1
            local_seq = cat_seq[cat]

            # Filename: 00001_0x00401000__my_function.c
            # The leading number keeps VSCode explorer in Ghidra order
            safe = sanitize_filename(name)
            filename = "{:05d}_{}__{}.c".format(local_seq, addr, safe)
            filepath = os.path.join(cat_dir, filename)

            # Build file
            header = build_header_comment(func, program_name, seq)
            content = header + "\n\n" + c_code

            with open(filepath, 'w') as f:
                f.write(content)

            exported += 1
            rel_path = os.path.join(cat, filename)
            func_size = func.getBody().getNumAddresses()

            index_data.append({
                'name': name, 'addr': addr, 'seq': seq,
                'status': 'OK', 'error': '',
                'category': cat, 'file': rel_path,
                'size': func_size
            })

        except Exception as e:
            failed += 1
            print("  [!] Error on {} @ {}: {}".format(name, addr, str(e)))

    decomp.dispose()
    elapsed = time.time() - start

    # =================================================================
    # INDEX.md
    # =================================================================
    if GENERATE_INDEX_MD and index_data:
        index_path = os.path.join(base_dir, "INDEX.md")
        with open(index_path, 'w') as f:
            f.write("# {} &mdash; Decompiled Functions\n\n".format(program_name))
            f.write("## Binary Info\n\n")
            f.write("| Property | Value |\n")
            f.write("|----------|-------|\n")
            f.write("| Binary | `{}` |\n".format(program_name))
            f.write("| Language | {} |\n".format(lang))
            f.write("| Compiler | {} |\n".format(compiler_spec))
            f.write("| Format | {} |\n".format(exe_format))
            f.write("| Exported | {} functions |\n".format(exported))
            f.write("| Failed | {} |\n".format(failed))
            f.write("| Skipped | {} |\n".format(skipped))
            f.write("| Date | {} |\n\n".format(time.strftime("%Y-%m-%d %H:%M:%S")))

            f.write("## Categories\n\n")
            f.write("| Category | Count |\n")
            f.write("|----------|-------|\n")
            for cat in sorted(categories_count.keys()):
                f.write("| [`{}`](./{}) | {} |\n".format(
                    cat, cat, categories_count[cat]))
            f.write("\n")

            # Functions listed in Ghidra order (by seq)
            f.write("## Functions (Ghidra order)\n\n")
            f.write("| # | Address | Name | Category | Size |\n")
            f.write("|---|---------|------|----------|------|\n")

            for entry in sorted(index_data, key=lambda x: x['seq']):
                if entry['status'] == 'OK':
                    f.write("| {} | `{}` | [{}](./{}) | {} | {} B |\n".format(
                        entry['seq'],
                        entry['addr'],
                        entry['name'][:60],
                        entry['file'],
                        entry['category'],
                        entry.get('size', '?')
                    ))
                else:
                    f.write("| - | `{}` | {} | - | FAIL |\n".format(
                        entry['addr'], entry['name'][:60]
                    ))

        print("[+] Index: {}".format(index_path))

    # =================================================================
    # VSCode workspace
    # =================================================================
    if GENERATE_VSCODE_WS:
        ws_name = sanitize_filename(program_name, 80)
        ws_path = os.path.join(base_dir, "{}.code-workspace".format(ws_name))

        ws = {
            "folders": [{"path": "."}],
            "settings": {
                "files.associations": {"*.c": "c"},
                "editor.readOnly": True,
                "search.useIgnoreFiles": False,
                "editor.minimap.enabled": True,
                "editor.wordWrap": "on",
                "breadcrumbs.enabled": True,
                "explorer.sortOrder": "default",
                "C_Cpp.errorSquiggles": "disabled"
            },
            "extensions": {
                "recommendations": [
                    "ms-vscode.cpptools",
                    "streetsidesoftware.code-spell-checker"
                ]
            }
        }

        with open(ws_path, 'w') as f:
            json.dump(ws, f, indent=2)

        print("[+] VSCode workspace: {}".format(ws_path))

    # =================================================================
    # FUNCTIONS.txt
    # =================================================================
    tags_path = os.path.join(base_dir, "FUNCTIONS.txt")
    with open(tags_path, 'w') as f:
        f.write("# Quick Search: Ctrl+F to find by name or address\n")
        f.write("# Then Ctrl+P in VSCode -> type the filename to jump\n")
        f.write("#\n")
        f.write("# {:<5s}  {:<18s}  {:<55s}  {}\n".format(
            "#", "ADDRESS", "FUNCTION", "FILE"))
        f.write("# " + "-" * 105 + "\n")
        for entry in sorted(index_data, key=lambda x: x['seq']):
            if entry['status'] == 'OK':
                f.write("  {:<5d}  {:<18s}  {:<55s}  {}\n".format(
                    entry['seq'],
                    entry['addr'],
                    entry['name'][:55],
                    entry['file']
                ))
    print("[+] Search index: {}".format(tags_path))

    # =================================================================
    # Summary
    # =================================================================
    print("")
    print("=" * 65)
    print("  EXPORT COMPLETE")
    print("=" * 65)
    print("  Exported  : {:>6} functions".format(exported))
    print("  Failed    : {:>6} functions".format(failed))
    print("  Skipped   : {:>6} functions".format(skipped))
    print("  Time      : {:>6.1f} seconds".format(elapsed))
    if elapsed > 0 and count > 0:
        print("  Speed     : {:>6.0f} functions/sec".format(count / elapsed))
    print("")
    print("  Categories:")
    for cat in sorted(categories_count.keys()):
        print("    {:<35s} : {:>5} files".format(cat, categories_count[cat]))
    print("")
    print("  Output: {}".format(base_dir))
    print("")
    print("  Open in VSCode:")
    print("    code \"{}\"".format(base_dir))
    print("=" * 65)

    try:
        from javax.swing import JOptionPane
        msg = (
            "Export complete!\n\n"
            "Exported: {} functions\n"
            "Failed: {} | Skipped: {}\n"
            "Time: {:.1f}s\n\n"
            "Output:\n{}"
        ).format(exported, failed, skipped, elapsed, base_dir)

        JOptionPane.showMessageDialog(
            None, msg,
            "Decompiled Code Exporter",
            JOptionPane.INFORMATION_MESSAGE
        )
    except:
        pass


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    run_export()
else:
    run_export()
