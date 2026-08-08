# Ghidra Decompiled Exporter

Export every decompiled function from a Ghidra project into separate `.c` files — organized, numbered, and ready to open as a full folder in VSCode.

Works with **any binary**: iOS (Mach-O), Android (ELF/SO), Windows (PE), Linux (ELF), firmware, whatever Ghidra can analyze.

## Why

Ghidra's built-in decompiler is great, but you can only look at one function at a time. This script dumps everything out so you can:

- **Search across all functions at once** with `Ctrl+Shift+F` in VSCode
- **Jump between functions** with `Ctrl+P`
- **Read decompiled code** with proper syntax highlighting and your preferred editor setup
- **Track your RE progress** by annotating files, adding TODOs, or renaming things
- **Feed functions to LLMs** or other tools that work better with files on disk

## Each File Contains

```c
/*
 * ========================================================
 * #42    Function : -[MyViewController viewDidLoad]
 * Address  : 0x100003a00
 * Size     : 284 bytes
 * Signature: void viewDidLoad(MyViewController * this)
 * CallConv : __thiscall
 * Source   : IMPORTED
 * Called by: applicationDidFinishLaunching, sceneWillConnect
 * Calls    : UIView_init, NSLog, objc_msgSend
 * Binary   : MyApp
 * ========================================================
 */

void _MyViewController_viewDidLoad_(MyViewController *this) {
    // ... Ghidra's decompiled C code ...
}
```

## Usage

### 1. Copy the script

Put `ghidra_export_decompiled.py` in one of these locations:

- `~/ghidra_scripts/` (user scripts directory)
- `<ghidra_install>/Ghidra/Features/Base/ghidra_scripts/`
- Or any folder you've added in Ghidra's **Script Manager → Script Directories**

### 2. Run it

1. Open your binary in Ghidra
2. Let auto-analysis finish
3. **Script Manager** (`Window → Script Manager`) → find `ghidra_export_decompiled` → **Run**
4. Pick an output folder in the dialog
5. Wait for the export to finish

## Requirements

- **Ghidra** (tested on 12.x.x)
- **Python** (Jython) — built into Ghidra, no extra install needed
