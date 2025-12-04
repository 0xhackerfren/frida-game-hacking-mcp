#!/usr/bin/env python3
"""
Proof of Concept Demo - Frida Game Hacking MCP

This script demonstrates the MCP tools working against the hackme.py test game.
Run hackme.py first, then run this script to see the hacking in action.
"""

import os
import sys
import time

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frida_game_hacking_mcp.server import (
    list_processes, attach, detach, get_session_info,
    scan_value, scan_next, get_scan_results, clear_scan,
    write_memory, read_memory, list_modules, list_memory_regions
)


def main():
    print("=" * 70)
    print("  FRIDA GAME HACKING MCP - PROOF OF CONCEPT DEMONSTRATION")
    print("=" * 70)
    
    my_pid = os.getpid()
    
    # Step 1: Find target process
    print("\n[STEP 1] Finding python processes...")
    procs = list_processes("python")
    print("Found {} python processes:".format(procs.get("count", 0)))
    
    target_pid = None
    for p in procs.get("processes", []):
        status = "(THIS SCRIPT)" if p["pid"] == my_pid else ""
        print("  PID: {} - {} {}".format(p["pid"], p["name"], status))
        if p["pid"] != my_pid and target_pid is None:
            target_pid = p["pid"]
    
    if not target_pid:
        print("\n[!] ERROR: No target process found!")
        print("    Please run hackme.py first, then run this script.")
        return False
    
    # Step 2: Attach to target
    print("\n[STEP 2] Attaching to target PID {}...".format(target_pid))
    result = attach(target_pid)
    print("Result: {}".format(result))
    
    if not result.get("success"):
        print("[!] Failed to attach!")
        return False
    
    # Step 3: Show session info
    print("\n[STEP 3] Session info:")
    session = get_session_info()
    print("  Attached: {}".format(session.get("attached")))
    print("  PID: {}".format(session.get("pid")))
    print("  Process: {}".format(session.get("process_name")))
    
    # Step 4: List modules
    print("\n[STEP 4] Listing loaded modules...")
    mods = list_modules()
    print("Found {} modules. First 5:".format(mods.get("count", 0)))
    for m in mods.get("modules", [])[:5]:
        print("  {} @ {} ({} bytes)".format(m["name"], m["base"], m["size"]))
    
    # Step 5: Scan for health value (100)
    print("\n[STEP 5] Scanning for health value (100, int32)...")
    print("         This searches all read-write memory regions...")
    scan_result = scan_value(100, "int32")
    found = scan_result.get("found", 0)
    print("Result: Found {} addresses containing value 100".format(found))
    
    if found == 0:
        print("[!] No addresses found. The game may have different health value.")
        print("    Try: scan_value(<current_health>, 'int32')")
        detach()
        return False
    
    # Step 6: Get scan results
    print("\n[STEP 6] Getting scan results (top 10)...")
    results = get_scan_results(10)
    print("Showing {} of {} results:".format(
        results.get("shown", 0), 
        results.get("total", 0)
    ))
    
    addresses = []
    for r in results.get("results", []):
        addresses.append(r["address"])
        print("  {} = {} (hex: {})".format(r["address"], r["value"], r["hex"]))
    
    if not addresses:
        print("[!] No results to modify")
        detach()
        return False
    
    # Step 7: Demonstrate narrowing (scan_next)
    print("\n[STEP 7] Demonstrating scan narrowing...")
    print("         In real usage, you would change the value in-game first.")
    print("         For now, searching for same value to verify stability...")
    next_result = scan_next(100)
    print("Result: {} addresses still have value 100".format(
        next_result.get("remaining", 0)
    ))
    
    # Step 8: Write to first address
    target_addr = addresses[0]
    print("\n[STEP 8] Writing value 999 to address {}...".format(target_addr))
    write_result = write_memory(target_addr, "999", "int32")
    print("Result: {}".format(write_result))
    
    # Step 9: Verify the write
    print("\n[STEP 9] Verifying write by reading back...")
    read_result = read_memory(target_addr, 4, "int32")
    print("Result: {}".format(read_result))
    
    new_value = read_result.get("value", 0)
    if new_value == 999:
        print("\n[+] SUCCESS! Value changed from 100 to 999!")
        print("    Check the hackme.py window - if this was the health address,")
        print("    the health display should now show 999!")
    else:
        print("\n[?] Value is now {}. May not be the exact address.".format(new_value))
        print("    In practice, you narrow down using scan_next after")
        print("    changing values in-game.")
    
    # Step 10: Try writing to more addresses
    print("\n[STEP 10] Writing 999 to next 4 addresses to increase chances...")
    for addr in addresses[1:5]:
        wr = write_memory(addr, "999", "int32")
        status = "OK" if wr.get("success") else "FAIL"
        print("  {} -> {} ({})".format(addr, 999, status))
    
    # Step 11: Clear scan
    print("\n[STEP 11] Clearing scan state...")
    print(clear_scan())
    
    # Step 12: Detach
    print("\n[STEP 12] Detaching from process...")
    print(detach())
    
    print("\n" + "=" * 70)
    print("  PROOF OF CONCEPT COMPLETE!")
    print("=" * 70)
    print("\n  What we demonstrated:")
    print("  [+] list_processes() - Found target process")
    print("  [+] attach() - Connected to process with Frida")
    print("  [+] list_modules() - Enumerated loaded DLLs")
    print("  [+] scan_value() - Found addresses containing target value")
    print("  [+] scan_next() - Narrowed results (would narrow more with value changes)")
    print("  [+] get_scan_results() - Retrieved matching addresses")
    print("  [+] write_memory() - Modified values in target process memory")
    print("  [+] read_memory() - Verified our changes")
    print("  [+] detach() - Cleanly disconnected")
    print("\n  Check the hackme.py window to see if any values changed!")
    print("  If health shows 999, we found and modified the right address!")
    print("=" * 70)
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

