#!/usr/bin/env python3
"""
Full Interactive Demo - Frida Game Hacking MCP

This demonstrates the complete Cheat Engine-style workflow:
1. Attach to target
2. Scan for initial value
3. Change value in game
4. Narrow with scan_next
5. Repeat until found
6. Modify the value

Run hackme.py first in a separate window!
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frida_game_hacking_mcp.server import (
    list_processes, attach, detach, get_session_info,
    scan_value, scan_next, scan_changed, get_scan_results, clear_scan,
    write_memory, read_memory, list_modules
)


def print_header(text):
    print("\n" + "=" * 70)
    print("  " + text)
    print("=" * 70)


def print_step(num, text):
    print("\n[STEP {}] {}".format(num, text))


def wait_for_enter(msg="Press Enter to continue..."):
    input("\n>>> " + msg)


def find_and_attach():
    """Find the hackme.py process and attach."""
    print_step(1, "Finding target process")
    
    my_pid = os.getpid()
    procs = list_processes("python")
    
    print("Python processes found:")
    target_pid = None
    for p in procs.get("processes", []):
        marker = " <- THIS SCRIPT" if p["pid"] == my_pid else ""
        print("  PID {} - {}{}".format(p["pid"], p["name"], marker))
        if p["pid"] != my_pid and target_pid is None:
            target_pid = p["pid"]
    
    if not target_pid:
        print("\n[ERROR] No target found! Run hackme.py first.")
        return None
    
    print_step(2, "Attaching to PID {}".format(target_pid))
    result = attach(target_pid)
    
    if result.get("success"):
        print("[+] Successfully attached!")
        return target_pid
    else:
        print("[-] Failed: {}".format(result.get("error")))
        return None


def demo_value_scan_workflow():
    """Demonstrate the Cheat Engine value scanning workflow."""
    
    print_header("CHEAT ENGINE WORKFLOW DEMO")
    print("""
    This demo shows how to find a specific value in memory:
    
    1. Scan for the current value
    2. Change the value in the game (press D in hackme.py)
    3. Scan for the new value to narrow results
    4. Repeat until only a few addresses remain
    5. Write new value to found addresses
    """)
    
    wait_for_enter("Make sure hackme.py is running, then press Enter")
    
    # Attach
    pid = find_and_attach()
    if not pid:
        return
    
    # Initial scan
    print_step(3, "Initial scan for health value")
    print("In hackme.py, health starts at 100.")
    print("We'll scan for all addresses containing 100...")
    
    result = scan_value(100, "int32")
    initial_count = result.get("found", 0)
    print("\n[+] Found {} addresses with value 100".format(initial_count))
    
    if initial_count == 0:
        print("[-] No addresses found. Check if hackme.py is running.")
        detach()
        return
    
    # Show some results
    results = get_scan_results(5)
    print("\nSample addresses:")
    for r in results.get("results", [])[:5]:
        print("  {} = {}".format(r["address"], r["value"]))
    
    # Narrowing loop
    print_step(4, "Narrowing down the results")
    print("""
    Now we need to narrow down {} addresses to find the real health.
    
    In hackme.py window:
    - Press 'D' to take 10 damage (health becomes 90)
    - Then come back here and enter the new value
    """.format(initial_count))
    
    narrowing_round = 1
    current_count = initial_count
    
    while current_count > 10:
        print("\n--- Narrowing Round {} ---".format(narrowing_round))
        print("Current matching addresses: {}".format(current_count))
        
        try:
            new_value = input("Enter the NEW health value from hackme.py (or 'q' to skip): ").strip()
            
            if new_value.lower() == 'q':
                print("Skipping narrowing...")
                break
            
            new_value = int(new_value)
            result = scan_next(new_value)
            current_count = result.get("remaining", 0)
            
            print("[+] Narrowed to {} addresses".format(current_count))
            
            if current_count <= 10:
                print("\n[+] Great! We have {} candidates.".format(current_count))
                break
            else:
                print("\nChange the value again in hackme.py (D for damage, H for heal)")
                
        except ValueError:
            print("Please enter a number")
        except KeyboardInterrupt:
            break
            
        narrowing_round += 1
        if narrowing_round > 10:
            print("Max rounds reached, proceeding with current results...")
            break
    
    # Get final results
    print_step(5, "Getting final candidate addresses")
    final_results = get_scan_results(20)
    addresses = [r["address"] for r in final_results.get("results", [])]
    
    print("Found {} candidate addresses:".format(len(addresses)))
    for r in final_results.get("results", [])[:10]:
        print("  {} = {}".format(r["address"], r["value"]))
    
    # Write new value
    print_step(6, "Modifying memory to set health to 999")
    
    if not addresses:
        print("[-] No addresses to modify")
        detach()
        return
    
    print("Writing 999 to all {} candidate addresses...".format(len(addresses)))
    success_count = 0
    
    for addr in addresses[:20]:  # Limit to first 20
        result = write_memory(addr, "999", "int32")
        if result.get("success"):
            success_count += 1
    
    print("[+] Successfully wrote to {} addresses".format(success_count))
    
    # Verify
    print_step(7, "Verification")
    print("Reading back first address to verify...")
    
    if addresses:
        read_result = read_memory(addresses[0], 4, "int32")
        print("Value at {}: {}".format(addresses[0], read_result.get("value")))
    
    print("""
    CHECK HACKME.PY WINDOW NOW!
    
    If the health value shows 999, we successfully hacked it!
    
    If not all values changed, one of the addresses we wrote to
    was the correct one - the Cheat Engine workflow is to test
    each address individually until finding the right one.
    """)
    
    # Cleanup
    print_step(8, "Cleaning up")
    clear_scan()
    detach()
    print("[+] Done!")


def demo_direct_hack():
    """Quick demo - just scan and write without narrowing."""
    
    print_header("QUICK HACK DEMO")
    print("This attempts to hack all values at once by writing to all matches.")
    
    pid = find_and_attach()
    if not pid:
        return
    
    values_to_hack = [
        (100, "health (if at 100)"),
        (50, "gold (if at 50)"),
        (30, "ammo (if at 30)"),
    ]
    
    for value, name in values_to_hack:
        print("\n--- Hacking {} ---".format(name))
        
        scan_result = scan_value(value, "int32")
        found = scan_result.get("found", 0)
        print("Found {} addresses with value {}".format(found, value))
        
        if found > 0 and found < 50000:
            results = get_scan_results(50)
            addresses = [r["address"] for r in results.get("results", [])]
            
            print("Writing 999 to first {} addresses...".format(min(len(addresses), 10)))
            for addr in addresses[:10]:
                write_memory(addr, "999", "int32")
            
            print("[+] Done!")
        
        clear_scan()
    
    detach()
    print("\nCheck hackme.py - values might have changed to 999!")


def main():
    print_header("FRIDA GAME HACKING MCP - INTERACTIVE DEMO")
    print("""
    This demo proves the MCP tools work by hacking a test game.
    
    Prerequisites:
    1. Run hackme.py in another terminal window
    2. Make sure you can see its output
    
    Options:
    1. Full Cheat Engine workflow (scan, narrow, modify)
    2. Quick hack (scan and modify directly)
    3. Exit
    """)
    
    while True:
        choice = input("\nEnter choice (1/2/3): ").strip()
        
        if choice == "1":
            demo_value_scan_workflow()
        elif choice == "2":
            demo_direct_hack()
        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()

