#!/usr/bin/env python3
"""
Automated Test - Frida Game Hacking MCP

This is a fully automated test that:
1. Starts the test game in a subprocess
2. Runs MCP tools against it
3. Verifies the hacks work
4. Reports results

Run this to verify the MCP server works correctly.
"""

import os
import sys
import time
import subprocess
import ctypes

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frida_game_hacking_mcp.server import (
    list_processes, attach, detach, get_session_info,
    scan_value, scan_next, get_scan_results, clear_scan,
    write_memory, read_memory, list_modules, check_installation
)


class TestResult:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []
    
    def ok(self, name, msg=""):
        self.passed += 1
        self.results.append(("[PASS]", name, msg))
        print("[PASS] {} {}".format(name, msg))
    
    def fail(self, name, msg=""):
        self.failed += 1
        self.results.append(("[FAIL]", name, msg))
        print("[FAIL] {} {}".format(name, msg))
    
    def summary(self):
        print("\n" + "=" * 60)
        print("TEST SUMMARY: {} passed, {} failed".format(self.passed, self.failed))
        print("=" * 60)
        return self.failed == 0


def test_check_installation(results):
    """Test that Frida is properly installed."""
    result = check_installation()
    if result.get("installed") and result.get("working"):
        results.ok("check_installation", "Frida {} installed".format(result.get("frida_version")))
    else:
        results.fail("check_installation", str(result))


def test_list_processes(results):
    """Test process enumeration."""
    result = list_processes("")
    if result.get("count", 0) > 0:
        results.ok("list_processes", "Found {} processes".format(result["count"]))
    else:
        results.fail("list_processes", "No processes found")


def test_attach_detach(results, pid):
    """Test attach and detach."""
    # Test attach
    result = attach(pid)
    if result.get("success"):
        results.ok("attach", "Attached to PID {}".format(pid))
    else:
        results.fail("attach", str(result))
        return False
    
    # Test session info
    session = get_session_info()
    if session.get("attached"):
        results.ok("get_session_info", "Session active")
    else:
        results.fail("get_session_info", "Not attached")
    
    # Test detach
    result = detach()
    if result.get("success"):
        results.ok("detach", "Detached successfully")
    else:
        results.fail("detach", str(result))
    
    return True


def test_memory_scan(results, pid):
    """Test memory scanning workflow."""
    # Reattach
    attach(pid)
    
    # Test scan_value
    result = scan_value(100, "int32")
    found = result.get("found", 0)
    if found > 0:
        results.ok("scan_value", "Found {} addresses with value 100".format(found))
    else:
        results.fail("scan_value", "No addresses found")
        detach()
        return False
    
    # Test get_scan_results
    scan_results = get_scan_results(10)
    shown = scan_results.get("shown", 0)
    if shown > 0:
        results.ok("get_scan_results", "Retrieved {} results".format(shown))
        addresses = [r["address"] for r in scan_results.get("results", [])]
    else:
        results.fail("get_scan_results", "No results retrieved")
        detach()
        return False
    
    # Test scan_next (narrowing with same value for testing)
    result = scan_next(100)
    remaining = result.get("remaining", 0)
    if remaining > 0:
        results.ok("scan_next", "{} addresses remaining".format(remaining))
    else:
        results.fail("scan_next", "No addresses remaining")
    
    # Test clear_scan
    result = clear_scan()
    if result.get("success"):
        results.ok("clear_scan", "Scan cleared")
    else:
        results.fail("clear_scan", str(result))
    
    detach()
    return addresses if addresses else []


def test_memory_read_write(results, pid, addresses):
    """Test memory read/write operations."""
    if not addresses:
        results.fail("memory_read_write", "No addresses to test")
        return
    
    attach(pid)
    
    test_addr = addresses[0]
    
    # Test read_memory
    result = read_memory(test_addr, 4, "int32")
    if "value" in result:
        original_value = result["value"]
        results.ok("read_memory", "Read value {} from {}".format(original_value, test_addr))
    else:
        results.fail("read_memory", str(result))
        detach()
        return
    
    # Test write_memory
    result = write_memory(test_addr, "999", "int32")
    if result.get("success"):
        results.ok("write_memory", "Wrote 999 to {}".format(test_addr))
    else:
        results.fail("write_memory", str(result))
        detach()
        return
    
    # Verify write
    result = read_memory(test_addr, 4, "int32")
    if result.get("value") == 999:
        results.ok("verify_write", "Value confirmed as 999")
    else:
        results.fail("verify_write", "Value is {} not 999".format(result.get("value")))
    
    # Restore original value
    write_memory(test_addr, str(original_value), "int32")
    
    detach()


def test_modules(results, pid):
    """Test module enumeration."""
    attach(pid)
    
    result = list_modules()
    if result.get("count", 0) > 0:
        results.ok("list_modules", "Found {} modules".format(result["count"]))
    else:
        results.fail("list_modules", "No modules found")
    
    detach()


def main():
    print("=" * 60)
    print("  FRIDA GAME HACKING MCP - AUTOMATED TEST")
    print("=" * 60)
    
    results = TestResult()
    
    # Test 1: Check installation
    print("\n--- Testing Installation ---")
    test_check_installation(results)
    
    # Test 2: List processes
    print("\n--- Testing Process Enumeration ---")
    test_list_processes(results)
    
    # Find or start test target
    print("\n--- Finding Test Target ---")
    my_pid = os.getpid()
    
    # Look for existing hackme.py
    procs = list_processes("python")
    target_pid = None
    for p in procs.get("processes", []):
        if p["pid"] != my_pid:
            target_pid = p["pid"]
            break
    
    if not target_pid:
        # Start hackme.py as subprocess
        print("Starting test target (hackme.py)...")
        hackme_path = os.path.join(os.path.dirname(__file__), "hackme.py")
        
        if os.path.exists(hackme_path):
            proc = subprocess.Popen(
                [sys.executable, hackme_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            target_pid = proc.pid
            time.sleep(2)  # Wait for process to start
            print("Started hackme.py with PID {}".format(target_pid))
        else:
            # Use any other Python process
            print("hackme.py not found, using another Python process")
            target_pid = my_pid  # Will fail attach but tests the error handling
    
    if target_pid:
        print("Using target PID: {}".format(target_pid))
        
        # Test 3: Attach/Detach
        print("\n--- Testing Attach/Detach ---")
        if test_attach_detach(results, target_pid):
            
            # Test 4: Memory Scanning
            print("\n--- Testing Memory Scanning ---")
            addresses = test_memory_scan(results, target_pid)
            
            # Test 5: Memory Read/Write
            print("\n--- Testing Memory Read/Write ---")
            test_memory_read_write(results, target_pid, addresses)
            
            # Test 6: Module Enumeration
            print("\n--- Testing Module Enumeration ---")
            test_modules(results, target_pid)
    else:
        results.fail("find_target", "No target process found")
    
    # Summary
    success = results.summary()
    
    if success:
        print("\n[+] ALL TESTS PASSED!")
        print("    The MCP server is working correctly.")
    else:
        print("\n[-] SOME TESTS FAILED")
        print("    Check the output above for details.")
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

