#!/usr/bin/env python3
"""
HackMe - Simple Target for Frida Game Hacking MCP Demo

This is a minimal target process designed to demonstrate the MCP tools.
It displays values that can be found and modified using memory scanning.

Run this, then use the MCP tools to:
1. attach() to this process
2. scan_value() to find the health/gold/ammo values
3. write_memory() to modify them
4. Watch the values change in real-time!
"""

import os
import sys
import time
import ctypes

# Prevent output buffering issues on Windows
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')


class Player:
    """Player class with hackable attributes stored as ctypes for stable addresses."""
    
    def __init__(self):
        # Using ctypes for more stable/findable memory addresses
        self._health = ctypes.c_int32(100)
        self._gold = ctypes.c_int32(50)
        self._ammo = ctypes.c_int32(30)
        self._score = ctypes.c_int32(0)
        
    @property
    def health(self):
        return self._health.value
    
    @health.setter
    def health(self, val):
        self._health.value = val
        
    @property
    def gold(self):
        return self._gold.value
    
    @gold.setter
    def gold(self, val):
        self._gold.value = val
        
    @property
    def ammo(self):
        return self._ammo.value
    
    @ammo.setter
    def ammo(self, val):
        self._ammo.value = val
        
    @property
    def score(self):
        return self._score.value
    
    @score.setter
    def score(self, val):
        self._score.value = val
        
    def get_health_address(self):
        return ctypes.addressof(self._health)
    
    def get_gold_address(self):
        return ctypes.addressof(self._gold)
    
    def get_ammo_address(self):
        return ctypes.addressof(self._ammo)
    
    def get_score_address(self):
        return ctypes.addressof(self._score)


def main():
    pid = os.getpid()
    player = Player()
    
    print("=" * 70)
    print("  HACKME - Frida Game Hacking MCP Demonstration Target")
    print("=" * 70)
    print(f"\n  Process ID (PID): {pid}")
    print(f"\n  Process Name: python.exe (or python)")
    print("\n  To hack this game with MCP tools:")
    print("  ----------------------------------------")
    print(f"  1. attach({pid})  OR  attach('python.exe')")
    print(f"  2. scan_value({player.health}, 'int32')  -> Find health")
    print("  3. Press 'D' here to take damage (health changes)")
    print("  4. scan_next(<new_health_value>)  -> Narrow results")
    print("  5. get_scan_results()  -> See matching addresses")
    print("  6. write_memory('<address>', '999', 'int32')  -> Set health to 999!")
    print("  ----------------------------------------")
    print("\n  Memory Addresses (for verification):")
    print(f"    Health @ {hex(player.get_health_address())}")
    print(f"    Gold   @ {hex(player.get_gold_address())}")
    print(f"    Ammo   @ {hex(player.get_ammo_address())}")
    print(f"    Score  @ {hex(player.get_score_address())}")
    print("\n" + "=" * 70)
    print("\n  Controls:")
    print("    [D] Take 10 damage")
    print("    [H] Heal 20 health")
    print("    [G] Add 25 gold")
    print("    [S] Spend 10 gold")
    print("    [A] Use 5 ammo")
    print("    [R] Reload (+30 ammo)")
    print("    [P] Add 100 score")
    print("    [Q] Quit")
    print("\n  The display updates every second. Watch values change!")
    print("=" * 70)
    
    if os.name == 'nt':
        import msvcrt
        
    running = True
    tick = 0
    
    while running:
        # Clear and redraw status
        print(f"\r  [Tick {tick:04d}]  Health: {player.health:4d}  |  Gold: {player.gold:4d}  |  Ammo: {player.ammo:3d}  |  Score: {player.score:6d}    ", end="", flush=True)
        
        # Check for input (non-blocking on Windows)
        if os.name == 'nt':
            if msvcrt.kbhit():
                key = msvcrt.getch().decode('utf-8', errors='ignore').upper()
                
                if key == 'D':
                    player.health = max(0, player.health - 10)
                    print(f"\n  [!] Took damage! Health now: {player.health}")
                elif key == 'H':
                    player.health = min(999, player.health + 20)
                    print(f"\n  [+] Healed! Health now: {player.health}")
                elif key == 'G':
                    player.gold += 25
                    print(f"\n  [+] Found gold! Gold now: {player.gold}")
                elif key == 'S':
                    player.gold = max(0, player.gold - 10)
                    print(f"\n  [-] Spent gold! Gold now: {player.gold}")
                elif key == 'A':
                    player.ammo = max(0, player.ammo - 5)
                    print(f"\n  [-] Used ammo! Ammo now: {player.ammo}")
                elif key == 'R':
                    player.ammo = min(999, player.ammo + 30)
                    print(f"\n  [+] Reloaded! Ammo now: {player.ammo}")
                elif key == 'P':
                    player.score += 100
                    print(f"\n  [+] Score! Score now: {player.score}")
                elif key == 'Q':
                    running = False
                    print("\n\n  [*] Quitting...")
        else:
            # Unix - use select for non-blocking
            import select
            if select.select([sys.stdin], [], [], 0)[0]:
                key = sys.stdin.read(1).upper()
                if key == 'D':
                    player.health = max(0, player.health - 10)
                elif key == 'H':
                    player.health = min(999, player.health + 20)
                elif key == 'G':
                    player.gold += 25
                elif key == 'S':
                    player.gold = max(0, player.gold - 10)
                elif key == 'A':
                    player.ammo = max(0, player.ammo - 5)
                elif key == 'R':
                    player.ammo = min(999, player.ammo + 30)
                elif key == 'P':
                    player.score += 100
                elif key == 'Q':
                    running = False
        
        time.sleep(0.5)
        tick += 1
        
        # Check for death
        if player.health <= 0:
            print("\n\n  [X] YOU DIED! (But you can hack yourself back to life!)")
            print("      Use: write_memory('<health_address>', '100', 'int32')")
            player.health = 0  # Keep at 0, let user hack it back
    
    print("\n  Final Stats:")
    print(f"    Health: {player.health}")
    print(f"    Gold:   {player.gold}")
    print(f"    Ammo:   {player.ammo}")
    print(f"    Score:  {player.score}")
    print("\n  Thanks for testing Frida Game Hacking MCP!")


if __name__ == "__main__":
    main()

