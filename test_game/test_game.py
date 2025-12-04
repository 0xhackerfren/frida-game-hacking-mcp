#!/usr/bin/env python3
"""
Test Game for Frida Game Hacking MCP Demonstration

A simple game with hackable values to demonstrate the MCP server capabilities.
Run this game, then use the MCP tools to find and modify the values.

Values to hack:
- Health (starts at 100, decreases over time)
- Gold (starts at 50, can increase/decrease)
- Ammo (starts at 30, decreases when "shooting")
- Score (starts at 0, increases over time)
"""

import os
import sys
import time
import ctypes
import random

# Game state - these are the values to hack
class GameState:
    def __init__(self):
        self.health = 100
        self.max_health = 100
        self.gold = 50
        self.ammo = 30
        self.max_ammo = 100
        self.score = 0
        self.level = 1
        self.is_alive = True
        # Secret value for pattern scanning demo
        self.secret_key = 0xDEADBEEF
        
    def take_damage(self, amount):
        self.health -= amount
        if self.health <= 0:
            self.health = 0
            self.is_alive = False
            
    def heal(self, amount):
        self.health = min(self.health + amount, self.max_health)
        
    def add_gold(self, amount):
        self.gold += amount
        
    def spend_gold(self, amount):
        if self.gold >= amount:
            self.gold -= amount
            return True
        return False
        
    def shoot(self):
        if self.ammo > 0:
            self.ammo -= 1
            self.score += 10
            return True
        return False
        
    def reload(self):
        self.ammo = self.max_ammo
        
    def add_score(self, points):
        self.score += points


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def get_address(obj, attr):
    """Get the memory address of an attribute (approximate for ctypes)."""
    # This gives us a way to show addresses for demonstration
    return id(getattr(obj, attr))


def print_game_state(game, pid):
    """Print current game state with memory addresses for hacking reference."""
    print("=" * 60)
    print("  TEST GAME - Frida MCP Hacking Demo")
    print("=" * 60)
    print(f"  Process ID (PID): {pid}")
    print("-" * 60)
    print(f"  Health: {game.health}/{game.max_health}")
    print(f"  Gold:   {game.gold}")
    print(f"  Ammo:   {game.ammo}/{game.max_ammo}")
    print(f"  Score:  {game.score}")
    print(f"  Level:  {game.level}")
    print("-" * 60)
    print("  Commands:")
    print("    [S] Shoot (uses ammo, +10 score)")
    print("    [R] Reload ammo")
    print("    [H] Buy health potion (costs 20 gold)")
    print("    [D] Take damage (simulates enemy hit)")
    print("    [G] Find gold (+10-50 random)")
    print("    [L] Level up")
    print("    [Q] Quit game")
    print("-" * 60)
    print("  TIP: Use Frida MCP to hack these values!")
    print("       scan_value(100, 'int32') to find health")
    print("=" * 60)


def main():
    pid = os.getpid()
    game = GameState()
    
    print(f"\n[*] Test Game Started!")
    print(f"[*] Process ID: {pid}")
    print(f"[*] Attach to this process using: attach({pid})")
    print(f"[*] Or by name: attach('python.exe') or attach('python')")
    print(f"\n[*] Starting values:")
    print(f"    Health = {game.health} (int32)")
    print(f"    Gold   = {game.gold} (int32)")
    print(f"    Ammo   = {game.ammo} (int32)")
    print(f"    Score  = {game.score} (int32)")
    print(f"\n[*] Press Enter to start the game loop...")
    input()
    
    last_damage_time = time.time()
    
    while game.is_alive:
        clear_screen()
        print_game_state(game, pid)
        
        # Passive damage every 10 seconds
        current_time = time.time()
        if current_time - last_damage_time > 10:
            damage = random.randint(5, 15)
            game.take_damage(damage)
            last_damage_time = current_time
            print(f"\n  [!] Took {damage} passive damage!")
        
        # Check for game over
        if not game.is_alive:
            print("\n  [X] GAME OVER - You died!")
            print(f"  Final Score: {game.score}")
            break
            
        print("\n  Enter command: ", end="", flush=True)
        
        # Non-blocking input with timeout
        if os.name == 'nt':
            import msvcrt
            start_time = time.time()
            cmd = ""
            while time.time() - start_time < 2:  # 2 second timeout
                if msvcrt.kbhit():
                    char = msvcrt.getch().decode('utf-8', errors='ignore').upper()
                    cmd = char
                    print(char)
                    break
                time.sleep(0.1)
        else:
            import select
            ready, _, _ = select.select([sys.stdin], [], [], 2)
            if ready:
                cmd = sys.stdin.readline().strip().upper()
            else:
                cmd = ""
        
        # Process commands
        if cmd == 'S':
            if game.shoot():
                print("  [+] Shot fired! +10 score")
            else:
                print("  [-] No ammo! Press R to reload")
            time.sleep(0.5)
            
        elif cmd == 'R':
            game.reload()
            print(f"  [+] Reloaded! Ammo: {game.ammo}")
            time.sleep(0.5)
            
        elif cmd == 'H':
            if game.spend_gold(20):
                game.heal(30)
                print(f"  [+] Healed! Health: {game.health}")
            else:
                print("  [-] Not enough gold! Need 20")
            time.sleep(0.5)
            
        elif cmd == 'D':
            damage = random.randint(10, 25)
            game.take_damage(damage)
            print(f"  [!] Took {damage} damage! Health: {game.health}")
            time.sleep(0.5)
            
        elif cmd == 'G':
            gold_found = random.randint(10, 50)
            game.add_gold(gold_found)
            print(f"  [+] Found {gold_found} gold! Total: {game.gold}")
            time.sleep(0.5)
            
        elif cmd == 'L':
            game.level += 1
            game.score += 100
            game.max_health += 20
            game.health = game.max_health
            print(f"  [+] Level Up! Now level {game.level}")
            time.sleep(0.5)
            
        elif cmd == 'Q':
            print("  [*] Quitting game...")
            break
    
    print("\n[*] Game ended. Final stats:")
    print(f"    Health: {game.health}")
    print(f"    Gold:   {game.gold}")
    print(f"    Ammo:   {game.ammo}")
    print(f"    Score:  {game.score}")
    print(f"    Level:  {game.level}")
    print("\n[*] Thanks for playing!")
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()

