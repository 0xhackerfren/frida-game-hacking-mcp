# Test Game - Proof of Concept

This folder contains test programs to demonstrate and verify the Frida Game Hacking MCP tools work correctly.

## Files

| File | Description |
|------|-------------|
| `hackme.py` | Simple target game with hackable values (health, gold, ammo, score) |
| `poc_demo.py` | Automated proof-of-concept that attaches and modifies memory |
| `full_demo.py` | Interactive demo with full Cheat Engine workflow |

## Quick Test

### 1. Start the target game

```bash
python hackme.py
```

This opens a window showing:
- Health: 100
- Gold: 50
- Ammo: 30
- Score: 0

### 2. Run the POC demo (in another terminal)

```bash
python poc_demo.py
```

This will:
1. Find the hackme.py process
2. Attach using Frida
3. Scan for addresses containing value 100
4. Write 999 to found addresses
5. Verify the write

### 3. Check results

Look at the hackme.py window - if the health value changed to 999, the hack worked!

## Interactive Demo

For a full walkthrough of the Cheat Engine-style workflow:

```bash
# Terminal 1
python hackme.py

# Terminal 2
python full_demo.py
```

Choose option 1 for the guided workflow:
1. Scan for initial value (100)
2. Press D in hackme.py to take damage
3. Enter the new value to narrow results
4. Repeat until finding the exact address
5. Modify to 999

## What This Proves

- **list_processes()** - Can enumerate running processes
- **attach()** - Can connect to a target process with Frida
- **scan_value()** - Can find values in process memory
- **scan_next()** - Can narrow results after value changes
- **get_scan_results()** - Can retrieve matching addresses
- **write_memory()** - Can modify values in target memory
- **read_memory()** - Can verify modifications

## Expected Output

```
[STEP 5] Scanning for health value (100, int32)...
Result: Found 4638 addresses containing value 100

[STEP 8] Writing value 999 to address 0x...
Result: {'success': True, 'address': '0x...', 'bytes_written': 4}

[STEP 9] Verifying write by reading back...
Result: {'address': '0x...', 'size': 4, 'value': 999}

[+] SUCCESS! Value changed from 100 to 999!
```

