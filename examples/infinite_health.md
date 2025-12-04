# Example: Infinite Health Hack

This example demonstrates how to find and modify a health value in a game using the Cheat Engine-style workflow.

## Scenario

You're playing a game where your character has 100 health points. You want to find the memory address storing this value and modify it.

## Step-by-Step

### 1. Find and attach to the game process

```
> list_processes("game")
{
  "count": 1,
  "processes": [{"pid": 12345, "name": "game.exe"}]
}

> attach("game.exe")
{
  "success": true,
  "pid": 12345,
  "process_name": "game.exe"
}
```

### 2. Initial scan for current health (100)

```
> scan_value(100, "int32")
{
  "success": true,
  "value": 100,
  "value_type": "int32",
  "found": 58869,
  "message": "Found 58869 addresses. Use scan_next() to narrow."
}
```

### 3. Take damage in-game (health now 95), then narrow search

```
> scan_next(95)
{
  "success": true,
  "value": 95,
  "remaining": 1419,
  "message": "Narrowed to 1419 addresses."
}
```

### 4. Keep narrowing until you find it

```
# Take more damage (health = 90)
> scan_next(90)
{"remaining": 68}

# Heal up (health = 100)
> scan_next(100)
{"remaining": 3}

# Get the results
> get_scan_results()
{
  "total": 3,
  "shown": 3,
  "results": [
    {"address": "0x12345678", "value": 100, "hex": "64000000"},
    {"address": "0x23456789", "value": 100, "hex": "64000000"},
    {"address": "0x34567890", "value": 100, "hex": "64000000"}
  ]
}
```

### 5. Test which address is correct

```
# Write 999 to first address
> write_memory("0x12345678", "999", "int32")

# Check in-game if health changed
# If yes, you found it! If no, try the next address.
```

### 6. For permanent infinite health, hook the damage function

```
# First, find what writes to this address using pattern scan
> scan_pattern("89 47 ?? 8B", "r-x")

# Hook the damage function to prevent health reduction
> hook_function("0xDAMAGE_FUNC",
    on_leave="retval.replace(0);")  # No damage dealt
```

## Tips

- **int32** is the most common type for health/ammo/money
- **float** is often used in modern games
- Use **scan_unchanged** if the value hasn't changed between scans
- Use **scan_changed** if you know it changed but not to what value

