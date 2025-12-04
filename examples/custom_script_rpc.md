# Example: Custom Scripts with RPC

This example shows how to load custom Frida scripts and call them via RPC.

## Scenario

You want to create a reusable "god mode" script that can be toggled on/off.

## Create and Load the Script

```
> attach("game.exe")

> load_script('''
    var godModeEnabled = false;
    var healthAddress = null;
    var originalDamageFunc = null;
    
    rpc.exports = {
        // Find the health address
        findHealth: function(currentValue) {
            var results = [];
            var ranges = Process.enumerateRanges("rw-");
            var pattern = "";
            
            // Convert to little-endian hex
            var buf = Memory.alloc(4);
            buf.writeS32(currentValue);
            pattern = buf.readByteArray(4);
            
            for (var i = 0; i < ranges.length; i++) {
                try {
                    var matches = Memory.scanSync(ranges[i].base, ranges[i].size, 
                        Array.from(new Uint8Array(pattern)).map(b => 
                            ('0' + b.toString(16)).slice(-2)).join(' '));
                    matches.forEach(m => results.push(m.address.toString()));
                } catch (e) {}
            }
            return results.slice(0, 100);
        },
        
        // Set health address for god mode
        setHealthAddress: function(addr) {
            healthAddress = ptr(addr);
            return "Health address set to " + addr;
        },
        
        // Toggle god mode
        toggleGodMode: function() {
            godModeEnabled = !godModeEnabled;
            return "God mode: " + (godModeEnabled ? "ON" : "OFF");
        },
        
        // Set health value
        setHealth: function(value) {
            if (!healthAddress) return "Health address not set!";
            healthAddress.writeS32(value);
            return "Health set to " + value;
        },
        
        // Get current health
        getHealth: function() {
            if (!healthAddress) return "Health address not set!";
            return healthAddress.readS32();
        }
    };
    
    console.log("[GodMode] Script loaded!");
''', "godmode")
```

## Use the RPC Methods

```
# Find health when it's at 100
> call_rpc("godmode", "findHealth", [100])
{
  "result": ["0x12345678", "0x23456789", ...]
}

# After narrowing down, set the health address
> call_rpc("godmode", "setHealthAddress", ["0x12345678"])
{
  "result": "Health address set to 0x12345678"
}

# Toggle god mode on
> call_rpc("godmode", "toggleGodMode", [])
{
  "result": "God mode: ON"
}

# Set health to max
> call_rpc("godmode", "setHealth", [9999])
{
  "result": "Health set to 9999"
}

# Check current health
> call_rpc("godmode", "getHealth", [])
{
  "result": 9999
}
```

## Cleanup

```
> unload_script("godmode")
{"success": true, "name": "godmode"}

> detach()
{"success": true}
```

## Benefits of RPC Scripts

1. **Persistent State**: Variables persist between calls
2. **Complex Logic**: Full JavaScript for game-specific hacks
3. **Performance**: Script runs in-process, no IPC overhead
4. **Reusability**: Load once, call many times

