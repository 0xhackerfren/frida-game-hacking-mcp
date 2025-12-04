# Frida Game Hacking MCP

A Model Context Protocol (MCP) server that provides **Cheat Engine-like capabilities** for game hacking through [Frida](https://frida.re/). Enables AI assistants and automation tools to perform memory scanning, value modification, pattern matching, function hooking, and code injection.

![MCP](https://img.shields.io/badge/MCP-Compatible-blue)
![Python](https://img.shields.io/badge/Python-3.10+-green)
![Frida](https://img.shields.io/badge/Frida-16.0+-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

### Memory Operations (Cheat Engine Style)
- **Value Scanning**: Find values in memory by type (int8-64, float, double, string)
- **Scan Refinement**: Narrow results with `scan_next`, `scan_changed`, `scan_unchanged`
- **Pattern Scanning**: Array of Bytes (AoB) with wildcard support (`??`)
- **Memory Read/Write**: Read and modify memory with type awareness

### Function Hooking & Code Injection
- **Intercept Functions**: Hook with `onEnter`/`onLeave` JavaScript callbacks
- **Replace Functions**: Make functions return custom values
- **Module Hooking**: Hook by `module!function` name
- **Symbol Resolution**: Resolve exports to addresses

### Process Management
- **Process Enumeration**: List and filter running processes
- **Attach/Detach**: Connect to running processes
- **Spawn & Resume**: Start processes suspended for early hooking

### Debugging
- **Breakpoints**: Software breakpoints via hooks
- **Register Access**: Read CPU registers at breakpoints
- **Module Analysis**: List modules, exports, imports

### Window Interaction (Windows)
- **Screenshot Capture**: Take screenshots of game windows
- **Keyboard Input**: Send keystrokes to game windows
- **Window Management**: List, focus, and interact with windows

## Installation

```bash
# Install from PyPI (coming soon)
pip install frida-game-hacking-mcp

# Or install from source
git clone https://github.com/0xhackerfren/frida-game-hacking-mcp.git
cd frida-game-hacking-mcp
pip install -e .
```

### Requirements
- Python 3.10+
- Frida 16.0+
- pywin32, pillow (Windows, for screenshot features)

```bash
pip install frida frida-tools mcp pillow
# On Windows, also install:
pip install pywin32
```

## Quick Start

### Run the MCP Server

```bash
# Run directly
python -m frida_game_hacking_mcp

# Or use the entry point
frida-game-hacking-mcp
```

### Configure with Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "frida-game-hacking": {
      "command": "python",
      "args": ["-m", "frida_game_hacking_mcp"]
    }
  }
}
```

### Configure with Other MCP Clients

The server uses stdio transport by default. Connect using:
- Command: `python -m frida_game_hacking_mcp`
- Transport: stdio

## Usage Examples

### Cheat Engine Workflow: Find and Modify Health

```
1. List processes and find your game
   > list_processes("game")
   
2. Attach to the game
   > attach("game.exe")
   
3. Initial scan for current health value (e.g., 100)
   > scan_value(100, "int32")
   Found: 58,869 addresses
   
4. Take damage in game (health now 95)
   > scan_next(95)
   Narrowed to: 1,419 addresses
   
5. Repeat until you find the address
   > scan_next(90)
   Narrowed to: 3 addresses
   
6. Get results and modify
   > get_scan_results()
   > write_memory("0x12345678", "E7030000")  # 999 in little-endian
```

### Array of Bytes Pattern Scanning

```
# Find code pattern (works across game updates)
> attach("game.exe")
> scan_pattern("89 47 44 ?? ?? 5B 7A", "r-x")
Found: 2 matches

# ?? = wildcard bytes
# "r-x" = executable memory regions
```

### Function Hooking

```
# Hook a function and log calls
> hook_function("0x401234",
    on_enter="console.log('Args:', args[0], args[1]);",
    on_leave="console.log('Return:', retval);")

# Make a function always return success
> replace_function("0x401234", 1)

# Hook by module and function name
> intercept_module_function("game.dll", "CheckLicense",
    on_leave="retval.replace(1);")
```

### Early Hooking (Spawn Suspended)

```
# Start process suspended
> spawn("C:/Games/game.exe")

# Set up hooks before code runs
> hook_function("0x401234", on_enter="...")

# Resume execution
> resume()
```

## Available Tools (42 Total)

### Process Management (6)
| Tool | Description |
|------|-------------|
| `list_processes` | Enumerate running processes |
| `attach` | Attach to process by name or PID |
| `detach` | Detach from current process |
| `spawn` | Start process suspended |
| `resume` | Resume spawned process |
| `get_session_info` | Get current session status |

### Memory Operations (10)
| Tool | Description |
|------|-------------|
| `read_memory` | Read bytes at address |
| `write_memory` | Write bytes/values to address |
| `scan_value` | Initial scan for exact value |
| `scan_next` | Narrow scan with new value |
| `scan_changed` | Find changed values |
| `scan_unchanged` | Find unchanged values |
| `scan_pattern` | AoB pattern scan with wildcards |
| `get_scan_results` | Get current scan results |
| `clear_scan` | Reset scan state |
| `list_memory_regions` | List memory regions |

### Module Information (5)
| Tool | Description |
|------|-------------|
| `list_modules` | List loaded modules/DLLs |
| `get_module_info` | Get module details |
| `get_module_exports` | List module exports |
| `get_module_imports` | List module imports |
| `resolve_symbol` | Resolve symbol to address |

### Function Hooking (6)
| Tool | Description |
|------|-------------|
| `hook_function` | Hook with callbacks |
| `unhook_function` | Remove hook |
| `replace_function` | Replace function return |
| `hook_native_function` | Hook with calling convention |
| `list_hooks` | List active hooks |
| `intercept_module_function` | Hook by module!function |

### Debugging (4)
| Tool | Description |
|------|-------------|
| `set_breakpoint` | Set software breakpoint |
| `remove_breakpoint` | Remove breakpoint |
| `list_breakpoints` | List breakpoints |
| `read_registers` | Read CPU registers |

### Script Management (3)
| Tool | Description |
|------|-------------|
| `load_script` | Load custom Frida JS |
| `unload_script` | Unload script |
| `call_rpc` | Call script RPC export |

### Window Interaction (5) - Windows Only
| Tool | Description |
|------|-------------|
| `list_windows` | Enumerate visible windows |
| `screenshot_window` | Capture window to PNG/base64 |
| `screenshot_screen` | Capture screen or region |
| `send_key_to_window` | Send keystrokes to window |
| `focus_window` | Bring window to foreground |

### Standard MCP (3)
| Tool | Description |
|------|-------------|
| `list_capabilities` | List all tools |
| `get_documentation` | Get help and examples |
| `check_installation` | Verify Frida installed |

## Value Types

| Type | Size | Description |
|------|------|-------------|
| `int8` | 1 byte | Signed byte |
| `uint8` | 1 byte | Unsigned byte |
| `int16` | 2 bytes | Signed short |
| `uint16` | 2 bytes | Unsigned short |
| `int32` | 4 bytes | Signed int (most common) |
| `uint32` | 4 bytes | Unsigned int |
| `int64` | 8 bytes | Signed long |
| `uint64` | 8 bytes | Unsigned long |
| `float` | 4 bytes | Single precision |
| `double` | 8 bytes | Double precision |
| `string` | Variable | Null-terminated string |

## Scan Regions

| Region | Description |
|--------|-------------|
| `rw-` | Read-write data (heap, stack, globals) - default for value scans |
| `r-x` | Executable code - default for pattern scans |
| `rwx` | Read-write-execute (rare, often exploitable) |
| `r--` | Read-only data |

## Platform Support

- **Windows**: Native support
- **Linux**: Native support  
- **macOS**: Native support
- **Android**: Via frida-server
- **iOS**: Via frida-server (jailbroken)

## Use Cases

- **Game Hacking**: Memory editing, value modification, trainer development
- **Security Research**: Vulnerability analysis, exploit development
- **Reverse Engineering**: Runtime analysis, API hooking
- **Software Testing**: Fault injection, behavior modification
- **Malware Analysis**: Dynamic analysis in sandboxed environments

## Security Notice

This tool is intended for:
- Educational purposes
- Security research on software you own or have permission to test
- Game modding in single-player/offline contexts

**Do not use for**:
- Cheating in online multiplayer games
- Circumventing software protections illegally
- Any malicious purposes

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE)

## Credits

- Built on [Frida](https://frida.re/) by Ole Andre Vadla Ravnas
- MCP protocol by [Anthropic](https://github.com/anthropics/anthropic-cookbook/tree/main/misc/model_context_protocol)
- Inspired by [Cheat Engine](https://www.cheatengine.org/) by Dark Byte

## Links

- [Frida Documentation](https://frida.re/docs/)
- [MCP Specification](https://spec.modelcontextprotocol.io/)
- [Report Issues](https://github.com/0xhackerfren/frida-game-hacking-mcp/issues)

---

*Built for AI-assisted game hacking and security research.*
