#!/usr/bin/env python3
"""
Frida Game Hacking MCP Server

Provides Cheat Engine-like capabilities for game hacking through Frida:
- Memory scanning and modification
- Array of Bytes (AoB) pattern scanning
- Function hooking and code injection
- Process attachment and spawning
- Module enumeration and symbol resolution

Usage:
    python -m frida_game_hacking_mcp
    
    Or configure in your MCP client:
    {
        "mcpServers": {
            "frida-game-hacking": {
                "command": "python",
                "args": ["-m", "frida_game_hacking_mcp"]
            }
        }
    }
"""

import struct
import logging
import base64
import io
import os
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, field

try:
    import frida
    FRIDA_AVAILABLE = True
except ImportError:
    FRIDA_AVAILABLE = False

# Screenshot support (Windows)
SCREENSHOT_AVAILABLE = False
try:
    import ctypes
    from ctypes import wintypes
    import win32gui
    import win32ui
    import win32con
    import win32process
    from PIL import Image
    SCREENSHOT_AVAILABLE = True
except ImportError:
    pass

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

# Initialize MCP server
mcp = FastMCP("frida-game-hacking-mcp")

# =============================================================================
# SESSION STATE MANAGEMENT
# =============================================================================

@dataclass
class ScanState:
    """Tracks memory scan state for Cheat Engine-style scanning."""
    value_type: str = ""
    results: List[int] = field(default_factory=list)
    last_values: Dict[int, Any] = field(default_factory=dict)
    scan_active: bool = False


@dataclass
class HookInfo:
    """Information about an active hook."""
    address: str
    script: Any
    hook_type: str
    description: str = ""


class FridaSession:
    """Manages Frida session state."""
    
    def __init__(self):
        self.device: Optional[Any] = None
        self.session: Optional[Any] = None
        self.pid: Optional[int] = None
        self.process_name: Optional[str] = None
        self.spawned: bool = False
        self.scan_state: ScanState = ScanState()
        self.hooks: Dict[str, HookInfo] = {}
        self.breakpoints: Dict[str, Any] = {}
        self.custom_scripts: Dict[str, Any] = {}
    
    def is_attached(self) -> bool:
        return self.session is not None and not self.session.is_detached
    
    def reset(self):
        self.session = None
        self.pid = None
        self.process_name = None
        self.spawned = False
        self.scan_state = ScanState()
        self.hooks.clear()
        self.breakpoints.clear()
        self.custom_scripts.clear()


# Global session instance
_session = FridaSession()


def get_device() -> Any:
    """Get the local Frida device."""
    global _session
    if _session.device is None:
        _session.device = frida.get_local_device()
    return _session.device


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_value_size(value_type: str) -> int:
    """Get byte size for value type."""
    sizes = {
        "int8": 1, "uint8": 1,
        "int16": 2, "uint16": 2,
        "int32": 4, "uint32": 4,
        "int64": 8, "uint64": 8,
        "float": 4, "double": 8
    }
    return sizes.get(value_type, 4)


def _pack_value(value: Any, value_type: str) -> bytes:
    """Pack value to bytes based on type."""
    formats = {
        "int8": "<b", "uint8": "<B",
        "int16": "<h", "uint16": "<H",
        "int32": "<i", "uint32": "<I",
        "int64": "<q", "uint64": "<Q",
        "float": "<f", "double": "<d"
    }
    fmt = formats.get(value_type)
    if fmt:
        return struct.pack(fmt, value)
    elif value_type == "string":
        return value.encode('utf-8') + b'\x00'
    return struct.pack("<i", int(value))


def _unpack_value(data: bytes, value_type: str) -> Any:
    """Unpack bytes to value based on type."""
    formats = {
        "int8": "<b", "uint8": "<B",
        "int16": "<h", "uint16": "<H",
        "int32": "<i", "uint32": "<I",
        "int64": "<q", "uint64": "<Q",
        "float": "<f", "double": "<d"
    }
    fmt = formats.get(value_type)
    if fmt:
        return struct.unpack(fmt, data)[0]
    elif value_type == "string":
        return data.split(b'\x00')[0].decode('utf-8', errors='replace')
    return struct.unpack("<i", data)[0]


# =============================================================================
# STANDARD MCP TOOLS
# =============================================================================

@mcp.tool()
def list_capabilities() -> Dict[str, Any]:
    """
    List all tools provided by this MCP server.
    
    Returns:
        Dictionary with MCP info and available tools organized by category.
    """
    return {
        "mcp_name": "frida-game-hacking-mcp",
        "version": "1.1.0",
        "description": "Cheat Engine-like game hacking capabilities through Frida",
        "frida_available": FRIDA_AVAILABLE,
        "screenshot_available": SCREENSHOT_AVAILABLE,
        "tool_categories": {
            "process_management": [
                "list_processes", "attach", "detach", "spawn", "resume", "get_session_info"
            ],
            "memory_operations": [
                "read_memory", "write_memory", "scan_value", "scan_next",
                "scan_changed", "scan_unchanged", "scan_pattern",
                "get_scan_results", "clear_scan", "list_memory_regions"
            ],
            "module_information": [
                "list_modules", "get_module_info", "get_module_exports",
                "get_module_imports", "resolve_symbol"
            ],
            "function_hooking": [
                "hook_function", "unhook_function", "replace_function",
                "hook_native_function", "list_hooks", "intercept_module_function"
            ],
            "debugging": [
                "set_breakpoint", "remove_breakpoint", "list_breakpoints", "read_registers"
            ],
            "script_management": [
                "load_script", "unload_script", "call_rpc"
            ],
            "window_interaction": [
                "list_windows", "screenshot_window", "screenshot_screen",
                "send_key_to_window", "focus_window"
            ],
            "standard": [
                "list_capabilities", "get_documentation", "check_installation"
            ]
        },
        "total_tools": 42
    }


@mcp.tool()
def get_documentation(topic: str = "general") -> Dict[str, Any]:
    """
    Get documentation and usage examples.
    
    Args:
        topic: Documentation topic (general, memory, hooking, scanning, examples)
    
    Returns:
        Documentation for the requested topic.
    """
    docs = {
        "tool": "frida-game-hacking-mcp",
        "official_docs": "https://frida.re/docs/",
        "topic": topic
    }
    
    if topic == "general":
        docs["quick_start"] = """
CHEAT ENGINE-STYLE WORKFLOW:

1. Find your target process:
   list_processes("game")

2. Attach to the process:
   attach("game.exe")

3. Scan for a known value (e.g., health = 100):
   scan_value(100, "int32")

4. Change the value in-game and narrow results:
   scan_next(95)

5. Repeat until you find the address, then modify:
   write_memory("0x12345678", "E7030000")  # 999

PATTERN SCANNING (for code that survives updates):
   scan_pattern("89 47 44 ?? ?? 5B", "r-x")

FUNCTION HOOKING:
   hook_function("0x401234",
       on_enter="console.log('Called!');",
       on_leave="retval.replace(1);")
"""
        docs["value_types"] = [
            "int8/uint8 (1 byte)", "int16/uint16 (2 bytes)",
            "int32/uint32 (4 bytes)", "int64/uint64 (8 bytes)",
            "float (4 bytes)", "double (8 bytes)", "string"
        ]
    
    elif topic == "scanning":
        docs["workflow"] = """
MEMORY SCANNING WORKFLOW:

1. scan_value(100, "int32")  - Initial scan
2. scan_next(95)             - Narrow after value changes
3. scan_changed()            - Find values that changed
4. scan_unchanged()          - Find values that stayed same
5. get_scan_results()        - View matching addresses
6. clear_scan()              - Reset for new scan

PATTERN SCANNING:
   scan_pattern("89 47 ?? 5B", "r-x")
   - ?? = wildcard (matches any byte)
   - "r-x" = code sections
   - "rw-" = data sections
"""
    
    elif topic == "hooking":
        docs["examples"] = """
INTERCEPT FUNCTION:
   hook_function("0x401234",
       on_enter="console.log('Args:', args[0]);",
       on_leave="console.log('Return:', retval);")

REPLACE RETURN VALUE:
   replace_function("0x401234", 1)  # Always return 1

HOOK BY NAME:
   intercept_module_function("game.dll", "CheckLicense",
       on_leave="retval.replace(1);")

EARLY HOOKING:
   spawn("game.exe")
   hook_function("0x401234", ...)
   resume()
"""
    
    return docs


@mcp.tool()
def check_installation() -> Dict[str, Any]:
    """
    Check if Frida is installed and working.
    
    Returns:
        Installation status and version information.
    """
    result = {
        "tool": "frida",
        "installed": FRIDA_AVAILABLE,
        "installation": "pip install frida frida-tools"
    }
    
    if FRIDA_AVAILABLE:
        result["frida_version"] = frida.__version__
        result["working"] = True
        try:
            device = get_device()
            result["device"] = device.name
            result["device_type"] = device.type
        except Exception as e:
            result["device_error"] = str(e)
    else:
        result["working"] = False
        result["error"] = "Frida not installed"
    
    return result


# =============================================================================
# PROCESS MANAGEMENT
# =============================================================================

@mcp.tool()
def list_processes(filter_name: str = "") -> Dict[str, Any]:
    """
    List all running processes.
    
    Args:
        filter_name: Optional filter to match process names (case-insensitive)
    
    Returns:
        List of processes with PID and name.
    """
    if not FRIDA_AVAILABLE:
        return {"error": "Frida not installed. Run: pip install frida frida-tools"}
    
    try:
        device = get_device()
        processes = device.enumerate_processes()
        
        result = []
        for proc in processes:
            if filter_name and filter_name.lower() not in proc.name.lower():
                continue
            result.append({"pid": proc.pid, "name": proc.name})
        
        result.sort(key=lambda x: x["name"].lower())
        return {"count": len(result), "processes": result[:100]}
    
    except Exception as e:
        return {"error": f"Failed to enumerate processes: {str(e)}"}


@mcp.tool()
def attach(target: Union[str, int]) -> Dict[str, Any]:
    """
    Attach to a running process.
    
    Args:
        target: Process name (string) or PID (integer)
    
    Returns:
        Session information.
    """
    global _session
    
    if not FRIDA_AVAILABLE:
        return {"error": "Frida not installed. Run: pip install frida frida-tools"}
    
    if _session.is_attached():
        detach()
    
    try:
        device = get_device()
        
        if isinstance(target, str):
            _session.session = device.attach(target)
            _session.process_name = target
            _session.pid = getattr(_session.session, 'pid', None)
        else:
            _session.session = device.attach(target)
            _session.pid = target
            for proc in device.enumerate_processes():
                if proc.pid == target:
                    _session.process_name = proc.name
                    break
        
        _session.spawned = False
        return {
            "success": True,
            "pid": _session.pid,
            "process_name": _session.process_name,
            "message": f"Attached to {_session.process_name or target}"
        }
    
    except frida.ProcessNotFoundError:
        return {"error": f"Process not found: {target}"}
    except frida.PermissionDeniedError:
        return {"error": "Permission denied. Try running as administrator."}
    except Exception as e:
        return {"error": f"Failed to attach: {str(e)}"}


@mcp.tool()
def detach() -> Dict[str, Any]:
    """
    Detach from the current process.
    
    Returns:
        Detach status.
    """
    global _session
    
    if not _session.is_attached():
        return {"message": "No active session"}
    
    try:
        for hook_info in _session.hooks.values():
            try:
                hook_info.script.unload()
            except:
                pass
        
        for script in _session.custom_scripts.values():
            try:
                script.unload()
            except:
                pass
        
        _session.session.detach()
        old_name = _session.process_name
        _session.reset()
        
        return {"success": True, "message": f"Detached from {old_name}"}
    
    except Exception as e:
        _session.reset()
        return {"error": f"Error during detach: {str(e)}"}


@mcp.tool()
def spawn(path: str, args: List[str] = None) -> Dict[str, Any]:
    """
    Spawn a process suspended for early hooking.
    
    Args:
        path: Path to executable
        args: Optional command line arguments
    
    Returns:
        Spawn information. Call resume() to start execution.
    """
    global _session
    
    if not FRIDA_AVAILABLE:
        return {"error": "Frida not installed. Run: pip install frida frida-tools"}
    
    if _session.is_attached():
        detach()
    
    try:
        device = get_device()
        spawn_args = [path] + (args or [])
        
        _session.pid = device.spawn(spawn_args)
        _session.session = device.attach(_session.pid)
        _session.process_name = path.split("\\")[-1].split("/")[-1]
        _session.spawned = True
        
        return {
            "success": True,
            "pid": _session.pid,
            "process_name": _session.process_name,
            "state": "suspended",
            "message": f"Spawned {_session.process_name}. Call resume() to start."
        }
    
    except Exception as e:
        return {"error": f"Failed to spawn: {str(e)}"}


@mcp.tool()
def resume() -> Dict[str, Any]:
    """
    Resume a spawned process.
    
    Returns:
        Resume status.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "No active session. Use spawn() first."}
    
    if not _session.spawned:
        return {"error": "Process was not spawned."}
    
    try:
        device = get_device()
        device.resume(_session.pid)
        return {"success": True, "message": f"Resumed {_session.process_name}"}
    
    except Exception as e:
        return {"error": f"Failed to resume: {str(e)}"}


@mcp.tool()
def get_session_info() -> Dict[str, Any]:
    """
    Get current session information.
    
    Returns:
        Session state including attached process, hooks, scan state.
    """
    return {
        "attached": _session.is_attached(),
        "pid": _session.pid,
        "process_name": _session.process_name,
        "spawned": _session.spawned,
        "scan_active": _session.scan_state.scan_active,
        "scan_results_count": len(_session.scan_state.results),
        "scan_value_type": _session.scan_state.value_type,
        "active_hooks": len(_session.hooks),
        "active_breakpoints": len(_session.breakpoints),
        "custom_scripts": len(_session.custom_scripts)
    }


# =============================================================================
# MEMORY OPERATIONS
# =============================================================================

@mcp.tool()
def read_memory(address: str, size: int = 16, format: str = "hex") -> Dict[str, Any]:
    """
    Read memory at specified address.
    
    Args:
        address: Memory address (hex string like "0x401234")
        size: Number of bytes to read
        format: Output format ("hex", "bytes", "int32", "float", "string")
    
    Returns:
        Memory contents in requested format.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        script_code = f"""
        var addr = ptr("{hex(addr)}");
        try {{
            var data = Memory.readByteArray(addr, {size});
            var hex = '';
            var bytes = new Uint8Array(data);
            for (var i = 0; i < bytes.length; i++) {{
                hex += ('0' + bytes[i].toString(16)).slice(-2);
            }}
            send({{type: 'data', hex: hex}});
        }} catch (e) {{
            send({{type: 'error', msg: e.toString()}});
        }}
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        if not result_data:
            return {"error": "No response from Frida"}
        
        response = result_data[0]
        if response.get('type') == 'error':
            return {"error": f"Memory read failed: {response.get('msg')}"}
        
        raw_bytes = bytes.fromhex(response['hex'])
        output = {"address": hex(addr), "size": size}
        
        if format == "hex":
            output["hex"] = raw_bytes.hex()
            output["hex_spaced"] = " ".join(f"{b:02x}" for b in raw_bytes)
        elif format == "bytes":
            output["bytes"] = list(raw_bytes)
        elif format == "int32" and size >= 4:
            output["value"] = struct.unpack("<i", raw_bytes[:4])[0]
        elif format == "float" and size >= 4:
            output["value"] = struct.unpack("<f", raw_bytes[:4])[0]
        elif format == "string":
            output["string"] = raw_bytes.split(b'\x00')[0].decode('utf-8', errors='replace')
        else:
            output["hex"] = raw_bytes.hex()
            output["hex_spaced"] = " ".join(f"{b:02x}" for b in raw_bytes)
        
        return output
    
    except Exception as e:
        return {"error": f"Failed to read memory: {str(e)}"}


@mcp.tool()
def write_memory(address: str, data: str, value_type: str = "bytes") -> Dict[str, Any]:
    """
    Write data to memory address.
    
    Args:
        address: Memory address (hex string like "0x401234")
        data: Data to write (hex string, or value if value_type specified)
        value_type: Type of data ("bytes", "int32", "float", "string", etc.)
    
    Returns:
        Write status.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        if value_type == "bytes":
            write_bytes = bytes.fromhex(data.replace(" ", ""))
        elif value_type in ("int8", "uint8", "int16", "uint16", "int32", "uint32",
                           "int64", "uint64", "float", "double"):
            value = float(data) if value_type in ("float", "double") else int(data)
            write_bytes = _pack_value(value, value_type)
        elif value_type == "string":
            write_bytes = data.encode('utf-8') + b'\x00'
        else:
            write_bytes = bytes.fromhex(data.replace(" ", ""))
        
        byte_array = ", ".join(f"0x{b:02x}" for b in write_bytes)
        script_code = f"""
        var addr = ptr("{hex(addr)}");
        Memory.writeByteArray(addr, [{byte_array}]);
        send("done");
        """
        
        script = _session.session.create_script(script_code)
        script.on('message', lambda m, d: None)
        script.load()
        script.unload()
        
        return {
            "success": True,
            "address": hex(addr),
            "bytes_written": len(write_bytes),
            "data_hex": write_bytes.hex()
        }
    
    except Exception as e:
        return {"error": f"Failed to write memory: {str(e)}"}


@mcp.tool()
def list_memory_regions(protection: str = "") -> Dict[str, Any]:
    """
    List memory regions in the process.
    
    Args:
        protection: Filter by protection (e.g., "r-x", "rw-", "rwx")
    
    Returns:
        List of memory regions with base, size, and protection.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = """
        var ranges = Process.enumerateRanges('r--');
        var result = ranges.map(function(r) {
            return {
                base: r.base.toString(),
                size: r.size,
                protection: r.protection,
                file: r.file ? r.file.path : null
            };
        });
        send(JSON.stringify(result));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        if not result_data:
            return {"error": "Failed to enumerate regions"}
        
        import json
        regions = json.loads(result_data[0])
        
        if protection:
            regions = [r for r in regions if protection in r['protection']]
        
        return {"count": len(regions), "regions": regions[:100]}
    
    except Exception as e:
        return {"error": f"Failed to enumerate regions: {str(e)}"}


@mcp.tool()
def scan_value(value: Union[int, float, str], value_type: str = "int32",
               scan_regions: str = "rw-") -> Dict[str, Any]:
    """
    Scan memory for exact value (initial scan).
    
    Args:
        value: Value to search for
        value_type: Type ("int8", "int16", "int32", "int64", "float", "double", "string")
        scan_regions: Memory protection to scan (default: "rw-" for data)
    
    Returns:
        Number of addresses found.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        _session.scan_state = ScanState()
        _session.scan_state.value_type = value_type
        _session.scan_state.scan_active = True
        
        if value_type == "string":
            search_pattern = value.encode('utf-8').hex()
        else:
            search_pattern = _pack_value(value, value_type).hex()
        
        script_code = f"""
        var results = [];
        var pattern = "{search_pattern}";
        var ranges = Process.enumerateRanges("{scan_regions}");
        
        for (var i = 0; i < ranges.length && results.length < 100000; i++) {{
            try {{
                var matches = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
                for (var j = 0; j < matches.length && results.length < 100000; j++) {{
                    results.push(matches[j].address.toString());
                }}
            }} catch (e) {{ }}
        }}
        send(JSON.stringify(results));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        if not result_data:
            return {"error": "Scan failed"}
        
        import json
        addresses = json.loads(result_data[0])
        _session.scan_state.results = [int(a, 16) for a in addresses]
        
        for addr in _session.scan_state.results[:1000]:
            _session.scan_state.last_values[addr] = value
        
        return {
            "success": True,
            "value": value,
            "value_type": value_type,
            "found": len(_session.scan_state.results),
            "message": f"Found {len(_session.scan_state.results)} addresses. Use scan_next() to narrow."
        }
    
    except Exception as e:
        return {"error": f"Scan failed: {str(e)}"}


@mcp.tool()
def scan_next(value: Union[int, float, str]) -> Dict[str, Any]:
    """
    Narrow scan results with new value.
    
    Args:
        value: New value to search for
    
    Returns:
        Number of remaining addresses.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if not _session.scan_state.scan_active:
        return {"error": "No active scan. Use scan_value() first."}
    
    try:
        value_type = _session.scan_state.value_type
        value_size = _get_value_size(value_type)
        
        if value_type == "string":
            expected_hex = value.encode('utf-8').hex()
        else:
            expected_hex = _pack_value(value, value_type).hex()
        
        addresses = _session.scan_state.results
        if not addresses:
            return {"success": True, "value": value, "remaining": 0}
        
        batch_size = 1000
        new_results = []
        
        for batch_start in range(0, len(addresses), batch_size):
            batch = addresses[batch_start:batch_start + batch_size]
            addr_list = ", ".join(f'"{hex(a)}"' for a in batch)
            
            script_code = f"""
            var addresses = [{addr_list}];
            var size = {value_size};
            var expected = "{expected_hex}";
            var matches = [];
            
            for (var i = 0; i < addresses.length; i++) {{
                try {{
                    var data = Memory.readByteArray(ptr(addresses[i]), size);
                    var hex = '';
                    var bytes = new Uint8Array(data);
                    for (var j = 0; j < bytes.length; j++) {{
                        hex += ('0' + bytes[j].toString(16)).slice(-2);
                    }}
                    if (hex === expected) matches.push(addresses[i]);
                }} catch (e) {{ }}
            }}
            send(JSON.stringify(matches));
            """
            
            result_data = []
            def on_message(message, data):
                if message['type'] == 'send':
                    result_data.append(message['payload'])
            
            script = _session.session.create_script(script_code)
            script.on('message', on_message)
            script.load()
            script.unload()
            
            if result_data:
                import json
                matches = json.loads(result_data[0])
                new_results.extend([int(a, 16) for a in matches])
        
        _session.scan_state.results = new_results
        _session.scan_state.last_values = {addr: value for addr in new_results}
        
        return {
            "success": True,
            "value": value,
            "remaining": len(new_results),
            "message": f"Narrowed to {len(new_results)} addresses."
        }
    
    except Exception as e:
        return {"error": f"Scan next failed: {str(e)}"}


@mcp.tool()
def scan_changed() -> Dict[str, Any]:
    """
    Find addresses where value has changed since last scan.
    
    Returns:
        Number of changed addresses.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if not _session.scan_state.scan_active:
        return {"error": "No active scan. Use scan_value() first."}
    
    try:
        value_type = _session.scan_state.value_type
        value_size = _get_value_size(value_type)
        
        addresses = [a for a in _session.scan_state.results if a in _session.scan_state.last_values]
        if not addresses:
            return {"success": True, "remaining": 0}
        
        expected_map = {}
        for addr in addresses:
            last_val = _session.scan_state.last_values[addr]
            if value_type == "string":
                expected_map[addr] = str(last_val).encode('utf-8').hex()
            else:
                expected_map[addr] = _pack_value(last_val, value_type).hex()
        
        batch_size = 1000
        new_results = []
        new_last_values = {}
        
        for batch_start in range(0, len(addresses), batch_size):
            batch = addresses[batch_start:batch_start + batch_size]
            addr_expected = ", ".join(f'["{hex(a)}", "{expected_map[a]}"]' for a in batch)
            
            script_code = f"""
            var pairs = [{addr_expected}];
            var size = {value_size};
            var changed = [];
            
            for (var i = 0; i < pairs.length; i++) {{
                try {{
                    var data = Memory.readByteArray(ptr(pairs[i][0]), size);
                    var hex = '';
                    var bytes = new Uint8Array(data);
                    for (var j = 0; j < bytes.length; j++) {{
                        hex += ('0' + bytes[j].toString(16)).slice(-2);
                    }}
                    if (hex !== pairs[i][1]) {{
                        changed.push({{address: pairs[i][0], hex: hex}});
                    }}
                }} catch (e) {{ }}
            }}
            send(JSON.stringify(changed));
            """
            
            result_data = []
            def on_message(message, data):
                if message['type'] == 'send':
                    result_data.append(message['payload'])
            
            script = _session.session.create_script(script_code)
            script.on('message', on_message)
            script.load()
            script.unload()
            
            if result_data:
                import json
                changed = json.loads(result_data[0])
                for c in changed:
                    addr = int(c['address'], 16)
                    try:
                        current_value = _unpack_value(bytes.fromhex(c['hex']), value_type)
                        new_results.append(addr)
                        new_last_values[addr] = current_value
                    except:
                        pass
        
        _session.scan_state.results = new_results
        _session.scan_state.last_values = new_last_values
        
        return {"success": True, "remaining": len(new_results)}
    
    except Exception as e:
        return {"error": f"Scan changed failed: {str(e)}"}


@mcp.tool()
def scan_unchanged() -> Dict[str, Any]:
    """
    Find addresses where value has NOT changed since last scan.
    
    Returns:
        Number of unchanged addresses.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if not _session.scan_state.scan_active:
        return {"error": "No active scan. Use scan_value() first."}
    
    try:
        value_type = _session.scan_state.value_type
        value_size = _get_value_size(value_type)
        
        addresses = [a for a in _session.scan_state.results if a in _session.scan_state.last_values]
        if not addresses:
            return {"success": True, "remaining": 0}
        
        expected_map = {}
        for addr in addresses:
            last_val = _session.scan_state.last_values[addr]
            if value_type == "string":
                expected_map[addr] = str(last_val).encode('utf-8').hex()
            else:
                expected_map[addr] = _pack_value(last_val, value_type).hex()
        
        batch_size = 1000
        new_results = []
        new_last_values = {}
        
        for batch_start in range(0, len(addresses), batch_size):
            batch = addresses[batch_start:batch_start + batch_size]
            addr_expected = ", ".join(f'["{hex(a)}", "{expected_map[a]}"]' for a in batch)
            
            script_code = f"""
            var pairs = [{addr_expected}];
            var size = {value_size};
            var unchanged = [];
            
            for (var i = 0; i < pairs.length; i++) {{
                try {{
                    var data = Memory.readByteArray(ptr(pairs[i][0]), size);
                    var hex = '';
                    var bytes = new Uint8Array(data);
                    for (var j = 0; j < bytes.length; j++) {{
                        hex += ('0' + bytes[j].toString(16)).slice(-2);
                    }}
                    if (hex === pairs[i][1]) {{
                        unchanged.push({{address: pairs[i][0], hex: hex}});
                    }}
                }} catch (e) {{ }}
            }}
            send(JSON.stringify(unchanged));
            """
            
            result_data = []
            def on_message(message, data):
                if message['type'] == 'send':
                    result_data.append(message['payload'])
            
            script = _session.session.create_script(script_code)
            script.on('message', on_message)
            script.load()
            script.unload()
            
            if result_data:
                import json
                unchanged = json.loads(result_data[0])
                for c in unchanged:
                    addr = int(c['address'], 16)
                    try:
                        current_value = _unpack_value(bytes.fromhex(c['hex']), value_type)
                        new_results.append(addr)
                        new_last_values[addr] = current_value
                    except:
                        pass
        
        _session.scan_state.results = new_results
        _session.scan_state.last_values = new_last_values
        
        return {"success": True, "remaining": len(new_results)}
    
    except Exception as e:
        return {"error": f"Scan unchanged failed: {str(e)}"}


@mcp.tool()
def scan_pattern(pattern: str, scan_regions: str = "r-x") -> Dict[str, Any]:
    """
    Scan for Array of Bytes (AoB) pattern.
    
    Args:
        pattern: Byte pattern like "89 47 44 ?? ?? 5B" (?? = wildcard)
        scan_regions: Memory protection to scan (default: "r-x" for code)
    
    Returns:
        List of matching addresses.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        frida_pattern = pattern.strip()
        
        script_code = f"""
        var results = [];
        var pattern = "{frida_pattern}";
        var ranges = Process.enumerateRanges("{scan_regions}");
        
        for (var i = 0; i < ranges.length && results.length < 1000; i++) {{
            try {{
                var matches = Memory.scanSync(ranges[i].base, ranges[i].size, pattern);
                for (var j = 0; j < matches.length && results.length < 1000; j++) {{
                    results.push({{address: matches[j].address.toString(), size: matches[j].size}});
                }}
            }} catch (e) {{ }}
        }}
        send(JSON.stringify(results));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        if not result_data:
            return {"error": "Pattern scan failed"}
        
        import json
        matches = json.loads(result_data[0])
        
        return {"success": True, "pattern": pattern, "found": len(matches), "matches": matches[:50]}
    
    except Exception as e:
        return {"error": f"Pattern scan failed: {str(e)}"}


@mcp.tool()
def get_scan_results(limit: int = 20) -> Dict[str, Any]:
    """
    Get current scan results with values.
    
    Args:
        limit: Maximum results to return (default: 20)
    
    Returns:
        List of addresses and their current values.
    """
    global _session
    
    if not _session.scan_state.scan_active:
        return {"error": "No active scan. Use scan_value() first."}
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        value_type = _session.scan_state.value_type
        value_size = _get_value_size(value_type)
        addresses = _session.scan_state.results[:limit]
        
        if not addresses:
            return {"total": len(_session.scan_state.results), "shown": 0, "results": []}
        
        addr_list = ", ".join(f'"{hex(a)}"' for a in addresses)
        
        script_code = f"""
        var addresses = [{addr_list}];
        var size = {value_size};
        var results = [];
        
        for (var i = 0; i < addresses.length; i++) {{
            try {{
                var data = Memory.readByteArray(ptr(addresses[i]), size);
                var hex = '';
                var bytes = new Uint8Array(data);
                for (var j = 0; j < bytes.length; j++) {{
                    hex += ('0' + bytes[j].toString(16)).slice(-2);
                }}
                results.push({{address: addresses[i], hex: hex}});
            }} catch (e) {{
                results.push({{address: addresses[i], error: e.toString()}});
            }}
        }}
        send(JSON.stringify(results));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        if not result_data:
            return {"error": "Failed to get results"}
        
        import json
        raw_results = json.loads(result_data[0])
        
        results = []
        for r in raw_results:
            if 'error' not in r:
                try:
                    current_value = _unpack_value(bytes.fromhex(r['hex']), value_type)
                    results.append({"address": r['address'], "value": current_value, "hex": r['hex']})
                except:
                    pass
        
        return {
            "total": len(_session.scan_state.results),
            "shown": len(results),
            "value_type": value_type,
            "results": results
        }
    
    except Exception as e:
        return {"error": f"Failed to get results: {str(e)}"}


@mcp.tool()
def clear_scan() -> Dict[str, Any]:
    """
    Clear current scan results and reset scan state.
    
    Returns:
        Confirmation message.
    """
    global _session
    _session.scan_state = ScanState()
    return {"success": True, "message": "Scan state cleared."}


# =============================================================================
# MODULE INFORMATION
# =============================================================================

@mcp.tool()
def list_modules() -> Dict[str, Any]:
    """
    List all loaded modules (DLLs/shared libraries).
    
    Returns:
        List of modules with base address, size, and path.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = """
        var modules = Process.enumerateModules();
        var result = modules.map(function(m) {
            return {name: m.name, base: m.base.toString(), size: m.size, path: m.path};
        });
        send(JSON.stringify(result));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        if not result_data:
            return {"error": "Failed to enumerate modules"}
        
        import json
        modules = json.loads(result_data[0])
        return {"count": len(modules), "modules": modules}
    
    except Exception as e:
        return {"error": f"Failed to list modules: {str(e)}"}


@mcp.tool()
def get_module_info(module_name: str) -> Dict[str, Any]:
    """
    Get detailed information about a specific module.
    
    Args:
        module_name: Name of the module (e.g., "game.dll")
    
    Returns:
        Module details including base, size, exports count.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = f"""
        var module = Process.findModuleByName("{module_name}");
        if (module) {{
            send(JSON.stringify({{
                name: module.name, base: module.base.toString(), size: module.size,
                path: module.path, imports: module.enumerateImports().length,
                exports: module.enumerateExports().length
            }}));
        }} else {{
            send(JSON.stringify({{error: "Module not found"}}));
        }}
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        import json
        return json.loads(result_data[0]) if result_data else {"error": "No response"}
    
    except Exception as e:
        return {"error": f"Failed to get module info: {str(e)}"}


@mcp.tool()
def get_module_exports(module_name: str, filter_name: str = "") -> Dict[str, Any]:
    """
    List exports from a module.
    
    Args:
        module_name: Name of the module
        filter_name: Optional filter for export names
    
    Returns:
        List of exports with name and address.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = f"""
        var module = Process.findModuleByName("{module_name}");
        if (module) {{
            var exports = module.enumerateExports();
            send(JSON.stringify(exports.map(function(e) {{
                return {{name: e.name, type: e.type, address: e.address.toString()}};
            }})));
        }} else {{
            send(JSON.stringify([]));
        }}
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        import json
        exports = json.loads(result_data[0]) if result_data else []
        
        if filter_name:
            exports = [e for e in exports if filter_name.lower() in e['name'].lower()]
        
        return {"module": module_name, "count": len(exports), "exports": exports[:100]}
    
    except Exception as e:
        return {"error": f"Failed to get exports: {str(e)}"}


@mcp.tool()
def get_module_imports(module_name: str, filter_name: str = "") -> Dict[str, Any]:
    """
    List imports for a module.
    
    Args:
        module_name: Name of the module
        filter_name: Optional filter for import names
    
    Returns:
        List of imports with name, module, and address.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = f"""
        var module = Process.findModuleByName("{module_name}");
        if (module) {{
            var imports = module.enumerateImports();
            send(JSON.stringify(imports.map(function(i) {{
                return {{name: i.name, module: i.module, type: i.type,
                        address: i.address ? i.address.toString() : null}};
            }})));
        }} else {{
            send(JSON.stringify([]));
        }}
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        import json
        imports = json.loads(result_data[0]) if result_data else []
        
        if filter_name:
            imports = [i for i in imports if filter_name.lower() in i['name'].lower()]
        
        return {"module": module_name, "count": len(imports), "imports": imports[:100]}
    
    except Exception as e:
        return {"error": f"Failed to get imports: {str(e)}"}


@mcp.tool()
def resolve_symbol(module_name: str, symbol_name: str) -> Dict[str, Any]:
    """
    Resolve a symbol to its address.
    
    Args:
        module_name: Name of the module containing the symbol
        symbol_name: Name of the symbol/function
    
    Returns:
        Address of the symbol.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = f"""
        var addr = Module.findExportByName("{module_name}", "{symbol_name}");
        send(JSON.stringify(addr ? {{address: addr.toString()}} : {{error: "Symbol not found"}}));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        import json
        result = json.loads(result_data[0]) if result_data else {"error": "No response"}
        result["module"] = module_name
        result["symbol"] = symbol_name
        return result
    
    except Exception as e:
        return {"error": f"Failed to resolve symbol: {str(e)}"}


# =============================================================================
# FUNCTION HOOKING
# =============================================================================

@mcp.tool()
def hook_function(address: str, on_enter: str = "", on_leave: str = "",
                  description: str = "") -> Dict[str, Any]:
    """
    Hook a function at the specified address.
    
    Args:
        address: Address to hook (hex string)
        on_enter: JavaScript code for onEnter (has access to 'args' array)
        on_leave: JavaScript code for onLeave (has access to 'retval')
        description: Optional description
    
    Returns:
        Hook status.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if address in _session.hooks:
        return {"error": f"Hook exists at {address}. Use unhook_function() first."}
    
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
        
        # Use empty statement if no code provided (comment would break JS syntax)
        on_enter_code = on_enter.strip() if on_enter else ""
        on_leave_code = on_leave.strip() if on_leave else ""
        
        script_code = f"""
        Interceptor.attach(ptr("{hex(addr)}"), {{
            onEnter: function(args) {{ {on_enter_code} }},
            onLeave: function(retval) {{ {on_leave_code} }}
        }});
        send("Hook installed");
        """
        
        def on_message(message, data):
            if message['type'] == 'error':
                logger.error(f"Hook error: {message}")
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        
        _session.hooks[address] = HookInfo(
            address=address, script=script, hook_type="intercept",
            description=description or f"Hook at {address}"
        )
        
        return {"success": True, "address": address, "message": f"Hook installed at {address}"}
    
    except Exception as e:
        return {"error": f"Failed to install hook: {str(e)}"}


@mcp.tool()
def unhook_function(address: str) -> Dict[str, Any]:
    """
    Remove a hook from an address.
    
    Args:
        address: Address to unhook
    
    Returns:
        Unhook status.
    """
    global _session
    
    if address not in _session.hooks:
        return {"error": f"No hook at {address}"}
    
    try:
        _session.hooks[address].script.unload()
        del _session.hooks[address]
        return {"success": True, "address": address, "message": f"Hook removed from {address}"}
    
    except Exception as e:
        return {"error": f"Failed to remove hook: {str(e)}"}


@mcp.tool()
def replace_function(address: str, return_value: Union[int, str] = 0) -> Dict[str, Any]:
    """
    Replace a function to always return a specific value.
    
    Args:
        address: Address of function to replace
        return_value: Value to return
    
    Returns:
        Replacement status.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if address in _session.hooks:
        return {"error": f"Hook exists at {address}. Use unhook_function() first."}
    
    try:
        addr = int(address, 16) if isinstance(address, str) and address.startswith("0x") else int(address)
        ret_val = int(return_value, 16) if isinstance(return_value, str) and return_value.startswith("0x") else int(return_value)
        
        script_code = f"""
        Interceptor.replace(ptr("{hex(addr)}"), new NativeCallback(function() {{
            return {ret_val};
        }}, 'int', []));
        send("Function replaced");
        """
        
        script = _session.session.create_script(script_code)
        script.on('message', lambda m, d: None)
        script.load()
        
        _session.hooks[address] = HookInfo(
            address=address, script=script, hook_type="replace",
            description=f"Returns {ret_val}"
        )
        
        return {"success": True, "address": address, "return_value": ret_val}
    
    except Exception as e:
        return {"error": f"Failed to replace function: {str(e)}"}


@mcp.tool()
def hook_native_function(address: str, calling_convention: str = "default",
                         arg_types: List[str] = None, return_type: str = "int",
                         on_enter: str = "", on_leave: str = "") -> Dict[str, Any]:
    """
    Hook a native function with explicit calling convention.
    
    Args:
        address: Address of function
        calling_convention: "default", "stdcall", "fastcall", "thiscall"
        arg_types: List of argument types
        return_type: Return type
        on_enter: JavaScript for onEnter
        on_leave: JavaScript for onLeave
    
    Returns:
        Hook status.
    """
    return hook_function(address, on_enter, on_leave, f"Native hook ({calling_convention})")


@mcp.tool()
def list_hooks() -> Dict[str, Any]:
    """
    List all active hooks.
    
    Returns:
        List of active hooks with addresses and descriptions.
    """
    hooks = [{"address": addr, "type": h.hook_type, "description": h.description}
             for addr, h in _session.hooks.items()]
    return {"count": len(hooks), "hooks": hooks}


@mcp.tool()
def intercept_module_function(module_name: str, function_name: str,
                              on_enter: str = "", on_leave: str = "") -> Dict[str, Any]:
    """
    Hook a function by module and function name.
    
    Args:
        module_name: Name of the module (e.g., "game.dll")
        function_name: Name of the exported function
        on_enter: JavaScript for onEnter
        on_leave: JavaScript for onLeave
    
    Returns:
        Hook status with resolved address.
    """
    result = resolve_symbol(module_name, function_name)
    if "error" in result:
        return result
    
    return hook_function(result["address"], on_enter, on_leave,
                        f"{module_name}!{function_name}")


# =============================================================================
# DEBUGGING
# =============================================================================

@mcp.tool()
def set_breakpoint(address: str, callback: str = "") -> Dict[str, Any]:
    """
    Set a software breakpoint at address.
    
    Args:
        address: Address for breakpoint
        callback: JavaScript code to execute when hit
    
    Returns:
        Breakpoint status.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if address in _session.breakpoints:
        return {"error": f"Breakpoint exists at {address}"}
    
    try:
        addr = int(address, 16) if address.startswith("0x") else int(address)
        callback_code = callback or "console.log('[BP] Hit at ' + this.context.pc);"
        
        script_code = f"""
        Interceptor.attach(ptr("{hex(addr)}"), {{
            onEnter: function(args) {{ {callback_code} }}
        }});
        send("Breakpoint set");
        """
        
        script = _session.session.create_script(script_code)
        script.on('message', lambda m, d: None)
        script.load()
        
        _session.breakpoints[address] = script
        return {"success": True, "address": address}
    
    except Exception as e:
        return {"error": f"Failed to set breakpoint: {str(e)}"}


@mcp.tool()
def remove_breakpoint(address: str) -> Dict[str, Any]:
    """
    Remove a breakpoint.
    
    Args:
        address: Address of breakpoint to remove
    
    Returns:
        Removal status.
    """
    global _session
    
    if address not in _session.breakpoints:
        return {"error": f"No breakpoint at {address}"}
    
    try:
        _session.breakpoints[address].unload()
        del _session.breakpoints[address]
        return {"success": True, "address": address}
    
    except Exception as e:
        return {"error": f"Failed to remove breakpoint: {str(e)}"}


@mcp.tool()
def list_breakpoints() -> Dict[str, Any]:
    """List all active breakpoints."""
    return {"count": len(_session.breakpoints), "breakpoints": list(_session.breakpoints.keys())}


@mcp.tool()
def read_registers() -> Dict[str, Any]:
    """
    Read CPU register values.
    
    Note: Full register context available in hook callbacks via 'this.context'.
    
    Returns:
        Basic thread and architecture info.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    try:
        script_code = """
        send(JSON.stringify({
            arch: Process.arch,
            platform: Process.platform,
            pointer_size: Process.pointerSize,
            thread_id: Process.getCurrentThreadId()
        }));
        """
        
        result_data = []
        def on_message(message, data):
            if message['type'] == 'send':
                result_data.append(message['payload'])
        
        script = _session.session.create_script(script_code)
        script.on('message', on_message)
        script.load()
        script.unload()
        
        import json
        result = json.loads(result_data[0]) if result_data else {}
        result["note"] = "Full registers available in hook via 'this.context'"
        return result
    
    except Exception as e:
        return {"error": f"Failed to read registers: {str(e)}"}


# =============================================================================
# SCRIPT MANAGEMENT
# =============================================================================

@mcp.tool()
def load_script(script_code: str, name: str = "custom") -> Dict[str, Any]:
    """
    Load a custom Frida JavaScript script.
    
    Args:
        script_code: JavaScript code to load
        name: Name to identify the script
    
    Returns:
        Load status.
    """
    global _session
    
    if not _session.is_attached():
        return {"error": "Not attached. Use attach() first."}
    
    if name in _session.custom_scripts:
        return {"error": f"Script '{name}' exists. Use unload_script() first."}
    
    try:
        script = _session.session.create_script(script_code)
        script.on('message', lambda m, d: logger.info(f"[{name}] {m}"))
        script.load()
        
        _session.custom_scripts[name] = script
        return {"success": True, "name": name}
    
    except Exception as e:
        return {"error": f"Failed to load script: {str(e)}"}


@mcp.tool()
def unload_script(name: str) -> Dict[str, Any]:
    """
    Unload a custom script.
    
    Args:
        name: Name of the script to unload
    
    Returns:
        Unload status.
    """
    global _session
    
    if name not in _session.custom_scripts:
        return {"error": f"Script '{name}' not found"}
    
    try:
        _session.custom_scripts[name].unload()
        del _session.custom_scripts[name]
        return {"success": True, "name": name}
    
    except Exception as e:
        return {"error": f"Failed to unload script: {str(e)}"}


@mcp.tool()
def call_rpc(name: str, method: str, args: List[Any] = None) -> Dict[str, Any]:
    """
    Call an RPC export from a loaded script.
    
    Args:
        name: Name of the loaded script
        method: RPC method name to call
        args: Arguments to pass
    
    Returns:
        RPC result.
    """
    global _session
    
    if name not in _session.custom_scripts:
        return {"error": f"Script '{name}' not found"}
    
    try:
        script = _session.custom_scripts[name]
        rpc_method = getattr(script.exports, method)
        result = rpc_method(*(args or []))
        return {"success": True, "method": method, "result": result}
    
    except AttributeError:
        return {"error": f"RPC method '{method}' not found"}
    except Exception as e:
        return {"error": f"RPC call failed: {str(e)}"}


# =============================================================================
# SCREENSHOT & WINDOW TOOLS
# =============================================================================

@mcp.tool()
def list_windows(filter_name: str = "") -> Dict[str, Any]:
    """
    List all visible windows.
    
    Args:
        filter_name: Optional filter to match window titles (case-insensitive)
    
    Returns:
        List of windows with handle, title, and associated PID.
    """
    if not SCREENSHOT_AVAILABLE:
        return {"error": "Screenshot support not available. Install: pip install pywin32 pillow"}
    
    windows = []
    
    def enum_callback(hwnd, _):
        if win32gui.IsWindowVisible(hwnd):
            title = win32gui.GetWindowText(hwnd)
            if title:
                if filter_name and filter_name.lower() not in title.lower():
                    return True
                try:
                    _, pid = win32process.GetWindowThreadProcessId(hwnd)
                    rect = win32gui.GetWindowRect(hwnd)
                    width = rect[2] - rect[0]
                    height = rect[3] - rect[1]
                    if width > 0 and height > 0:
                        windows.append({
                            "hwnd": hwnd,
                            "title": title,
                            "pid": pid,
                            "x": rect[0],
                            "y": rect[1],
                            "width": width,
                            "height": height
                        })
                except:
                    pass
        return True
    
    try:
        win32gui.EnumWindows(enum_callback, None)
        return {"count": len(windows), "windows": windows}
    except Exception as e:
        return {"error": f"Failed to enumerate windows: {str(e)}"}


@mcp.tool()
def screenshot_window(target: Union[str, int], save_path: str = "") -> Dict[str, Any]:
    """
    Take a screenshot of a specific window.
    
    Args:
        target: Window title (string) or HWND handle (integer)
        save_path: Optional path to save the screenshot (PNG). If empty, returns base64.
    
    Returns:
        Screenshot info with base64 data or saved file path.
    """
    if not SCREENSHOT_AVAILABLE:
        return {"error": "Screenshot support not available. Install: pip install pywin32 pillow"}
    
    try:
        # Find the window
        hwnd = None
        if isinstance(target, int):
            hwnd = target
        else:
            def find_window(h, _):
                nonlocal hwnd
                if win32gui.IsWindowVisible(h):
                    title = win32gui.GetWindowText(h)
                    if title and target.lower() in title.lower():
                        hwnd = h
                        return False
                return True
            win32gui.EnumWindows(find_window, None)
        
        if not hwnd:
            return {"error": f"Window not found: {target}"}
        
        # Get window dimensions
        rect = win32gui.GetWindowRect(hwnd)
        width = rect[2] - rect[0]
        height = rect[3] - rect[1]
        
        if width <= 0 or height <= 0:
            return {"error": "Window has invalid dimensions"}
        
        # Capture the window
        hwnd_dc = win32gui.GetWindowDC(hwnd)
        mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
        save_dc = mfc_dc.CreateCompatibleDC()
        
        bitmap = win32ui.CreateBitmap()
        bitmap.CreateCompatibleBitmap(mfc_dc, width, height)
        save_dc.SelectObject(bitmap)
        
        # Try PrintWindow first (works for most windows)
        result = ctypes.windll.user32.PrintWindow(hwnd, save_dc.GetSafeHdc(), 2)
        
        if result == 0:
            # Fallback to BitBlt
            save_dc.BitBlt((0, 0), (width, height), mfc_dc, (0, 0), win32con.SRCCOPY)
        
        # Convert to PIL Image
        bmp_info = bitmap.GetInfo()
        bmp_str = bitmap.GetBitmapBits(True)
        
        img = Image.frombuffer(
            'RGB',
            (bmp_info['bmWidth'], bmp_info['bmHeight']),
            bmp_str, 'raw', 'BGRX', 0, 1
        )
        
        # Cleanup
        win32gui.DeleteObject(bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)
        
        # Save or return base64
        if save_path:
            img.save(save_path, 'PNG')
            return {
                "success": True,
                "path": save_path,
                "width": width,
                "height": height,
                "window_title": win32gui.GetWindowText(hwnd)
            }
        else:
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            return {
                "success": True,
                "width": width,
                "height": height,
                "window_title": win32gui.GetWindowText(hwnd),
                "image_base64": img_base64,
                "format": "png"
            }
    
    except Exception as e:
        return {"error": f"Screenshot failed: {str(e)}"}


@mcp.tool()
def screenshot_screen(save_path: str = "", region: List[int] = None) -> Dict[str, Any]:
    """
    Take a screenshot of the entire screen or a region.
    
    Args:
        save_path: Optional path to save the screenshot (PNG). If empty, returns base64.
        region: Optional [x, y, width, height] to capture specific region.
    
    Returns:
        Screenshot info with base64 data or saved file path.
    """
    if not SCREENSHOT_AVAILABLE:
        return {"error": "Screenshot support not available. Install: pip install pywin32 pillow"}
    
    try:
        # Get screen dimensions
        if region:
            x, y, width, height = region
        else:
            x, y = 0, 0
            width = ctypes.windll.user32.GetSystemMetrics(0)
            height = ctypes.windll.user32.GetSystemMetrics(1)
        
        # Capture screen
        hwnd = win32gui.GetDesktopWindow()
        hwnd_dc = win32gui.GetWindowDC(hwnd)
        mfc_dc = win32ui.CreateDCFromHandle(hwnd_dc)
        save_dc = mfc_dc.CreateCompatibleDC()
        
        bitmap = win32ui.CreateBitmap()
        bitmap.CreateCompatibleBitmap(mfc_dc, width, height)
        save_dc.SelectObject(bitmap)
        
        save_dc.BitBlt((0, 0), (width, height), mfc_dc, (x, y), win32con.SRCCOPY)
        
        # Convert to PIL Image
        bmp_info = bitmap.GetInfo()
        bmp_str = bitmap.GetBitmapBits(True)
        
        img = Image.frombuffer(
            'RGB',
            (bmp_info['bmWidth'], bmp_info['bmHeight']),
            bmp_str, 'raw', 'BGRX', 0, 1
        )
        
        # Cleanup
        win32gui.DeleteObject(bitmap.GetHandle())
        save_dc.DeleteDC()
        mfc_dc.DeleteDC()
        win32gui.ReleaseDC(hwnd, hwnd_dc)
        
        # Save or return base64
        if save_path:
            img.save(save_path, 'PNG')
            return {
                "success": True,
                "path": save_path,
                "width": width,
                "height": height
            }
        else:
            buffer = io.BytesIO()
            img.save(buffer, format='PNG')
            img_base64 = base64.b64encode(buffer.getvalue()).decode('utf-8')
            
            return {
                "success": True,
                "width": width,
                "height": height,
                "image_base64": img_base64,
                "format": "png"
            }
    
    except Exception as e:
        return {"error": f"Screenshot failed: {str(e)}"}


@mcp.tool()
def send_key_to_window(target: Union[str, int], key: str) -> Dict[str, Any]:
    """
    Send a keystroke to a specific window.
    
    Args:
        target: Window title (string) or HWND handle (integer)
        key: Key to send (e.g., "a", "enter", "space", "up", "down", "left", "right")
    
    Returns:
        Success status.
    """
    if not SCREENSHOT_AVAILABLE:
        return {"error": "Window control not available. Install: pip install pywin32"}
    
    # Key code mapping
    key_codes = {
        "enter": 0x0D, "return": 0x0D,
        "space": 0x20,
        "up": 0x26, "down": 0x28, "left": 0x25, "right": 0x27,
        "escape": 0x1B, "esc": 0x1B,
        "tab": 0x09,
        "backspace": 0x08,
        "w": 0x57, "a": 0x41, "s": 0x53, "d": 0x44,
        "r": 0x52, "q": 0x51, "e": 0x45,
        "1": 0x31, "2": 0x32, "3": 0x33, "4": 0x34, "5": 0x35,
    }
    
    try:
        # Find the window
        hwnd = None
        if isinstance(target, int):
            hwnd = target
        else:
            def find_window(h, _):
                nonlocal hwnd
                if win32gui.IsWindowVisible(h):
                    title = win32gui.GetWindowText(h)
                    if title and target.lower() in title.lower():
                        hwnd = h
                        return False
                return True
            win32gui.EnumWindows(find_window, None)
        
        if not hwnd:
            return {"error": f"Window not found: {target}"}
        
        # Get key code
        key_lower = key.lower()
        if key_lower in key_codes:
            vk_code = key_codes[key_lower]
        elif len(key) == 1:
            vk_code = ord(key.upper())
        else:
            return {"error": f"Unknown key: {key}"}
        
        # Bring window to foreground
        win32gui.SetForegroundWindow(hwnd)
        
        import time
        time.sleep(0.1)
        
        # Send key using PostMessage
        WM_KEYDOWN = 0x0100
        WM_KEYUP = 0x0101
        
        win32gui.PostMessage(hwnd, WM_KEYDOWN, vk_code, 0)
        time.sleep(0.05)
        win32gui.PostMessage(hwnd, WM_KEYUP, vk_code, 0)
        
        return {
            "success": True,
            "window": win32gui.GetWindowText(hwnd),
            "key_sent": key
        }
    
    except Exception as e:
        return {"error": f"Failed to send key: {str(e)}"}


@mcp.tool()
def focus_window(target: Union[str, int]) -> Dict[str, Any]:
    """
    Bring a window to the foreground.
    
    Args:
        target: Window title (string) or HWND handle (integer)
    
    Returns:
        Success status.
    """
    if not SCREENSHOT_AVAILABLE:
        return {"error": "Window control not available. Install: pip install pywin32"}
    
    try:
        hwnd = None
        if isinstance(target, int):
            hwnd = target
        else:
            def find_window(h, _):
                nonlocal hwnd
                if win32gui.IsWindowVisible(h):
                    title = win32gui.GetWindowText(h)
                    if title and target.lower() in title.lower():
                        hwnd = h
                        return False
                return True
            win32gui.EnumWindows(find_window, None)
        
        if not hwnd:
            return {"error": f"Window not found: {target}"}
        
        win32gui.SetForegroundWindow(hwnd)
        
        return {
            "success": True,
            "window": win32gui.GetWindowText(hwnd),
            "hwnd": hwnd
        }
    
    except Exception as e:
        return {"error": f"Failed to focus window: {str(e)}"}


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point for MCP server."""
    import sys
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        stream=sys.stderr
    )
    
    logger.info("Starting Frida Game Hacking MCP server...")
    
    if FRIDA_AVAILABLE:
        logger.info(f"Frida version: {frida.__version__}")
    else:
        logger.warning("Frida not installed! Run: pip install frida frida-tools")
    
    try:
        mcp.run()
    except KeyboardInterrupt:
        logger.info("Server stopped")
        if _session.is_attached():
            detach()


if __name__ == "__main__":
    main()

