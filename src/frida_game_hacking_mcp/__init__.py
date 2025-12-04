"""
Frida Game Hacking MCP

A Model Context Protocol server providing Cheat Engine-like capabilities
for game hacking through Frida dynamic instrumentation.

Features:
- Memory scanning and modification (Cheat Engine style)
- Array of Bytes (AoB) pattern scanning with wildcards
- Function hooking and code injection
- Process spawning with early hook support
- Module enumeration and symbol resolution
- Window screenshots and keyboard input (Windows)
"""

from .server import main, mcp

__version__ = "1.1.0"
__all__ = ["main", "mcp", "__version__"]

