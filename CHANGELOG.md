# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2025-12-04

### Added
- **Window Interaction Tools** (Windows only):
  - `list_windows` - Enumerate visible windows with HWND, title, PID, dimensions
  - `screenshot_window` - Capture specific window to PNG file or base64
  - `screenshot_screen` - Capture full screen or region
  - `send_key_to_window` - Send keystrokes to target window (uses SendInput)
  - `focus_window` - Bring window to foreground
- New dependencies: `pywin32` (Windows), `pillow`

### Fixed
- Hook function JavaScript syntax issue with empty callbacks

## [1.0.0] - 2025-12-04

### Added
- Initial release with 37 tools across 7 categories
- **Process Management**: `list_processes`, `attach`, `detach`, `spawn`, `resume`, `get_session_info`
- **Memory Operations**: Full Cheat Engine-style scanning workflow
  - `scan_value` - Initial exact value scan
  - `scan_next` - Narrow results with new value
  - `scan_changed` - Find changed values
  - `scan_unchanged` - Find unchanged values
  - `scan_pattern` - Array of Bytes (AoB) with wildcards
  - `read_memory`, `write_memory` - Direct memory access
  - `list_memory_regions` - Memory map enumeration
- **Module Information**: `list_modules`, `get_module_info`, `get_module_exports`, `get_module_imports`, `resolve_symbol`
- **Function Hooking**: Full Interceptor support
  - `hook_function` - Hook with onEnter/onLeave
  - `unhook_function` - Remove hooks
  - `replace_function` - Replace return values
  - `hook_native_function` - Hook with calling conventions
  - `intercept_module_function` - Hook by module!function name
- **Debugging**: `set_breakpoint`, `remove_breakpoint`, `list_breakpoints`, `read_registers`
- **Script Management**: `load_script`, `unload_script`, `call_rpc`
- Cross-platform support (Windows, Linux, macOS)
- Example documentation for common use cases

