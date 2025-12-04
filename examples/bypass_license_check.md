# Example: Bypass License Check

This example demonstrates how to bypass a software license check using function hooking.

## Scenario

A software has a `CheckLicense()` function that returns 1 for valid license and 0 for invalid. You want to make it always return 1.

## Method 1: Replace Function Return Value

```
> attach("software.exe")
{"success": true}

# Find the license check function
> get_module_exports("software.exe", "License")
{
  "exports": [
    {"name": "CheckLicense", "address": "0x401234"},
    {"name": "ValidateLicense", "address": "0x401300"}
  ]
}

# Replace the function to always return 1 (success)
> replace_function("0x401234", 1)
{
  "success": true,
  "address": "0x401234",
  "return_value": 1
}
```

## Method 2: Hook and Modify Return Value

```
# More flexible - can log and conditionally modify
> hook_function("0x401234",
    on_enter="console.log('[LICENSE] Check called');",
    on_leave="console.log('[LICENSE] Original result: ' + retval); retval.replace(1);")
```

## Method 3: NOP the Check (Permanent)

```
# Find the conditional jump after the check
> scan_pattern("74 05 E8 ?? ?? ?? ??", "r-x")  # JE followed by CALL
{
  "found": 1,
  "matches": [{"address": "0x401500"}]
}

# NOP the conditional jump (74 05 -> 90 90)
> write_memory("0x401500", "90 90")
{
  "success": true,
  "bytes_written": 2
}
```

## Method 4: Early Hook with Spawn

```
# Start software suspended to hook before license check runs
> spawn("C:/Program Files/Software/software.exe")
{
  "success": true,
  "pid": 5678,
  "state": "suspended"
}

# Install hook
> replace_function("0x401234", 1)

# Resume execution
> resume()
```

## Finding the License Function

If the function isn't exported:

1. **String search**: Look for error messages
   ```
   > scan_pattern("4C 69 63 65 6E 73 65", "r--")  # "License"
   ```

2. **API hooking**: Hook Windows crypto/network APIs
   ```
   > intercept_module_function("advapi32.dll", "CryptDecrypt",
       on_enter="console.log('Crypto called from: ' + this.returnAddress);")
   ```

3. **Trace execution**: Set breakpoints and step through

