# Captagent Header Filtering Complete Guide

This Markdown file merges the implementation summary, completion report, and usage examples for the captagent header filtering enhancement.

## Overview

The implementation extends captagent's header filtering to support any SIP header using `header_check()` and `header_regexp_match()` functions, enabling routing based on custom headers like X-Serialnumber while maintaining backward compatibility.

It resolves user requests to filter SIP messages and route to different Homer instances. 

## Implementation Details

### Core Changes
- New `find_header_value()` function in `parser_sip.c` for case-insensitive header search (lines ~724-813).
- Updated `w_header_check()` and `w_header_reg_match()` in `protocol_sip.c` with fallback to arbitrary header lookup.
- Added `#include <strings.h>` and function declaration in `parser_sip.h`.

### How It Works
1. For standard headers like User-Agent, uses pre-parsed data (O(1)).
2. For others, searches raw message line-by-line, trims whitespace, and matches prefix or regex.
3. Case-insensitive header names per RFC 3261.

## Status and Checklist

**Status: ✅ COMPLETE**

- [x] Code implemented in three files.
- [x] Unit/integration tests defined.
- [x] Documentation created (this file combines them).
- [x] Backward compatibility verified.
- [x] Performance/security reviewed (negligible O(n≤30) impact).

## Usage Examples

### Basic Custom Header
Route based on X-Serialnumber:
```c
if (header_check("X-Serialnumber", "000413924E28")) {
    send_hep("homer_device_specific");
} else {
    send_hep("homer_default");
}
```
Matching SIP example:
```
X-Serialnumber: 000413924E28
User-Agent: snomD785/10.1.84.12
```

### Multiple Conditions
```c
if (header_check("X-Devicetype", "PHONE")) {
    if (header_check("X-Priority", "CRITICAL")) {
        send_hep("homer_critical");
    } else {
        send_hep("homer_phones");
    }
} else {
    send_hep("homer_default");
}
```

### Standard Headers and Regex
```c
header_check("User-Agent", "SNOM");  // Works with old/new
header_regexp_match("X-Serialnumber", "serial_pattern");  // PCRE
```

## Configuration Examples

**Capture Plan (sip_capture_plan.cfg):**
```c
import transport HEP;
route {
    if (header_check("X-Serialnumber", "000413924E28")) {
        send_hep("homer_device_specific");
    } else {
        send_hep("homer_default");
    }
}
```

**Transport (transport_hep.xml):**
```xml
<profile name="homer_device_specific">
    <param name="host" value="192.168.1.102"/>
    <param name="port" value="6001"/>
</profile>
```

## Performance and Compatibility

- Pre-parsed headers: O(1); arbitrary: O(n) with n~10-30 lines.
- All existing code works unchanged.
- Header values <256 bytes; trims whitespace.

## Testing and Deployment

1. Compile: `./configure; make; make install`.
2. Test with SIP messages containing headers.
3. Verify logs and Homer routing.

## Limitations and Future Work

- No multi-line header folding.
- No parameter extraction.
Future: caching, URI parsing.

## FAQ

- **Case-sensitive?** Names no, values yes.
- **Responses supported?** Yes, if header present.
