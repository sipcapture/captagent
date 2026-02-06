# Implementation Summary: Header Filtering Enhancement

## Issue #284: Make captagent filter on headers

### Overview
This implementation extends captagent's header filtering capabilities to support matching any SIP header, not just the pre-configured custom header. Users can now use `header_check()` and `header_regexp_match()` to filter on arbitrary SIP headers.

### Changes Made

#### 1. **New Function: `find_header_value()` in parser_sip.c**
   - **Location**: `src/modules/protocol/sip/parser_sip.c` (lines ~724-813)
   - **Purpose**: Searches through a SIP message for a header by name
   - **Features**:
     - Case-insensitive header name matching
     - Handles whitespace trimming
     - Stops at message body boundary
     - Returns header value in a `str` structure
   - **Signature**: `int find_header_value(const char *message, unsigned int msg_len, const char *header_name, str *header_value)`
   - **Returns**: 0 on success, -1 if header not found

#### 2. **Updated Function: `w_header_check()` in protocol_sip.c**
   - **Location**: `src/modules/protocol/sip/protocol_sip.c` (lines 192-223)
   - **Changes**:
     - Maintains backward compatibility with User-Agent and custom header matching
     - Added fallback to search for any header by name using `find_header_value()`
     - Supports starting string match with `startwith()` function
   - **Usage Examples**:
     ```c
     // Old way (still works)
     header_check("User-Agent", "snomD785")
     header_check("custom", "value")
     
     // New way (arbitrary headers)
     header_check("X-Serialnumber", "000413924E28")
     header_check("Contact", "sip:666@192.168.250.108")
     header_check("Accept", "application/sdp")
     ```

#### 3. **Updated Function: `w_header_reg_match()` in protocol_sip.c**
   - **Location**: `src/modules/protocol/sip/protocol_sip.c` (lines 240-284)
   - **Changes**:
     - Maintains backward compatibility with existing PCRE matches
     - Added regex matching support for any header by name
     - Uses `find_header_value()` for header discovery
   - **Usage Examples**:
     ```c
     // Regex matching on arbitrary headers
     header_regexp_match("X-Serialnumber", "pattern1")
     header_regexp_match("User-Agent", "pattern2")
     ```

#### 4. **Updated Header File: parser_sip.h**
   - Added function declaration for `find_header_value()`

#### 5. **Added Include: strings.h**
   - Added `#include <strings.h>` for `strncasecmp()` function

### How It Works

#### Header Discovery Process
1. User calls `header_check("X-Serialnumber", "000413924E28")` in capture plan
2. Function checks param1:
   - If "User-Agent", uses pre-parsed `_m->sip.userAgent`
   - If "custom", uses pre-configured custom header
   - Otherwise, calls `find_header_value()` to search raw message
3. `find_header_value()` searches through message line-by-line:
   - Performs case-insensitive comparison of header names
   - Extracts header value with whitespace trimmed
   - Returns the value in a `str` structure
4. Comparison is performed using `startwith()` for prefix matching (original behavior)

### Testing Scenarios

#### Test Case 1: Basic Header Matching
```c
// SIP Message with custom header
X-Serialnumber: 000413924E28
User-Agent: snomD785/10.1.84.12

// Should match:
if(header_check("X-Serialnumber", "000413924E28")) { ... }
if(header_check("User-Agent", "snom")) { ... }  // partial match
```

#### Test Case 2: Case-Insensitive Matching
```c
// Header in message: "X-SerialNumber: value"
// Should match all:
header_check("X-SerialNumber", "value")
header_check("x-serialnumber", "value")  // lowercase
header_check("X-SERIALNUMBER", "value")  // uppercase
```

#### Test Case 3: PCRE Regex Matching
```c
// With PCRE configured:
if(header_regexp_match("X-Serialnumber", "pattern_name")) { ... }
if(header_regexp_match("Contact", "pattern_name")) { ... }
```

### Backward Compatibility
- ✅ Existing `header_check("User-Agent", ...)` calls still work
- ✅ Existing `header_check("custom", ...)` calls still work
- ✅ Existing `header_regexp_match()` calls still work
- ✅ Pre-configured custom headers still parsed and used optimally

### Implementation Details

#### Supported Header Types
- Standard SIP headers: Via, From, To, Contact, CSeq, Call-ID, etc.
- Custom X- headers: X-Serialnumber, X-Custom-Header, etc.
- Any RFC 3261 compliant header name

#### Limitations
- Header values longer than MAX_PARSE_LEN (256 bytes) are rejected
- Matching is performed on header value only (not the full header line)
- Multi-line headers (folded headers) are treated as separate lines

### Example Configuration
```xml
<!-- In capture plan -->
if(header_check("X-Serialnumber", "000413924E28")) {
    if(!send_hep("homer1")) {
        clog("ERROR", "Failed to send HEP");
    }
} else {
    if(!send_hep("homer2")) {
        clog("ERROR", "Failed to send HEP");
    }
}
```

### Performance Considerations
- For User-Agent and pre-configured custom headers: O(1) lookup (uses pre-parsed data)
- For arbitrary headers: O(n) header search where n = number of lines in SIP message
- Typical SIP INVITE: 10-30 header lines = minimal overhead

### Future Enhancements
- Support for multi-line (folded) header values
- Support for header parameter extraction (e.g., `Contact: <...>; param=value`)
- Support for quoted header values
- Caching of frequently searched headers
