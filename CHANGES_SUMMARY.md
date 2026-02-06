# Implementation Summary for Issue #284

## Overview
This implementation adds support for filtering SIP messages based on arbitrary header values, allowing users to route calls to different Homer instances based on specific header content.

## Files Modified

### 1. `/workspaces/captagent/src/modules/protocol/sip/parser_sip.c`
**Location**: Lines 1-10 and 720-813

**Changes Made**:
- **Added include**: `#include <strings.h>` for `strncasecmp()` function (line 9)
- **Added function**: `find_header_value()` (lines 724-813)
  - Searches for a header by name in a SIP message
  - Case-insensitive header name matching
  - Handles whitespace trimming
  - Returns header value in a `str` structure
  - Returns 0 on success, -1 if header not found

### 2. `/workspaces/captagent/src/modules/protocol/sip/protocol_sip.c`
**Location**: Lines 192-290

**Changes Made**:
- **Updated function**: `w_header_check()` (lines 192-223)
  - Maintains backward compatibility with User-Agent and custom headers
  - Added fallback to use `find_header_value()` for arbitrary headers
  - Now supports any SIP header name
  
- **Updated function**: `w_header_reg_match()` (lines 240-284)
  - Updated to support PCRE regex matching on arbitrary headers
  - Maintains backward compatibility with existing regex matches
  - Uses `find_header_value()` for dynamic header lookup

### 3. `/workspaces/captagent/src/modules/protocol/sip/parser_sip.h`
**Location**: Line 28

**Changes Made**:
- **Added declaration**: `int find_header_value(const char *message, unsigned int msg_len, const char *header_name, str *header_value);`

## Key Features

### 1. Arbitrary Header Filtering
Users can now filter on any SIP header using the standard `header_check()` function:
```c
header_check("X-Serialnumber", "000413924E28")
header_check("Accept", "application/sdp")
header_check("Contact", "<sip:666@192.168.250.108>")
```

### 2. Case-Insensitive Header Matching
Header names are matched case-insensitively per RFC 3261:
```c
header_check("X-SerialNumber", "value")  // Exact case
header_check("x-serialnumber", "value")  // Lowercase - also matches
header_check("X-SERIALNUMBER", "value")  // Uppercase - also matches
```

### 3. PCRE Regex Support
When PCRE is enabled, regex patterns can match any header:
```c
header_regexp_match("X-Serialnumber", "pattern_name")
```

### 4. Full Backward Compatibility
All existing code continues to work without modification:
```c
header_check("User-Agent", "snom")           // Still works
header_check("custom", "value")              // Still works
header_regexp_match("body", "pattern")       // Still works
```

## Technical Implementation Details

### Header Discovery Algorithm
1. Search message header section line by line
2. For each line, check if header name matches (case-insensitive)
3. If match found, extract and trim header value
4. Return value in `str` structure

### Performance Characteristics
- **Pre-configured custom headers**: O(1) - uses pre-parsed data
- **User-Agent header**: O(1) - uses pre-parsed data  
- **Arbitrary headers**: O(n) where n = number of header lines (typically 10-30)
- **Overall impact**: Negligible, as SIP messages are small

### Constraints
- Header values must be < 256 bytes (MAX_PARSE_LEN)
- Folded headers (multi-line) treated as separate lines
- Matching is always case-sensitive for header values

## Testing Recommendations

### Unit Tests
1. Test with various SIP header formats
2. Test case-insensitive header name matching
3. Test whitespace trimming
4. Test edge cases (empty values, long values)

### Integration Tests
1. Route test calls with specific headers through capture plan
2. Verify correct routing to Homer instances
3. Test backward compatibility with existing configurations
4. Test with PCRE regex patterns

### Example Test Case
```c
// SIP Message
INVITE sip:100@192.168.1.1 SIP/2.0
X-Serialnumber: 000413924E28

// Capture Plan
if (header_check("X-Serialnumber", "000413924E28")) {
    send_hep("homer_device1");
}

// Expected: Message routed to homer_device1
```

## Compilation Instructions

```bash
cd /workspaces/captagent
./configure
make
make install
```

## Rollback Instructions

If any issues arise, revert to the original code:
```bash
git checkout -- src/modules/protocol/sip/parser_sip.c
git checkout -- src/modules/protocol/sip/protocol_sip.c
git checkout -- src/modules/protocol/sip/parser_sip.h
```

## Verification Checklist

- [x] Added `find_header_value()` function
- [x] Updated `w_header_check()` to support arbitrary headers
- [x] Updated `w_header_reg_match()` to support arbitrary headers
- [x] Added necessary includes (strings.h)
- [x] Added function declarations in header file
- [x] Maintained backward compatibility
- [x] Proper error handling
- [x] Code follows existing style conventions
- [x] Comprehensive documentation created

## Related Documentation

- `IMPLEMENTATION_SUMMARY.md` - Detailed technical documentation
- `HEADER_FILTERING_USAGE.md` - Practical usage examples
- `test_implementation.py` - Test case definitions

## Future Enhancements

1. Support for folded (multi-line) headers
2. Support for header parameter extraction
3. Support for quoted header values
4. Caching of frequently searched headers
5. Performance optimization for repeated header lookups

## Support and Questions

For questions or issues regarding this implementation, refer to issue #284 in the GitHub repository.
