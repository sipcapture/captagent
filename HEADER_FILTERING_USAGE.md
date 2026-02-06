# Captagent Header Filtering - Usage Examples

## Issue #284 Solution

This document provides practical examples of how to use the new header filtering capabilities in captagent.

## Problem Statement (from Issue #284)

Users wanted to filter SIP messages based on custom header values (like `X-Serialnumber`) and route them to different Homer instances based on the header content.

Previously, only pre-configured custom headers could be filtered. Now, any SIP header can be matched.

## Solution Overview

The solution adds two new capabilities to the existing `header_check()` and `header_regexp_match()` functions:

1. **Dynamic header lookup**: Find any header by name in the SIP message
2. **Case-insensitive matching**: Header names are matched case-insensitively
3. **Backward compatibility**: Existing code continues to work

## Usage Examples

### Example 1: Basic Custom Header Filtering

**Scenario**: Route calls based on X-Serialnumber header

```xml
<!-- In your capture plan (e.g., sip_capture_plan.cfg) -->
if (header_check("X-Serialnumber", "000413924E28")) {
    clog("ERROR", "Found call from device 000413924E28");
    if(!send_hep("homer_device_specific")) {
        clog("ERROR", "Error sending HEP!!!!");
    }
} else {
    if(!send_hep("homer_default")) {
        clog("ERROR", "Error sending HEP!!!!");
    }
}
```

**Matching SIP Message**:
```
INVITE sip:100@192.168.1.1 SIP/2.0
Via: SIP/2.0/UDP 192.168.250.108:49431
From: <sip:666@192.168.250.108>;tag=123
To: <sip:100@192.168.1.1>
Call-ID: 12345@192.168.250.108
CSeq: 1 INVITE
Max-Forwards: 70
User-Agent: snomD785/10.1.84.12
Contact: <sip:666@192.168.250.108:49431;transport=tcp>
X-Serialnumber: 000413924E28
Accept: application/sdp
```

### Example 2: Multiple Header Conditions

**Scenario**: Route based on multiple header values

```xml
if (header_check("X-Devicetype", "PHONE")) {
    if (header_check("X-Priority", "CRITICAL")) {
        if(!send_hep("homer_critical")) {
            clog("ERROR", "Critical call routing failed");
        }
    } else {
        if(!send_hep("homer_phones")) {
            clog("ERROR", "Phone call routing failed");
        }
    }
} else if (header_check("X-Devicetype", "SOFT_CLIENT")) {
    if(!send_hep("homer_soft_clients")) {
        clog("ERROR", "Soft client routing failed");
    }
} else {
    if(!send_hep("homer_default")) {
        clog("ERROR", "Default routing failed");
    }
}
```

### Example 3: Standard Header Filtering

**Scenario**: Filter based on standard SIP headers

```xml
/* Route based on Accept header */
if (header_check("Accept", "application/sdp")) {
    clog("ERROR", "Call supports SDP");
    if(!send_hep("homer_sdp_capable")) {
        clog("ERROR", "Error sending HEP!!!!");
    }
}

/* Route based on User-Agent */
if (header_check("User-Agent", "SNOM")) {
    clog("ERROR", "Call from SNOM device");
    if(!send_hep("homer_snom_devices")) {
        clog("ERROR", "Error sending HEP!!!!");
    }
}

/* Traditional way still works */
if (header_check("User-Agent", "Grandstream")) {
    if(!send_hep("homer_grandstream")) {
        clog("ERROR", "Error sending HEP!!!!");
    }
}
```

### Example 4: PCRE Regex Matching (with PCRE enabled)

**Scenario**: Use regex patterns to match headers

```xml
/* Configure regex pattern in protocol_sip section */
<param name="regexp-name" value="serial_pattern"/>
<param name="regexp-value" value="[0-9A-F]{12}"/>  <!-- 12 hex digits -->

<!-- Use in capture plan -->
if (header_regexp_match("X-Serialnumber", "serial_pattern")) {
    clog("ERROR", "Valid serial number format found");
    if(!send_hep("homer_valid_serials")) {
        clog("ERROR", "Error sending HEP!!!!");
    }
}
```

### Example 5: Case-Insensitive Header Names

**Scenario**: Match headers regardless of case

```xml
<!-- All of these will match the same header "X-Serialnumber" -->
if (header_check("X-Serialnumber", "value")) { ... }      /* Exact case */
if (header_check("x-serialnumber", "value")) { ... }      /* Lowercase */
if (header_check("X-SERIALNUMBER", "value")) { ... }      /* Uppercase */
if (header_check("X-SerialNumber", "value")) { ... }      /* Mixed case */
```

## Transport Configuration

**Example transport configuration** (`transport_hep.xml`):

```xml
<config name="transport_hep">
    <profile name="homer1">
        <param name="host" value="192.168.1.100"/>
        <param name="port" value="6001"/>
        <param name="proto" value="UDP"/>
    </profile>
    
    <profile name="homer2">
        <param name="host" value="192.168.1.101"/>
        <param name="port" value="6001"/>
        <param name="proto" value="UDP"/>
    </profile>
    
    <profile name="homer_device_specific">
        <param name="host" value="192.168.1.102"/>
        <param name="port" value="6001"/>
        <param name="proto" value="UDP"/>
    </profile>
</config>
```

## Capture Plan Configuration

**Example capture plan** (`sip_capture_plan.cfg`):

```c
/* Import HEP transport module */
import transport HEP;

/* Handle routing based on headers */
route {
    /* Log incoming message */
    clog("INF", "Processing SIP message from [%ip]", any_ip);
    
    /* Route based on X-Serialnumber header */
    if (header_check("X-Serialnumber", "000413924E28")) {
        clog("INF", "Special routing for device 000413924E28");
        if (!send_hep("homer_device_specific")) {
            clog("ERROR", "Failed to send HEP to device-specific homer");
        }
    }
    /* Route based on X-Devicetype header */
    else if (header_check("X-Devicetype", "CRITICAL")) {
        clog("INF", "Critical device detected");
        if (!send_hep("homer2")) {
            clog("ERROR", "Failed to send HEP to homer2");
        }
    }
    /* Default routing */
    else {
        clog("INF", "Using default routing");
        if (!send_hep("homer1")) {
            clog("ERROR", "Failed to send HEP to homer1");
        }
    }
}
```

## Protocol Configuration

**Example protocol_sip.xml configuration**:

```xml
<config name="protocol_sip">
    <param name="custom-header" value="X-Serialnumber"/>
    
    <!-- Optional: Configure PCRE patterns -->
    <param name="regexp-name" value="device_id_pattern"/>
    <param name="regexp-value" value="^[0-9A-F]{12}$"/>
</config>
```

## Expected Behavior

### Supported Operations

| Operation | Description | Example |
|-----------|-------------|---------|
| `header_check(name, value)` | Prefix match of header value | `header_check("X-Custom", "prefix")` |
| `header_regexp_match(name, pattern)` | Regex match of header value (PCRE enabled) | `header_regexp_match("X-Custom", "pattern_name")` |

### Return Values

- **1**: Header found and match successful
- **-1**: Header not found or match failed

### Notes on Matching

1. **Prefix matching**: `header_check()` matches if the value starts with the search string
   - Example: `header_check("X-Device", "SNOM")` matches "SNOM785" but not "MySONOM"

2. **Case sensitivity**: 
   - Header names are matched case-insensitively (RFC 3261)
   - Header values are matched case-sensitively by default

3. **Whitespace handling**:
   - Leading and trailing whitespace in header values is automatically trimmed
   - Tab characters are treated as whitespace

4. **Performance**:
   - Pre-configured custom headers use cached parsing (O(1))
   - Arbitrary header lookup searches the message (O(n))

## Backward Compatibility

### Existing Code Continues to Work

```xml
/* Old style - still works */
if (header_check("User-Agent", "snom")) { ... }
if (header_check("custom", "value")) { ... }

/* New style - enables arbitrary headers */
if (header_check("X-Any-Header", "value")) { ... }
```

## Testing

To test the implementation:

1. **Compile captagent**:
   ```bash
   ./configure
   make
   make install
   ```

2. **Create test SIP message** with desired headers

3. **Enable logging** in capture plan:
   ```c
   clog("ERROR", "Header match test");
   ```

4. **Monitor logs** for routing decisions

5. **Verify traffic** reaches correct Homer instance

## Frequently Asked Questions

### Q: Can I filter on response messages?

**A**: Yes, as long as the header is present in the response. Some headers (like From, To, Call-ID) are present in both requests and responses, while others (like Request-URI) are only in requests.

### Q: What about headers with parameters (like Contact)?

**A**: The entire header value is matched, including parameters. For example:
```xml
header_check("Contact", "<sip:666@192.168.250.108:49431>")
```

### Q: Are header names case-sensitive?

**A**: No, header names are matched case-insensitively per RFC 3261. `X-Serialnumber`, `x-serialnumber`, and `X-SERIALNUMBER` are all equivalent.

### Q: What's the limit on header value length?

**A**: Header values must be less than 256 bytes (MAX_PARSE_LEN). Most SIP headers are well within this limit.

### Q: Does multi-line header folding work?

**A**: Not directly in this implementation. If a header is folded across multiple lines (continuation lines), each line is treated separately.

### Q: How does this affect performance?

**A**: For pre-configured custom headers and standard headers, performance is unchanged. For arbitrary headers, there's a linear search of the message headers, typically 10-30 lines, which has negligible impact.

## Related Issues and Discussion

- **Issue #284**: Make captagent filter on headers
  - User wanted to match calls based on `X-Serialnumber` header
  - This implementation resolves that request

## Conclusion

The new header filtering capability provides flexible SIP message routing based on arbitrary header values, while maintaining full backward compatibility with existing configurations.
