# SIP Header Filtering in Captagent

This document explains how to compile Captagent with SIP header filtering support and how to use the `header_check` and `header_regexp_match` functions in capture plan scripts to route traffic based on any SIP header value.

---

## Table of Contents

- [Overview](#overview)
- [Compiling Captagent](#compiling-captagent)
  - [Basic Build (prefix match only)](#basic-build-prefix-match-only)
  - [Build with PCRE Regex Support](#build-with-pcre-regex-support)
- [Configuration](#configuration)
  - [transport_hep.xml – Multiple HEP Destinations](#transport_hepxml--multiple-hep-destinations)
  - [protocol_sip.xml – Optional: Pre-configured Custom Header](#protocol_sipxml--optional-pre-configured-custom-header)
  - [protocol_sip.xml – Optional: Named Regexp Patterns](#protocol_sipxml--optional-named-regexp-patterns)
- [Capture Plan Functions](#capture-plan-functions)
  - [header_check](#header_check)
  - [header_regexp_match](#header_regexp_match)
- [Examples](#examples)
  - [Route by exact header prefix](#route-by-exact-header-prefix)
  - [Route by User-Agent prefix](#route-by-user-agent-prefix)
  - [Route by regex on any header](#route-by-regex-on-any-header)
  - [Route by regex on User-Agent](#route-by-regex-on-user-agent)
  - [Combining multiple conditions](#combining-multiple-conditions)

---

## Overview

Captagent supports two functions for filtering SIP traffic based on header values inside capture plan scripts:

| Function | Matching style | PCRE required |
|---|---|---|
| `header_check(name, value)` | Prefix match (starts-with) | No |
| `header_regexp_match(name, regexp_name)` | Regular expression match | Yes (`--enable-pcre`) |

Both functions support **any arbitrary SIP header** by name, in addition to the built-in shortcuts `User-Agent`, `useragent`, `custom`, and (for `header_regexp_match`) `body`/`raw`.

Header names are matched **case-insensitively** (e.g. `X-Serialnumber` and `x-serialnumber` are equivalent).

---

## Compiling Captagent

### Prerequisites

```bash
# Debian/Ubuntu
sudo apt-get install -y \
    build-essential autoconf automake libtool \
    libpcap-dev libxml2-dev

# For PCRE regex support (recommended)
sudo apt-get install -y libpcre2-dev
# or for older PCRE:
# sudo apt-get install -y libpcre3-dev
```

### Basic Build (prefix match only)

The `header_check` function works without PCRE. To build:

```bash
cd captagent
./build.sh         # generates configure script
./configure --prefix=/usr
make
sudo make install
```

### Build with PCRE Regex Support

To enable `header_regexp_match`, pass `--enable-pcre` to `configure`. Captagent automatically detects and prefers PCRE2 over the older PCRE library:

```bash
cd captagent
./build.sh
./configure --prefix=/usr --enable-pcre
make
sudo make install
```

Verify that PCRE support is active by checking the build output for one of:
- `Using PCRE2` – modern PCRE2 library in use
- `Using PCRE` – legacy PCRE library in use

---

## Configuration

### transport_hep.xml – Multiple HEP Destinations

Define as many HEP profiles as you need. Each profile is a named routing target used by `send_hep("name")` in the capture plan.

```xml
<?xml version="1.0"?>
<document type="captagent_module/xml">
    <module name="transport_hep" description="HEP Protocol" serial="2014010402">

        <!-- Default Homer -->
        <profile name="hepsocket" description="Default HEP" enable="true" serial="2014010402">
            <settings>
                <param name="version" value="3"/>
                <param name="capture-host" value="10.0.0.1"/>
                <param name="capture-port" value="9060"/>
                <param name="capture-proto" value="udp"/>
                <param name="capture-id" value="2001"/>
                <param name="capture-password" value="myhep"/>
                <param name="payload-compression" value="false"/>
            </settings>
        </profile>

        <!-- Secondary Homer, e.g. for traffic from specific devices -->
        <profile name="homer2" description="Secondary HEP" enable="true" serial="2014010403">
            <settings>
                <param name="version" value="3"/>
                <param name="capture-host" value="10.0.0.2"/>
                <param name="capture-port" value="9060"/>
                <param name="capture-proto" value="udp"/>
                <param name="capture-id" value="2002"/>
                <param name="capture-password" value="myhep"/>
                <param name="payload-compression" value="false"/>
            </settings>
        </profile>

    </module>
</document>
```

### protocol_sip.xml – Optional: Pre-configured Custom Header

If you only need to match a **single** custom header throughout the entire capture plan, you can declare it here and then use `header_check("custom", "value")` in scripts. This is slightly more efficient since the header is extracted at parse time.

```xml
<?xml version="1.0"?>
<document type="captagent_module/xml">
    <module name="protocol_sip" description="SIP Protocol" serial="2014010402">
        <profile name="proto_sip" description="PROTO SIP" enable="true" serial="2014010402">
            <settings>
                <param name="dialog-type" value="2"/>
                <param name="dialog-timeout" value="180"/>
                <!-- Name of the custom header to extract and expose as "custom" -->
                <param name="custom-header" value="X-Serialnumber"/>
            </settings>
        </profile>
    </module>
</document>
```

Usage in the capture plan:

```
if(header_check("custom", "000413924E28")) { ... }
```

### protocol_sip.xml – Optional: Named Regexp Patterns

When using `header_regexp_match`, define one or more named regexp patterns. Each pattern is declared with a pair of `regexp-name` / `regexp-value` parameters:

```xml
<?xml version="1.0"?>
<document type="captagent_module/xml">
    <module name="protocol_sip" description="SIP Protocol" serial="2014010402">
        <profile name="proto_sip" description="PROTO SIP" enable="true" serial="2014010402">
            <settings>
                <param name="dialog-type" value="2"/>
                <param name="dialog-timeout" value="180"/>

                <!-- Regexp pattern 1: match snom devices by User-Agent -->
                <param name="regexp-name" value="snom_regexp"/>
                <param name="regexp-value" value="snom.*"/>

                <!-- Regexp pattern 2: match a specific serial number prefix -->
                <param name="regexp-name" value="serial_prefix"/>
                <param name="regexp-value" value="^0004139.*"/>
            </settings>
        </profile>
    </module>
</document>
```

Up to 10 named patterns are supported (`MAX_REGEXP_INDEXES = 10`).

---

## Capture Plan Functions

### header_check

```
header_check("HEADER-NAME", "VALUE")
```

Returns `true` when the value of the named SIP header **starts with** `VALUE` (prefix match).

**Built-in keyword shortcuts:**

| First argument | Matches against |
|---|---|
| `User-Agent` or `useragent` | Pre-parsed `User-Agent` header |
| `custom` | The single header declared via `custom-header` in `protocol_sip.xml` |
| Any other string | Scanned directly from the raw SIP message (case-insensitive header name lookup) |

**Examples:**

```
header_check("X-Serialnumber", "000413924E28")
header_check("User-Agent", "snom")
header_check("custom", "000413924E28")   # requires custom-header=X-Serialnumber in xml
header_check("Max-Forwards", "70")
```

### header_regexp_match

```
header_regexp_match("HEADER-NAME", "REGEXP-NAME")
```

Returns `true` when the value of the named SIP header matches the named PCRE regular expression. Requires Captagent to be compiled with `--enable-pcre`.

**Built-in keyword shortcuts:**

| First argument | Matches against |
|---|---|
| `User-Agent` or `useragent` | Pre-parsed `User-Agent` header |
| `custom` | The single header declared via `custom-header` in `protocol_sip.xml` |
| `body` or `raw` | The entire raw SIP message payload |
| Any other string | Scanned directly from the raw SIP message (case-insensitive header name lookup) |

**Examples:**

```
header_regexp_match("User-Agent", "snom_regexp")
header_regexp_match("X-Serialnumber", "serial_prefix")
header_regexp_match("body", "snom_regexp")
```

---

## Examples

### Route by exact header prefix

Send all packets where `X-Serialnumber` starts with `000413924E28` to a secondary Homer:

```
# conf/captureplans/sip_capture_plan.cfg

capture[pcap] {

    if(msg_check("size", "100")) {

        if(parse_sip()) {

            # Default: send everything to primary Homer
            if(!send_hep("hepsocket")) {
                clog("ERROR", "Error sending HEP!!!!");
            }

            # Additionally route matching traffic to secondary Homer
            if(header_check("X-Serialnumber", "000413924E28")) {
                if(!send_hep("homer2")) {
                    clog("ERROR", "Error sending to homer2!!!!");
                }
            }
        }
    }
    drop;
}
```

### Route by User-Agent prefix

```
capture[pcap] {
    if(msg_check("size", "100")) {
        if(parse_sip()) {
            if(header_check("User-Agent", "snom")) {
                if(!send_hep("homer2")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            } else {
                if(!send_hep("hepsocket")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            }
        }
    }
    drop;
}
```

### Route by regex on any header

Requires `--enable-pcre` and the `serial_prefix` pattern defined in `protocol_sip.xml`:

```
capture[pcap] {
    if(msg_check("size", "100")) {
        if(parse_sip()) {
            if(header_regexp_match("X-Serialnumber", "serial_prefix")) {
                if(!send_hep("homer2")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            } else {
                if(!send_hep("hepsocket")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            }
        }
    }
    drop;
}
```

### Route by regex on User-Agent

Requires `--enable-pcre` and the `snom_regexp` pattern defined in `protocol_sip.xml`:

```
capture[pcap] {
    if(msg_check("size", "100")) {
        if(parse_sip()) {
            if(header_regexp_match("User-Agent", "snom_regexp")) {
                if(!send_hep("homer2")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            } else {
                if(!send_hep("hepsocket")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            }
        }
    }
    drop;
}
```

### Combining multiple conditions

Route traffic to different Homer instances based on IP *and* header:

```
capture[pcap] {
    if(msg_check("size", "100")) {
        if(parse_sip()) {

            if(msg_check("any_ip", "10.0.1.50") && header_check("X-Serialnumber", "000413924E28")) {
                if(!send_hep("homer2")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            } else {
                if(!send_hep("hepsocket")) {
                    clog("ERROR", "Error sending HEP!!!!");
                }
            }

        }
    }
    drop;
}
```
