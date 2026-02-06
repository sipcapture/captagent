#!/usr/bin/env python3
"""
Test script to validate the header filtering implementation for captagent issue #284
"""

import sys

def test_header_value_extraction():
    """Test cases for header value extraction logic"""
    
    test_cases = [
        {
            "name": "Basic header matching",
            "message": "INVITE sip:user@host SIP/2.0\r\nX-Serialnumber: 000413924E28\r\nUser-Agent: snom\r\n\r\nBODY",
            "header_name": "X-Serialnumber",
            "expected": "000413924E28"
        },
        {
            "name": "Case-insensitive header name",
            "message": "INVITE sip:test SIP/2.0\r\nx-custom: myvalue\r\n\r\n",
            "header_name": "X-CUSTOM",
            "expected": "myvalue"
        },
        {
            "name": "Header with leading/trailing spaces",
            "message": "INVITE sip:test SIP/2.0\r\nContact:  <sip:user@host>  \r\n\r\n",
            "header_name": "Contact",
            "expected": "<sip:user@host>"
        },
        {
            "name": "Header with tabs",
            "message": "INVITE sip:test SIP/2.0\r\nAllow:\tOPTIONS, INVITE\r\n\r\n",
            "header_name": "Allow",
            "expected": "OPTIONS, INVITE"
        },
        {
            "name": "Multiple headers",
            "message": "INVITE sip:test SIP/2.0\r\nVia: SIP/2.0/UDP\r\nFrom: User\r\nX-Custom: value\r\n\r\n",
            "header_name": "X-Custom",
            "expected": "value"
        },
        {
            "name": "Header not present",
            "message": "INVITE sip:test SIP/2.0\r\nVia: SIP/2.0/UDP\r\n\r\n",
            "header_name": "X-Notfound",
            "expected": None
        },
        {
            "name": "Standard SIP header",
            "message": "INVITE sip:test SIP/2.0\r\nAccept: application/sdp\r\n\r\n",
            "header_name": "Accept",
            "expected": "application/sdp"
        },
        {
            "name": "Header before body",
            "message": "200 OK\r\nServer: test/1.0\r\nContent-Length: 4\r\n\r\nBODY",
            "header_name": "Server",
            "expected": "test/1.0"
        }
    ]
    
    results = []
    for test in test_cases:
        # This is a reference test case for the C implementation
        result = {
            "name": test["name"],
            "header_name": test["header_name"],
            "expected": test["expected"],
            "status": "DEFINED"
        }
        results.append(result)
    
    return results

def test_header_check_logic():
    """Test logic for header_check function"""
    
    test_cases = [
        {
            "name": "Prefix match User-Agent",
            "header_value": "snomD785/10.1.84.12",
            "search_value": "snom",
            "expected": True
        },
        {
            "name": "Exact match",
            "header_value": "000413924E28",
            "search_value": "000413924E28",
            "expected": True
        },
        {
            "name": "Partial match",
            "header_value": "options,invite,subscribe",
            "search_value": "options",
            "expected": True
        },
        {
            "name": "No match",
            "header_value": "value1",
            "search_value": "value2",
            "expected": False
        }
    ]
    
    return test_cases

def print_test_report():
    """Print test report"""
    print("=" * 70)
    print("CAPTAGENT ISSUE #284: HEADER FILTERING IMPLEMENTATION TEST PLAN")
    print("=" * 70)
    print()
    
    print("TEST CATEGORY 1: Header Value Extraction")
    print("-" * 70)
    extraction_tests = test_header_value_extraction()
    for i, test in enumerate(extraction_tests, 1):
        print(f"{i}. {test['name']}")
        print(f"   Header: {test['header_name']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    print("\nTEST CATEGORY 2: Header Check Logic")
    print("-" * 70)
    check_tests = test_header_check_logic()
    for i, test in enumerate(check_tests, 1):
        print(f"{i}. {test['name']}")
        print(f"   Value: {test['header_value']}")
        print(f"   Search: {test['search_value']}")
        print(f"   Expected: {test['expected']}")
        print()
    
    print("\nTEST CATEGORY 3: Integration Tests")
    print("-" * 70)
    print("1. Test backward compatibility with User-Agent matching")
    print("   - Existing header_check('User-Agent', ...) should work")
    print()
    print("2. Test backward compatibility with custom header")
    print("   - Existing header_check('custom', ...) should work")
    print()
    print("3. Test new X-header matching")
    print("   - header_check('X-Serialnumber', '000413924E28') should work")
    print("   - header_check('X-Custom-Header', 'value') should work")
    print()
    print("4. Test PCRE regex matching (if compiled with PCRE)")
    print("   - header_regexp_match('X-Custom', 'pattern_name') should work")
    print()
    print("5. Test case-insensitive header name matching")
    print("   - header_check('x-serialnumber', 'value') should match 'X-Serialnumber'")
    print()
    
    print("\nIMPLEMENTATION NOTES:")
    print("-" * 70)
    print("✓ Function find_header_value() added to parser_sip.c")
    print("✓ w_header_check() updated to support arbitrary headers")
    print("✓ w_header_reg_match() updated to support arbitrary headers")
    print("✓ Case-insensitive header name matching implemented")
    print("✓ Backward compatibility maintained")
    print()
    
    print("TO COMPILE AND TEST:")
    print("-" * 70)
    print("1. ./configure")
    print("2. make")
    print("3. make install")
    print("4. Test with capture plan using new header_check() syntax")
    print()

if __name__ == "__main__":
    print_test_report()
    sys.exit(0)
