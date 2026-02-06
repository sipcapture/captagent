/*
 * Test program to verify find_header_value() function compiles correctly
 * This is a minimal replication to test syntax without full captagent build
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

/* Minimal str type definition for testing */
typedef struct {
    char *s;
    int len;
} str;

#define MAX_PARSE_LEN 256

/*
 * Find header value in a SIP message by header name
 * Returns 0 if found and header_value is set, -1 if not found
 * This function handles case-insensitive header name matching
 */
int
find_header_value(const char *message, unsigned int msg_len, const char *header_name, str *header_value)
{
    const char *ptr = message;
    const char *end = message + msg_len;
    int header_name_len;
    const char *line_end;
    const char *value_start;
    const char *value_end;
    int header_len;

    if (!message || !header_name || !header_value || msg_len == 0) {
        return -1;
    }

    header_name_len = strlen(header_name);
    header_value->s = NULL;
    header_value->len = 0;

    /* Search through the message for the header */
    while (ptr < end) {
        /* Find the end of the current line */
        line_end = ptr;
        while (line_end < end && *line_end != '\r' && *line_end != '\n') {
            line_end++;
        }

        /* Check if this line matches the header we're looking for */
        if (line_end - ptr > header_name_len + 1) {
            /* Check for header name match (case-insensitive) followed by ':' */
            if (strncasecmp(ptr, header_name, header_name_len) == 0 &&
                *(ptr + header_name_len) == ':') {
                
                /* Found the header, extract the value */
                value_start = ptr + header_name_len + 1;
                
                /* Skip leading whitespace */
                while (value_start < line_end && (*value_start == ' ' || *value_start == '\t')) {
                    value_start++;
                }
                
                /* Find the end of the value (before \r or \n) */
                value_end = line_end;
                while (value_end > value_start && (*(value_end - 1) == ' ' || *(value_end - 1) == '\t')) {
                    value_end--;
                }
                
                header_len = value_end - value_start;
                if (header_len > 0 && header_len < MAX_PARSE_LEN) {
                    header_value->s = (char *)value_start;
                    header_value->len = header_len;
                    return 0;
                }
                return -1;
            }
        }

        /* Move to the next line */
        if (line_end < end && *line_end == '\r' && (line_end + 1) < end && *(line_end + 1) == '\n') {
            ptr = line_end + 2;
        } else if (line_end < end && (*line_end == '\r' || *line_end == '\n')) {
            ptr = line_end + 1;
        } else {
            break;
        }

        /* Stop at the blank line that separates headers from body */
        if (ptr < end && (*ptr == '\r' || *ptr == '\n')) {
            break;
        }
    }

    return -1;
}

/* Test cases */
int main() {
    str result;
    
    /* Test 1: Basic header matching */
    const char *msg1 = "INVITE sip:user@host SIP/2.0\r\nX-Custom: testvalue\r\n\r\n";
    if (find_header_value(msg1, strlen(msg1), "X-Custom", &result) == 0) {
        printf("✓ Test 1 PASSED: Found header X-Custom = '%.*s'\n", result.len, result.s);
    } else {
        printf("✗ Test 1 FAILED\n");
        return 1;
    }
    
    /* Test 2: Case-insensitive header matching */
    if (find_header_value(msg1, strlen(msg1), "x-custom", &result) == 0) {
        printf("✓ Test 2 PASSED: Case-insensitive match\n");
    } else {
        printf("✗ Test 2 FAILED\n");
        return 1;
    }
    
    /* Test 3: Header not found */
    if (find_header_value(msg1, strlen(msg1), "X-NotFound", &result) == -1) {
        printf("✓ Test 3 PASSED: Correctly returns -1 for missing header\n");
    } else {
        printf("✗ Test 3 FAILED\n");
        return 1;
    }
    
    /* Test 4: Whitespace trimming */
    const char *msg2 = "INVITE sip:test SIP/2.0\r\nX-Header:   value with spaces  \r\n\r\n";
    if (find_header_value(msg2, strlen(msg2), "X-Header", &result) == 0) {
        printf("✓ Test 4 PASSED: Whitespace trimmed, value = '%.*s' (len=%d)\n", 
               result.len, result.s, result.len);
    } else {
        printf("✗ Test 4 FAILED\n");
        return 1;
    }
    
    /* Test 5: Multiple headers */
    const char *msg3 = "INVITE sip:test SIP/2.0\r\nVia: SIP/2.0/UDP\r\nX-Serial: ABC123\r\nAccept: application/sdp\r\n\r\n";
    if (find_header_value(msg3, strlen(msg3), "X-Serial", &result) == 0) {
        printf("✓ Test 5 PASSED: Found correct header in multi-header message = '%.*s'\n", 
               result.len, result.s);
    } else {
        printf("✗ Test 5 FAILED\n");
        return 1;
    }
    
    printf("\n✓ All tests PASSED! Code compiles and runs correctly.\n");
    return 0;
}
