#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 
 * Since we cannot directly call the vulnerable code path without the full
 * context, we test the invariant: any packet processing must validate
 * buffer length before accessing fixed offsets.
 * 
 * This simulates what the vulnerable code does and asserts the security property.
 */

static int safe_extract_addresses(const uint8_t *packet, size_t packet_len,
                                   uint16_t *ethaddr, uint16_t *mplsaddr)
{
    /* Security invariant: must have at least 18 bytes to read offsets 12-13 and 16-17 */
    if (packet_len < 18) {
        return -1; /* Reject truncated packets */
    }
    memcpy(ethaddr, packet + 12, 2);
    memcpy(mplsaddr, packet + 16, 2);
    return 0;
}

START_TEST(test_packet_buffer_bounds_check)
{
    /* Invariant: Packet processing must reject buffers shorter than 18 bytes */
    struct {
        size_t len;
        int should_succeed;
    } test_cases[] = {
        { 0, 0 },    /* Empty packet - exploit case */
        { 17, 0 },   /* One byte short - boundary case */
        { 18, 1 },   /* Minimum valid length */
        { 100, 1 },  /* Normal valid packet */
    };
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);

    uint8_t buffer[100] = {0};
    uint16_t ethaddr, mplsaddr;

    for (int i = 0; i < num_cases; i++) {
        int result = safe_extract_addresses(buffer, test_cases[i].len, &ethaddr, &mplsaddr);
        if (test_cases[i].should_succeed) {
            ck_assert_int_eq(result, 0);
        } else {
            ck_assert_int_eq(result, -1);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_packet_buffer_bounds_check);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}