#ifndef _TCPIPREASM_H
#define _TCPIPREASM_H

#include <stdbool.h>

#include <pcap.h>


/*
 * This is an abstract time stamp. iptcpreasm doesn't care whether it is
 * in seconds, milliseconds, or nanodecades. All it does it add the
 * configured timeout value to it, and then compare it to the timstamps
 * of subsequent packets to decide whether a fragment has expired.
 */
typedef uint64_t tcpreasm_time_t;

struct tcpreasm_ip;

/*
 * Functions to create and destroy the reassembly environment.
 */
struct tcpreasm_ip *tcpreasm_ip_new (void);
void tcpreasm_ip_free (struct tcpreasm_ip *tcpreasm);

/*
 * This is the main packet processing function. It inputs one packet,
 * and MAY output one packet in turn. If the input was not a fragment,
 * it is passed unmodified. If the input was a fragment that completed
 * reassembly of a packet, the reassembled packet is output.
 * If more fragments are required for reassembly, or the input packet
 * is invalid for some reason, a NULL pointer is returned.
 *
 * The input must be a pointer allocated by malloc(). The output will
 * be a pointer allocated by malloc().
 *
 * Note that in the case of an IPv6 fragment, the input buffer will be
 * modified in-place. This is considered a bug and should be fixed in
 * the future.
 */
unsigned char *tcpreasm_ip_next (struct tcpreasm_ip *tcpreasm, unsigned char *packet, unsigned len, tcpreasm_time_t timestamp, unsigned *output_len);

unsigned char *tcpreasm_ip_next_tcp (struct tcpreasm_ip *tcpreasm, unsigned char *packet, unsigned len, tcpreasm_time_t timestamp, unsigned *output_len, struct in_addr *ip_src, struct in_addr *ip_dst, uint16_t sport, uint16_t dport, uint8_t psh);


/*
 * Set the timeout after which a noncompleted reassembly expires, in
 * abstract time units (see above for the definition of tcpreasm_time_t).
 */
bool tcpreasm_ip_set_timeout (struct tcpreasm_ip *tcpreasm, tcpreasm_time_t timeout);

/*
 * Query certain information about the current state.
 */
unsigned tcpreasm_ip_waiting (const struct tcpreasm_ip *tcpreasm);
unsigned tcpreasm_ip_max_waiting (const struct tcpreasm_ip *tcpreasm);
unsigned tcpreasm_ip_timed_out (const struct tcpreasm_ip *tcpreasm);
unsigned tcpreasm_ip_dropped_frags (const struct tcpreasm_ip *tcpreasm);


#endif /* _TCPIPREASM_H */
