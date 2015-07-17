#ifndef _IPREASM_H
#define _IPREASM_H

#include <stdbool.h>

#include <pcap.h>


/*
 * This is an abstract time stamp. ipreasm doesn't care whether it is
 * in seconds, milliseconds, or nanodecades. All it does it add the
 * configured timeout value to it, and then compare it to the timstamps
 * of subsequent packets to decide whether a fragment has expired.
 */
typedef uint64_t reasm_time_t;

struct reasm_ip;

/*
 * Functions to create and destroy the reassembly environment.
 */
struct reasm_ip *reasm_ip_new (void);
void reasm_ip_free (struct reasm_ip *reasm);

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
unsigned char *reasm_ip_next (struct reasm_ip *reasm, unsigned char *packet, unsigned len, reasm_time_t timestamp, unsigned *output_len);

/*
 * Set the timeout after which a noncompleted reassembly expires, in
 * abstract time units (see above for the definition of reasm_time_t).
 */
bool reasm_ip_set_timeout (struct reasm_ip *reasm, reasm_time_t timeout);

/*
 * Query certain information about the current state.
 */
unsigned reasm_ip_waiting (const struct reasm_ip *reasm);
unsigned reasm_ip_max_waiting (const struct reasm_ip *reasm);
unsigned reasm_ip_timed_out (const struct reasm_ip *reasm);
unsigned reasm_ip_dropped_frags (const struct reasm_ip *reasm);


#endif /* _IPREASM_H */
