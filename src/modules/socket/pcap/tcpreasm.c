/*
 * tcpreasm -- Routines for reassembly of fragmented IPv4 and IPv6 packets.
 * added tcp stream reassembling
 *
 * Copyright (c) 2007  Jan Andres <jandres@gmx.net>
 * Copyright (c) 2014  Alexandr Dubovikov  <alexandr.dubovikov@gmail.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#if USE_IPv6
#include <netinet/ip6.h>
#endif /* USE_IPv6 */

extern int debug_socket_pcap_enable;

#include "tcpreasm.h"


#define REASM_IP_HASH_SIZE 1021U


enum entry_state {
	STATE_ACTIVE,
	STATE_INVALID,
};


enum tcpreasm_proto {
	PROTO_IPV4,
#if USE_IPv6
	PROTO_IPV6,
#endif /* USE_IPv6 */
};


/*
 * This tuple uniquely identifies all fragments belonging to
 * the same IPv4 packet.
 */
struct tcpreasm_id_ipv4 {
	uint8_t ip_src[4], ip_dst[4];
	uint16_t ip_id;
	uint8_t ip_proto;
	uint16_t sport;
	uint16_t dport;
};


/*
 * Same for IPv6.
 */
struct tcpreasm_id_ipv6 {
	uint8_t ip_src[16], ip_dst[16];
	uint32_t ip_id;
	uint16_t sport;
	uint16_t dport;
};


union tcpreasm_id {
	struct tcpreasm_id_ipv4 ipv4;
	struct tcpreasm_id_ipv6 ipv6;
};


struct tcpreasm_frag_entry {
	unsigned len;  /* payload length of this fragment */
	unsigned offset; /* offset of this fragment into the payload of the reassembled packet */
	unsigned data_offset; /* offset to the data pointer where payload starts */
	unsigned char *data; /* payload starts at data + data_offset */
	struct tcpreasm_frag_entry *next;
};


/*
 * Reception of a complete packet is detected by counting the number
 * of "holes" that remain between the cached fragments. A hole is
 * assumed to exist at the upper end of the packet until the final
 * fragment has been received. When the number of holes drops to 0,
 * all fragments have been received and the packet can be reassembled.
 */
struct tcpreasm_ip_entry {
	union tcpreasm_id id;
	unsigned len, holes, frag_count, hash, mss;
	tcpreasm_time_t timeout;
	enum entry_state state;
	enum tcpreasm_proto protocol;
	struct tcpreasm_frag_entry *frags;
	struct tcpreasm_ip_entry *prev, *next;
	struct tcpreasm_ip_entry *time_prev, *time_next;
};


/*
 * This struct contains some metadata, the main hash table, and a pointer
 * to the first entry that will time out. A linked list is kept in the
 * order in which packets will time out. Using a linked list for this
 * purpose requires that packets are input in chronological order, and
 * that a constant timeout value is used, which doesn't change even when
 * the entry's state transitions from active to invalid.
 */
struct tcpreasm_ip {
	struct tcpreasm_ip_entry *table[REASM_IP_HASH_SIZE];
	struct tcpreasm_ip_entry *time_first, *time_last;
	unsigned waiting, max_waiting, timed_out, dropped_frags;
	tcpreasm_time_t timeout;
};


/*
 * Hash functions.
 */
static unsigned tcpreasm_ipv4_hash (const struct tcpreasm_id_ipv4 *id);
#if USE_IPv6
static unsigned tcpreasm_ipv6_hash (const struct tcpreasm_id_ipv6 *id);
#endif /* USE_IPv6 */

/*
 * Insert a new fragment to the correct position in the list of fragments.
 * Check for fragment overlap and other error conditions. Update the
 * "hole count".
 */
static bool add_fragment_tcp (struct tcpreasm_ip_entry *entry, struct tcpreasm_frag_entry *frag, bool last_frag);

/*
 * Is the entry complete, ready for reassembly?
 */
/*
static bool is_complete (struct tcpreasm_ip_entry *entry);
*/

static unsigned char *assemble_tcp (struct tcpreasm_ip_entry *entry, unsigned *output_len);

/*
 * Drop and free entries.
 */
static void drop_entry (struct tcpreasm_ip *tcpreasm, struct tcpreasm_ip_entry *entry);
static void free_entry (struct tcpreasm_ip_entry *entry);

/*
 * Dispose of any entries which have expired before "now".
 */
static void process_timeouts (struct tcpreasm_ip *tcpreasm, tcpreasm_time_t now);

/*
 * Create fragment structure from IPv6 packet. Returns NULL if the input
 * is not a fragment.
 * This function is called by parse_packet(), don't call it directly.
 */
#if USE_IPv6
static struct tcpreasm_frag_entry *frag_from_ipv6 (unsigned char *packet, uint32_t *ip_id, bool *last_frag);
#endif /* USE_IPv6 */

/*
 * Compare packet identification tuples for specified protocol.
 */
static bool tcpreasm_id_equal_tcp (enum tcpreasm_proto proto, const union tcpreasm_id *left, const union tcpreasm_id *right);


static unsigned
tcpreasm_ipv4_hash (const struct tcpreasm_id_ipv4 *id)
{
	unsigned hash = 0;
	int i;

	for (i = 0; i < 4; i++) {
		hash = 37U * hash + id->ip_src[i];
		hash = 37U * hash + id->ip_dst[i];
	}

	hash = 59U * hash + id->ip_id;

	hash = 47U * hash + id->ip_proto;
	hash = 47U * hash + id->dport;
	hash = 47U * hash + id->sport;

	return hash;
}


#if USE_IPv6
static unsigned
tcpreasm_ipv6_hash (const struct tcpreasm_id_ipv6 *id)
{
	unsigned hash = 0;
	int i;

	for (i = 0; i < 16; i++) {
		hash = 37U * hash + id->ip_src[i];
		hash = 37U * hash + id->ip_dst[i];
	}

	hash = 59U * hash + id->ip_id;
	hash = 47U * hash + id->dport;
	hash = 47U * hash + id->sport;
	return hash;
}
#endif /* USE_IPv6 */


unsigned char *
tcpreasm_ip_next_tcp (struct tcpreasm_ip *tcpreasm, unsigned char *packet, unsigned len, tcpreasm_time_t timestamp, unsigned *output_len, struct in_addr *ip_src, struct in_addr *ip_dst, uint16_t sport, uint16_t dport, uint8_t psh)
{
	enum tcpreasm_proto proto;
	union tcpreasm_id id;
	unsigned hash;
	bool last_frag = false;


	process_timeouts (tcpreasm, timestamp);
		
	struct tcpreasm_frag_entry *frag = NULL;
	frag = malloc (sizeof (*frag));
        if (frag == NULL)
        	return NULL;

	*frag = (struct tcpreasm_frag_entry) {
        	.len = len,
                .offset = 10 * 8,
                .data_offset = len,
                .data = packet,
	};
	
	proto = PROTO_IPV4;
	
	memcpy (id.ipv4.ip_src, ip_src, 4);
        memcpy (id.ipv4.ip_dst, ip_dst, 4);
        id.ipv4.ip_id = 200;
        id.ipv4.ip_proto = PROTO_IPV4;
        id.ipv4.sport = sport;
        id.ipv4.dport = dport;        
        
        hash = tcpreasm_ipv4_hash (&id.ipv4);
                
        if(debug_socket_pcap_enable) {
        
        	printf("\nTCPREASM: Proto [%d], Hash:[%d] SPORT: [%d], DPORT: [%d]\n", proto, hash, sport, dport);
        }
        
	hash %= REASM_IP_HASH_SIZE;
	struct tcpreasm_ip_entry *entry = tcpreasm->table[hash];
		
	while (entry != NULL && (!tcpreasm_id_equal_tcp (proto, &id, &entry->id)))
		entry = entry->next;
	
	/* no buffer, go out */
	if(psh == 1 && entry == NULL) {
		free(frag);
		if(debug_socket_pcap_enable) printf("RETURN PACKET BACK\n");
		*output_len = len;
		return packet;
	}		

	if (entry == NULL) {
	
		if(debug_socket_pcap_enable) printf("EMPTY ENTRY\n");
        			
		entry = malloc (sizeof (*entry));
		if (entry == NULL) {
			free (frag);
			return NULL;
		}

		struct tcpreasm_frag_entry *list_head = malloc (sizeof (*list_head));
		if (list_head == NULL) {
			free (frag);
			free (entry);
			return NULL;
		}

		*entry = (struct tcpreasm_ip_entry) {
			.id = id,
			.len = 0,
			.holes = 1,
			.frags = list_head,
			.hash = hash,
			.protocol = proto,
			.mss = len,
			.timeout = timestamp + tcpreasm->timeout,
			.state = STATE_ACTIVE,
			.prev = NULL,
			.next = tcpreasm->table[hash],
			.time_prev = tcpreasm->time_last,
			.time_next = NULL,
		};

		*list_head = (struct tcpreasm_frag_entry) {
			.len = 0,
			.offset = 0,
			.data_offset = 0,
			.data = NULL,
		};

		if (entry->next != NULL)
			entry->next->prev = entry;
		tcpreasm->table[hash] = entry;

		if (tcpreasm->time_last != NULL)
			tcpreasm->time_last->time_next = entry;
		else
			tcpreasm->time_first = entry;
		tcpreasm->time_last = entry;

		tcpreasm->waiting++;
		if (tcpreasm->waiting > tcpreasm->max_waiting)
			tcpreasm->max_waiting = tcpreasm->waiting;
	}

	if (entry->state != STATE_ACTIVE) {
		tcpreasm->dropped_frags++;
		return NULL;
	}

	
	
	if (!add_fragment_tcp (entry, frag, last_frag)) {
		entry->state = STATE_INVALID;
		tcpreasm->dropped_frags += entry->frag_count + 1;
		return NULL;
	}

	if(psh == 0) return NULL;
	
	/* workaround for ACK/PSH big messages */
	if(entry->mss == len) return NULL;
	
	unsigned char *r = assemble_tcp (entry, output_len);

	//printf("TCP REASSEM: [%d]\n", *output_len);
	//printf("MESSAGE: [%s]\n", r);
	
	drop_entry (tcpreasm, entry);
	return r;
}


static bool
add_fragment_tcp (struct tcpreasm_ip_entry *entry, struct tcpreasm_frag_entry *frag, bool last_frag)
{
	/*
	 * When a fragment is inserted into the list, different cases can occur
	 * concerning the number of holes.
	 * - The new fragment can be inserted in the middle of a hole, such that
	 *   it will split the hole in two. The number of holes increases by 1.
	 * - The new fragment can be attached to one end of a hole, such that
	 *   the rest of the hole remains at the opposite side of the fragment.
	 *   The number of holes remains constant.
	 * - The new fragment can fill a hole completely. The number of holes
	 *   decreases by 1.
	 */

        struct tcpreasm_frag_entry *cur = entry->frags;
        /* struct tcpreasm_frag_entry *next = cur->next; */

	entry->len+=frag->len;

	while (cur->next != NULL) cur = cur->next;
	/* next = cur->next; */

	/* Fragment is to be inserted between cur and next; next may be NULL. */

	if (frag->len != 0) {
		frag->next = cur->next;
		cur->next = frag;
		entry->frag_count++;
	} 
	
	return true;
}



struct tcpreasm_ip *
tcpreasm_ip_new (void)
{
	struct tcpreasm_ip *tcpreasm = malloc (sizeof (*tcpreasm));
	if (tcpreasm == NULL)
		return NULL;

	memset (tcpreasm, 0, sizeof (*tcpreasm));
	return tcpreasm;
}


void
tcpreasm_ip_free (struct tcpreasm_ip *tcpreasm)
{
	while (tcpreasm->time_first != NULL)
		drop_entry (tcpreasm, tcpreasm->time_first);
	free (tcpreasm);
}

/*
static bool
is_complete (struct tcpreasm_ip_entry *entry)
{
	return entry->holes == 0;
}
*/

static unsigned char *
assemble_tcp (struct tcpreasm_ip_entry *entry, unsigned *output_len)
{
	struct tcpreasm_frag_entry *frag = entry->frags->next; /* skip list head */
	unsigned offset0 = frag->data_offset;
	unsigned char *p = malloc (entry->len + offset0);
	unsigned tlen = 0;
	
	//printf("TOTAL LEN: %d\n", entry->len);
	
	if (p == NULL)
		return NULL;

	switch (entry->protocol) {
		case PROTO_IPV4:
			break;

#if USE_IPv6
		case PROTO_IPV6:
			offset0 -= 8; /* size of frag header */
			break;
#endif /* USE_IPv6 */

		default:
			break;
	}

	*output_len = entry->len;

	/* join all the payload fragments together */
	while (frag != NULL) {		
		memcpy (p + tlen, frag->data, frag->len);
		tlen += frag->len;			
		frag = frag->next;
	}

	return p;
}


static void
drop_entry (struct tcpreasm_ip *tcpreasm, struct tcpreasm_ip_entry *entry)
{
	if (entry->prev != NULL)
		entry->prev->next = entry->next;
	else
		tcpreasm->table[entry->hash] = entry->next;

	if (entry->next != NULL)
		entry->next->prev = entry->prev;

	if (entry->time_prev != NULL)
		entry->time_prev->time_next = entry->time_next;
	else
		tcpreasm->time_first = entry->time_next;

	if (entry->time_next != NULL)
		entry->time_next->time_prev = entry->time_prev;
	else
		tcpreasm->time_last = entry->time_prev;

	tcpreasm->waiting--;

	free_entry (entry);
}


static void
free_entry (struct tcpreasm_ip_entry *entry)
{
	struct tcpreasm_frag_entry *frag = entry->frags, *next;
	while (frag != NULL) {
		next = frag->next;
		if (frag->data != NULL)
			free (frag->data);
		free (frag);
		frag = next;
	}

	free (entry);
}


unsigned
tcpreasm_ip_waiting (const struct tcpreasm_ip *tcpreasm)
{
	return tcpreasm->waiting;
}


unsigned
tcpreasm_ip_max_waiting (const struct tcpreasm_ip *tcpreasm)
{
	return tcpreasm->max_waiting;
}


unsigned
tcpreasm_ip_timed_out (const struct tcpreasm_ip *tcpreasm)
{
	return tcpreasm->timed_out;
}


unsigned
tcpreasm_ip_dropped_frags (const struct tcpreasm_ip *tcpreasm)
{
	return tcpreasm->dropped_frags;
}


bool
tcpreasm_ip_set_timeout (struct tcpreasm_ip *tcpreasm, tcpreasm_time_t timeout)
{
	if (tcpreasm->time_first != NULL)
		return false;

	tcpreasm->timeout = timeout;
	return true;
}


static void
process_timeouts (struct tcpreasm_ip *tcpreasm, tcpreasm_time_t now)
{
	while (tcpreasm->time_first != NULL && tcpreasm->time_first->timeout < now) {
		tcpreasm->timed_out++;
		drop_entry (tcpreasm, tcpreasm->time_first);
	}
}


#if USE_IPv6
static struct tcpreasm_frag_entry *
frag_from_ipv6 (unsigned char *packet, uint32_t *ip_id, bool *last_frag)
{
	struct ip6_hdr *ip6_header = (struct ip6_hdr *) packet;
	unsigned offset = 40; /* IPv6 header size */
	uint8_t nxt = ip6_header->ip6_nxt;
	unsigned total_len = 40 + ntohs (ip6_header->ip6_plen);
	unsigned last_nxt = offsetof (struct ip6_hdr, ip6_nxt);

	/*
	 * IPv6 extension headers from RFC 2460:
	 *   0 Hop-by-Hop Options
	 *  43 Routing
	 *  44 Fragment
	 *  60 Destination Options
	 *
	 * We look out for the Fragment header; the other 3 header
	 * types listed above are recognized and considered safe to
	 * skip over if they occur before the Fragment header.
	 * Any unrecognized header will cause processing to stop and
	 * a subsequent Fragment header to stay unrecognized.
	 */
	while (nxt == IPPROTO_HOPOPTS || nxt == IPPROTO_ROUTING || nxt == IPPROTO_DSTOPTS) {
		if (offset + 2 > total_len)
			return NULL;  /* header extends past end of packet */

		unsigned exthdr_len = 8 + 8 * packet[offset + 1];
		if (offset + exthdr_len > total_len)
			return NULL;  /* header extends past end of packet */

		nxt = packet[offset];
		last_nxt = offset;
		offset += exthdr_len;
	}

	if (nxt != IPPROTO_FRAGMENT)
		return NULL;

	if (offset + 8 > total_len)
		return NULL;  /* Fragment header extends past end of packet */

	struct tcpreasm_frag_entry *frag = malloc (sizeof (*frag));
	if (frag == NULL)
		return NULL;

	struct ip6_frag *frag_header = (struct ip6_frag *) (packet + offset);
	offset += 8;

	/*
	 * The Fragment header will be removed on reassembly, so we have to
	 * replace the Next Header field of the previous header (which is
	 * currently IPPROTO_FRAGMENT), with the Next Header field of the
	 * Fragment header.
	 *
	 * XXX We really shouldn't manipulate the input packet in-place.
	 */
	packet[last_nxt] = frag_header->ip6f_nxt;

	*frag = (struct tcpreasm_frag_entry) {
		.len = total_len - offset,
		.data_offset = offset,
		.offset = ntohs (frag_header->ip6f_offlg & IP6F_OFF_MASK),
		.data = packet,
	};

	*ip_id = ntohl (frag_header->ip6f_ident);
	*last_frag = (frag_header->ip6f_offlg & IP6F_MORE_FRAG) == 0;

	return frag;
}
#endif /* USE_IPv6 */


static bool
tcpreasm_id_equal_tcp (enum tcpreasm_proto proto, const union tcpreasm_id *left, const union tcpreasm_id *right)
{
	switch (proto) {
		case PROTO_IPV4:
			return memcmp (left->ipv4.ip_src, right->ipv4.ip_src, 4) == 0
				&& memcmp (left->ipv4.ip_dst, right->ipv4.ip_dst, 4) == 0
				&& left->ipv4.ip_id == right->ipv4.ip_id
				&& left->ipv4.sport == right->ipv4.sport
				&& left->ipv4.dport == right->ipv4.dport
				&& left->ipv4.ip_proto == right->ipv4.ip_proto;
#if USE_IPv6
		case PROTO_IPV6:
			return memcmp (left->ipv6.ip_src, right->ipv6.ip_src, 16) == 0
				&& memcmp (left->ipv6.ip_dst, right->ipv6.ip_dst, 16) == 0
				&& left->ipv6.sport == right->ipv6.sport
				&& left->ipv6.dport == right->ipv6.dport
				&& left->ipv6.ip_id == right->ipv6.ip_id;
#endif /* USE_IPv6 */
		default:
			return memcmp (left->ipv4.ip_src, right->ipv4.ip_src, 4) == 0
				&& memcmp (left->ipv4.ip_dst, right->ipv4.ip_dst, 4) == 0
				&& left->ipv4.ip_id == right->ipv4.ip_id
				&& left->ipv4.sport == right->ipv4.sport
				&& left->ipv4.dport == right->ipv4.dport
				&& left->ipv4.ip_proto == right->ipv4.ip_proto;
	}
}

