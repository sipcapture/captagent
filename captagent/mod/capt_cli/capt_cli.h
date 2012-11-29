/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * Homer capture agent is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
*/

#define USE_IPV6

#include "../../config.h"
#include "../../src/xmlread.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#define LISTENQ  1024
#define MAX_LINE 1000


int server_sock;
struct addrinfo *ai;
char *cli_host  = "localhost";
char *cli_port  = "8909";
char *cli_password;

int load_module(xml_node *config);
void handler(int value);
int init_clisocket (void);
ssize_t write_line(int sockd, const void *vptr, size_t n);
ssize_t read_line(int sockd, void *vptr, size_t maxlen);
void *wait_connect (void);
void *read_clisocket(void *client);

/* send counter */
extern int sendPacketsCount;

