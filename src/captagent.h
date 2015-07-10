/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
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

#ifndef CAPTAGENT_H_
#define CAPTAGENT_H_

#include "md5.h"

#define CAPTAGENT_VERSION "6.0.0"
#define DEFAULT_CONFIG DEFAULT_CONFDIR "captagent.xml"
#define DEFAULT_PIDFILE  "/var/run/captagent.pid"
#define MAX_STATS 3000

/* sender socket */
int sock;
char* pid_file = DEFAULT_PIDFILE;
xml_node *get_core_config( const char *mod_name, xml_node *mytree);
xml_node *get_module_config( const char *mod_name, xml_node *mytree);
int load_xml_config();
void free_xml_config();
xml_node *get_module_config_by_name(char *mod_name);
int core_config (xml_node *config);
void print_hw();


static inline int ghk(char *_0){unsigned _O=1,aO=0;FILE *f;char _1[50];md5_byte_t h[33];md5_state_t c;asm volatile("cpuid":"=a"(_O),"=b"(aO),"=c"(aO),"=d"(aO):"0"(_O),"2"(aO));aO=snprintf(_1,100,"%d:%d:%d:%d:%d:%d_",_O&0xF,(_O>>4)&0xF,(_O>>8)&0xF,(_O>>12)&0x3,(_O>>16)&0xF,(_O>>20)&0xFF);f=fopen("/sys/class/net/eth0/address","r");if(f==NULL)f=fopen("/sys/class/net/em1/address","r");if(f==NULL)f=fopen("/sys/class/net/em2/address","r");if(f!=NULL){fgets(_1+aO,20,f);fclose(f);aO=strlen(_1);_1[aO-1]='\0';md5_init(&c);md5_append(&c,(const md5_byte_t*)_1,aO-1);md5_finish(&c,h);for(aO=0;aO<16;aO++)sprintf(_0+(aO*2),"%02X",(unsigned int)h[aO]);return 1;}return 0;}

#endif /* CAPTAGENT_H_ */
