/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2014 (http://www.sipcapture.org)
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


#include <signal.h>
#include <time.h>
#include <pthread.h>
#include "capthash.h"

struct ipport_items *ipports = NULL;
pthread_t thread_timer;
pthread_rwlock_t call_lock;
pthread_rwlock_t ipport_lock;
pthread_rwlock_t io_lock;

/* ADD IPPPORT  */
void add_ipport(char *key, str *callid) {

        struct ipport_items *ipport;
        int index = 0;

        ipport = (struct ipport_items*)malloc(sizeof(struct ipport_items));

        snprintf(ipport->name, sizeof(ipport->name), "%s",  key);        
                
        snprintf(ipport->callid, sizeof(ipport->callid), "%.*s", callid->len, callid->s);        
        ipport->modify_ts = (unsigned)time(NULL);
                                
        if (pthread_rwlock_wrlock(&ipport_lock) != 0) {
                fprintf(stderr,"can't acquire write lock");
                exit(-1);
        }     
              
        HASH_ADD_STR(ipports, name, ipport);
                        
        pthread_rwlock_unlock(&ipport_lock);
                
}     

struct ipport_items *find_ip_port_paar(char *ip, int port) {

        char name[300];

        snprintf(name, sizeof(name), "%s:%d",  ip, port);

        return find_ipport(name);
}

int find_and_update(char *callid, const char *srcip, int srcport, const char *dstip, int dstport) {

        ipport_items_t *ipport;
        int ret = 0;
        char name[300];

        snprintf(name, sizeof(name), "%s:%d",  srcip, srcport);

        if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
                fprintf(stderr,"can't acquire write lock");
                exit(-1);
        }

        HASH_FIND_STR( ipports, name, ipport);

        if(!ipport) {
             snprintf(name, sizeof(name), "%s:%d",  dstip, dstport);   
             HASH_FIND_STR( ipports, name, ipport);                                                          
        }
                
        if(ipport) {                
                snprintf(callid,sizeof(ipport->callid), "%s", ipport->callid);
                ipport->modify_ts = (unsigned)time(NULL);                    
                ret = 1;    
        }

        pthread_rwlock_unlock(&ipport_lock);

        return ret;        
}

struct ipport_items *find_ipport(char *name) {

        ipport_items_t *ipport;

        if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
                fprintf(stderr,"can't acquire write lock");
                exit(-1);
        }

        HASH_FIND_STR( ipports, name, ipport);

        pthread_rwlock_unlock(&ipport_lock);

        return ipport;
}

int clear_ipport(struct ipport_items *ipport ) {

	if(ipport) {

                if (pthread_rwlock_wrlock(&ipport_lock) != 0) {
                        fprintf(stderr, "can't acquire write lock");
                        exit(-1);
                }

                HASH_DEL( ipports, ipport);

                free(ipport);
                
                pthread_rwlock_unlock(&ipport_lock);
                
                return 1;
        }

        return 0;
}

int check_ipport(char *name)  {

	struct ipport_items *ipport;
	int ret = 1;

        if (pthread_rwlock_rdlock(&ipport_lock) != 0) {
                fprintf(stderr, "can't acquire write lock");
                exit(-1);
        }
 
        HASH_FIND_STR( ipports, name, ipport);
        
        if(ipport) {
        	if(((unsigned) time(NULL) - ipport->modify_ts) >=  expire_hash_value) {

                        HASH_DEL( ipports, ipport);
                        free(ipport);
                        ret = 2;
        	}
        	else {
        	
        	        ret = 0;
        	}
        }

        pthread_rwlock_unlock(&ipport_lock);
 
        return ret;      
}

int delete_ipport(char *ip, int port) {

        struct ipport_items *ipport;

        ipport = find_ip_port_paar(ip, port);

        return clear_ipport(ipport);
}

void clear_ipports() {

        struct ipport_items *s, *tmp;
        if (pthread_rwlock_wrlock(&ipport_lock) != 0) {
                        fprintf(stderr, "can't acquire write lock");
                        exit(-1);
        }
        /* free the hash table contents */
        HASH_ITER(hh, ipports, s, tmp) {
                HASH_DEL(ipports, s);
                free(s);
        }
         
        pthread_rwlock_unlock(&ipport_lock);
}
