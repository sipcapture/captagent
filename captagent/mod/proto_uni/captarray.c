/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-14 (http://www.sipcapture.org)
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


#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include "capthash.h"
#include "captarray.h"
#include "src/api.h"
       

pthread_t thread_timer;
int loop_stop = 1;

void ippexpire_copy(void *_dst, const void *_src) {
  ipp_expire_t *dst = (ipp_expire_t*)_dst, *src = (ipp_expire_t*)_src;
  dst->expire = src->expire;
  dst->id = src->id ? strdup(src->id) : NULL;
}

void ippexpire_dtor(void *_elt) {
  ipp_expire_t *elt = (ipp_expire_t*)_elt;
  if (elt->id) free(elt->id);
}

UT_array *ipps_expire;
UT_icd ipps_icd = {sizeof(ipp_expire_t), NULL, ippexpire_copy, ippexpire_dtor};


void ippexpire_init () {

        utarray_new(ipps_expire, &ipps_icd);

          /* start waiting thread */
        if( pthread_create(&thread_timer , NULL , timer_loop, NULL) < 0) {
            fprintf(stderr, "could not create timer thread");
            return 3;
        }        
}

/* ADD IPPPORT  */
void add_timer(char *pid) {

        ipp_expire_t ce;

        ce.expire = (unsigned)time(NULL) + EXPIRE_ARRAY;  
        ce.id = pid;  
        utarray_push_back(ipps_expire,&ce);                
}     

void clear_ippexpires() {

        ipp_expire_t *p = NULL;
          
        for(p=(ipp_expire_t*)utarray_front(ipps_expire);
            p!=NULL;
            p=(ipp_expire_t*)utarray_next(ipps_expire,p)) 
        {
                printf("%s %d\n", p->id, p->expire);
        }
                          
        utarray_free(ipps_expire);          
}

void* timer_loop() {

        ipp_expire_t *p = NULL;
                
        while(loop_stop) {
                
                while( (p=(ipp_expire_t*)utarray_next(ipps_expire,p))) {
                
                    while(p->expire > (unsigned)time(NULL))
                    {
                          if(!loop_stop) break;
                          sleep(2);                          
                    }
			
		    if(check_ipport(p->id) == 0) {
			add_timer(p->id);
		    }
                    
		    utarray_erase(ipps_expire, 0, 1);                                         
                    
                    if(!loop_stop) break;
                                        
                    //printf("%d %s\n", p->a, (p->s ? p->s : "null"));
                }
                                
                sleep(1);                
        }
        
        utarray_free(ipps_expire);

        return (void*) 1;  
}
