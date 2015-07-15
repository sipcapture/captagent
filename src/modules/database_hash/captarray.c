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
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "captarray.h"
#include "src/api.h"
#include "src/log.h"

      
pthread_t thread_timer;

struct list_head g_queue_head;

void timer_init () {

          /* start waiting thread */
        if( pthread_create(&thread_timer , NULL , timer_loop, NULL) < 0) {
            fprintf(stderr, "could not create timer thread");
        }        
}

int add_timer(char *pid)
{
	timer_queue_t *timer_node = (timer_queue_t *)malloc(sizeof(timer_queue_t));

	if (IS_EQUAL(timer_node, NULL)) {
		perror("add cus-group:");
		return -1;
	}

	memset(timer_node, 0, sizeof(timer_queue_t));
	timer_node->expire = (unsigned)time(NULL) + expire_timer_array;  
	snprintf(timer_node->id, sizeof(timer_node->id), "%s", pid);
	list_add_tail(&timer_node->node, &g_queue_head);

	return 0;
}

int delete_timer(timer_queue_t *timer)
{
	list_del(&timer->node);
	free(timer);
	return 1;
}

int gather_data_run()
{
	timer_queue_t *pos, *lpos;
	unsigned int mycount = 0;

	while (timer_loop_stop) {

		list_for_each_entry_safe(pos, lpos, &g_queue_head, node)
		{

			while (pos->expire > time(NULL)) {
				sleep(1);
			}

			if (check_ipport(pos->id) == 0) {
				add_timer(pos->id);
			}

			delete_timer(pos);
			mycount = list_size();

		}

		if (mycount == 0) sleep(1);
	}

	return 1;
}

int list_size() {

        unsigned int count = 0;
        
        timer_queue_t *pos, *lpos;
                
        list_for_each_entry_safe(pos, lpos, &g_queue_head, node) count++;

        return count;
}

void* timer_loop() {

	INIT_LIST_HEAD(&g_queue_head);

    gather_data_run();

    return (void*) 1;
}
