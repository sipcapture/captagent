#ifndef _CAPTARRAY_H
#define _CAPTARRAY_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include "list.h"

#define IS_EQUAL(x, y) ((x) == (y))
#define IS_BIGGER (x, y) ((x) > (y))

extern int expire_timer_array;
extern int timer_loop_stop;
extern int check_ipport(char *name);

typedef struct timer_queue {
        struct list_head node;
        char id[256];
        uint32_t expire;
}timer_queue_t;

void timer_init();
int add_timer(char *pid);
int delete_timer(timer_queue_t *timer);
int process_alarm_sig(int sig);
int gather_data_run();
void* timer_loop();
int list_size();

#endif
