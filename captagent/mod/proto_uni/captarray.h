#ifndef _CAPTARRAY_H
#define _CAPTARRAY_H

#include <stdio.h>
#include <stdlib.h>
#include "utarray.h"

typedef struct _ipp_expire {
  char *id;
  u_int32_t expire;
} ipp_expire_t;

void ippexpire_copy(void *_dst, const void *_src);
void ippexpire_dtor(void *_elt);

extern int loop_stop;
extern int expire_timer_array;

void ippexpire_init(); 
void add_timer(char *pid);
void clear_ippexpires();
void* timer_loop();


#endif
