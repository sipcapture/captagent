#ifndef action_h
#define action_h


struct action{
        int type;  /* forward, drop, log, send ...*/
        int index; 
        int p1_type; 
        int p2_type;
        int p3_type;
        union {
                int number;
                char* string;
                void* data;
        }p1, p2, p3;
        struct action* next;
};


struct run_act_ctx{
        int rec_lev;
        int run_flags;
        int last_retcode; /* return from last route */
};

int do_action(struct run_act_ctx* c, struct action* a, msg_t *msg);
int run_actions(struct run_act_ctx* c, struct action* a, msg_t* msg);

#endif

