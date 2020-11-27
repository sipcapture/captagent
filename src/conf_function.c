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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>


#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/capture.h>
#include <captagent/xmlread.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include <captagent/log.h>
#include "md5.h"
#include <captagent/globals.h>
#include <captagent/capture.h>
#include <captagent/action.h>
#include "conf_function.h"

#define E_UNSPEC      -1
#define MAX_REC_LEV 100 /* maximum number of recursive calls */
#define ROUTE_MAX_REC_LEV 10 /* maximum number of recursive calls
                                                           for capture()*/

/* ret= 0! if action -> end of list(e.g DROP),
      > 0 to continue processing next actions
   and <0 on error */
int do_action(struct run_act_ctx* h, struct action* a, msg_t* msg)
{
        int ret = 0;
        int v;
        union sockaddr_union* to;
        struct socket_info* send_sock;
        struct proxy_l* p;
        char* tmp;
        char *new_uri, *end, *crt;
        int len;
        int user;
        unsigned short port;

        /* reset the value of error to E_UNSPEC so avoid unknowledgable
           functions to return with errror (status<0) and not setting it
           leaving there previous error; cache the previous value though
           for functions which want to process it */
        ret = 1;
        switch (a->type){
                case DROP_T:
                    ret=0;
                    break;
		case IF_T:
                		/* if null expr => ignore if? */
                                if ((a->p1_type==EXPR_ST)&&a->p1.data){
                                        v=eval_expr(h, (struct expr*)a->p1.data, msg);
                                        if (v<0){
                                                if (v==EXPR_DROP){ /* hack to quit on DROP*/
                                                        ret=0;
                                                        break;
                                                }else{
                                                        LERR("WARNING: do_action: error in expression\n");
                                                }
                                        }
                                         
                                        ret=1;  /*default is continue */
                                        if (v>0) {
                                                if ((a->p2_type==ACTIONS_ST)&&a->p2.data){
							ret=run_actions(h,(struct action*)a->p2.data, msg);
                                                }
                                        }else if ((a->p3_type==ACTIONS_ST)&&a->p3.data){
                                                        ret=run_actions(h,(struct action*)a->p3.data, msg);
                                        }
                                }
                        break;   
                    
               case MODULE_T:
                        if ( ((a->p1_type==CMDF_ST)&&a->p1.data)){
                                ret=((cmd_function)(a->p1.data))(msg, (char*)a->p2.data, (char*)a->p3.data);
                        }else{
                                LERR("BUG: do_action: bad module call\n");
                        }
                        break;
                    
                default:
                        LERR("BUG: do_action: unknown type %d\n", a->type);
                        ret = 0;
        }

        return ret;
}

static int eval_elem(struct run_act_ctx* h, struct expr* e, msg_t* msg)
{
 
        int ret;
        ret=E_BUG;
 
        if (e->type!=ELEM_T){
                LERR(" BUG: eval_elem: invalid type\n");
                goto error;
        }
        switch(e->l.operand){
                case NUMBER_O:
                                ret=!(!e->r.intval); /* !! to transform it in {0,1} */
                                break;
                case ACTION_O:
                                ret=run_actions(h,(struct action*)e->r.param, msg);
                                if (ret<=0) ret=(ret==0)?EXPR_DROP:0;
                                else ret=1;
                                break;
                default:
                                LERR("BUG: eval_elem: invalid operand %d\n",e->l.operand);
        }
        return ret;
error:
        return -1;

}




/* ret= 0/1 (true/false) ,  -1 on error or EXPR_DROP (-127)  */
int eval_expr(struct run_act_ctx* h, struct expr* e, msg_t* msg)
{
        int ret;
        
        LDEBUG("EVAL_EXPR: [%d]->[%d]", h->route_rec_lev, h->rec_lev);

        h->rec_lev++;
        if (h->rec_lev>MAX_REC_LEV){
                LERR("ERROR: eval_expr: too many expressions (%d)\n", h->rec_lev);
                ret=-1;   
                goto skip;
        }
        
        if (e->type==ELEM_T){
                ret=eval_elem(h, e, msg);
        }else if (e->type==EXP_T){
                switch(e->op){
                        case AND_OP:
                                ret=eval_expr(h, e->l.expr, msg);
                                /* if error or false stop evaluating the rest */
                                if (ret!=1) break;
                                ret=eval_expr(h, e->r.expr, msg); /*ret1 is 1*/
                                break;
                        case OR_OP:
                                ret=eval_expr(h, e->l.expr, msg);
                                /* if true or error stop evaluating the rest */
                                if (ret!=0) break;
                                ret=eval_expr(h, e->r.expr, msg); /* ret1 is 0 */
                                break;
                        case NOT_OP:
                                ret=eval_expr(h, e->l.expr, msg);
                                if (ret<0) break;
                                ret= ! ret;
                                break;
                        default:
                                LERR("BUG: eval_expr: unknown op %d\n", e->op);
                                ret=-1;
                }
        }else{
                LERR("BUG: eval_expr: unknown type %d\n", e->type);
                ret=-1;
        }

skip:
        h->rec_lev--;
        return ret;
}


/* returns: 0, or 1 on success, <0 on error */
/* (0 if drop or break encountered, 1 if not ) */
int run_actions(struct run_act_ctx* h, struct action* a, msg_t* msg)
{
        struct action* t;
        int ret=E_UNSPEC;
        struct sr_module *mod;

        LDEBUG("RUN: [%d]->[%d]", h->route_rec_lev, h->rec_lev);

        h->route_rec_lev++;
        if (h->route_rec_lev>ROUTE_MAX_REC_LEV){
                printf("WARNING: too many recursive routing table lookups (%d)"
                                        " giving up!\n", h->route_rec_lev);
                printf("WARNING: Action: type: (%d), Ret: (%d), p2_type: (%s), p3_type: (%s)\n", a->type, ret, (char *)a->p2.data, (char *)a->p3.data);                                
                                                                        
                ret=E_UNSPEC;
                goto error;
        }

        if (a==0){
                printf("WARNING: run_actions: null action list (rec_level=%d)\n",
                        h->route_rec_lev);
                ret=0;
        }

        for (t=a; t!=0; t=t->next){
                ret=do_action(h, t, msg);
                if(ret==0) break;
                /* ignore errors */
                //else if (ret<0){ ret=-1; goto error; }
        }

        h->route_rec_lev--;
        /* process module onbreak handlers if present */
        if (h->route_rec_lev==0 && ret==0)
                for (mod=modules;mod;mod=mod->next)
                        if (mod->exports && mod->exports->onbreak_f) {
                                mod->exports->onbreak_f( msg );
                                printf("DEBUG: %s onbreak handler called\n", mod->exports->name);
                        }
        return ret;


error:
        h->route_rec_lev--;
        return ret;
}


int capture_get(struct capture_list* rt, char* name)
{
        int len;
        int i;

        //printf("!!!!!!!!!!!!!!!---------------> ROUTE GET: %s, E: [%d], I: [%d]\n", name, rt->entries, rt->idx);

        rt->entries+=1;
        rt->idx+=1;
        
        //printf("!!!!!!!!!!!!!!!---------------> ROUTE GET NN: [%d], I:[%d]\n", rt->entries, rt->idx);
        
        /* check if exists an non empty*/
        return rt->idx;
error:
        return -1;
}

/* adds an action list to head; a must be null terminated (last a->next=0))*/
void push(struct action* a, struct action** head)
{

        struct action *t;
        if (*head==0){
                *head=a;
                return;
        }

        /* go to the end of the list, then append */
        for (t=*head; t->next;t=t->next)
                ;
        t->next=a;
}

/* searches the module list and returns a pointer to the "name" function or
 * 0 if not found */

cmd_function find_export2(char* name, int param_no)
{
        struct sr_module* t;
        cmd_function s;
        int r;

        for(t=modules;t;t=t->next){
                for(r=0;r<t->exports->cmd_no;r++){
                        if((strcmp(name, t->exports->cmd_names[r])==0)&&
                                (t->exports->param_no[r]==param_no) ){
                                printf("find_export: found <%s> in module %s [%s]\n",
                                                name, t->exports->name, t->path);
                                return t->exports->cmd_pointers[r];
                        }
                }
        }
        LERR("find_export: <%s> not found \n", name);
        return s;
}


void* find_param_export(char* mod, char* name, modparam_t type)
{
        struct sr_module* t;
        int r;

        for(t = modules; t; t = t->next) {
                if (strcmp(mod, t->exports->name) == 0) {
                        for(r = 0; r < t->exports->par_no; r++) {
                                if ((strcmp(name, t->exports->param_names[r]) == 0) &&
                                    (t->exports->param_types[r] == type)) {
                                        printf("find_param_export: found <%s> in module %s [%s]\n",
                                            name, t->exports->name, t->path);
                                        return t->exports->param_pointers[r];
                                }
                        }
                }
        }
        LERR("find_param_export: parameter <%s> or module <%s> not found\n",
                        name, mod);
        return 0;
}


struct action* append_action(struct action* a, struct action* b)
{
        struct action *t;
        

        if (b==0) return a;
        if (a==0) return b;

        for(t=a;t->next;t=t->next);
        t->next=b;
        return a;
}



struct expr* mk_exp(int op, struct expr* left, struct expr* right)
{
        struct expr * e;
        
        
        e=(struct expr*)malloc(sizeof (struct expr));
        if (e==0) goto error;
        e->type=EXP_T;
        e->op=op;
        e->l.expr=left;
        e->r.expr=right;
        return e;
error:
        printf( "ERROR: mk_exp: memory allocation failure\n");
        return 0;
}


struct expr* mk_elem(int op, int subtype, int operand, void* param)
{
        struct expr * e;
        
        e=(struct expr*)malloc(sizeof (struct expr));
        if (e==0) goto error;
        e->type=ELEM_T;
        e->op=op;
        e->subtype=subtype;
        e->l.operand=operand;
        e->r.param=param;
        return e;
error:
        LERR( "ERROR: mk_elem: memory allocation failure\n");
        return 0;
}

struct action* mk_action(int type, int p1_type, int p2_type,
                                                                                        void* p1, void* p2)
{
        struct action* a;
        
        a=(struct action*)malloc(sizeof(struct action));
        if (a==0) goto  error;
        memset(a,0,sizeof(struct action));
        a->type=type;
        a->p1_type=p1_type;
        a->p2_type=p2_type;
        a->p1.string=(char*) p1;
        a->p2.string=(char*) p2;
        a->next=0;
        return a;

error:
        LERR( "ERROR: mk_action: memory allocation failure\n");
        return 0;

}



struct action* mk_action3(int type, int p1_type, int p2_type, int p3_type,
                                                        void* p1, void* p2, void* p3)
{
        struct action* a;

        //printf("ZZ TYPE: [%d], PLTYPE1: [%d], PLTYPE2: [%d], PLTYPE3: [%d]\n", type, p1_type, p2_type, p3_type);

        a=mk_action(type, p1_type, p2_type, p1, p2);
        if (a){
                        a->p3_type=p3_type;
                        a->p3.data=p3;
        }
        return a;
}


/* new one */
cmd_export_t* find_export_record(char* name,  int param_no, int flags, unsigned* mod_if_ver)
{
        return find_mod_export_record(0, name, param_no, flags, mod_if_ver);
}

cmd_export_t* find_mod_export_record(char* mod, char* name, int param_no, int flags, unsigned* mod_if_ver)
{
        struct module* t;
        cmd_export_t* cmd;


        for(t=module_list;t;t=t->next){

                if (mod!=0 && (strcmp(t->name, mod) !=0))
                        continue;
                if (t->cmds)
                        for(cmd=&t->cmds[0]; cmd->name; cmd++) {
                                //LERR("NAME: [%s] vs [%s]\n", name, cmd->name);
                                //LERR("PARAM: [%d] vs [%d]\n", param_no, cmd->param_no);
                        
                                if((strcmp(name, cmd->name) == 0) &&
                                        ((cmd->param_no == param_no) ||
                                         (cmd->param_no==VAR_PARAM_NO)) &&
                                        ((cmd->flags & flags) == flags)
                                ){
                                		LDEBUG("find_export_record: found <%s> in module %s [%s]",  name, t->name, t->path);
                                        return cmd;
                                }
                        }
        }
        LERR("find_export_record: <%s> not found \n", name);
        return 0;
}

cmd_function find_mod_export(char* mod, char* name, int param_no, int flags)
{
        cmd_export_t* cmd;
        unsigned mver;

        cmd=find_mod_export_record(mod, name, param_no, flags, &mver);
        if (cmd)
                return cmd->function;

        LERR("find_mod_export: <%s> in module <%s> not found\n", name, mod);
        return 0;
}

cmd_function find_export(char* name, int param_no, int flags)
{
        cmd_export_t* cmd;
        unsigned mver;

        cmd = find_export_record(name, param_no, flags, &mver);
        return cmd?cmd->function:0;
}






