/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012-2015 (http://www.sipcapture.org)
 *
 * Homer capture agent is free software; you can redistribute it and/or
 * modify
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

#ifndef CONF_FUNCTION_H_
#define CONF_FUNCTION_H_

#define EXPR_DROP -127  /* used only by the expression and if evaluator */
#define E_BUG         -5

enum { EXP_T=1, ELEM_T };
enum { AND_OP=1, OR_OP, NOT_OP };
enum { EQUAL_OP=10, MATCH_OP, NO_OP };
enum { METHOD_O=1, DEFAULT_O, ACTION_O, NUMBER_O};

enum { FORWARD_T=1, SEND_T, DROP_T, IF_T, MODULE_T};
enum { NOSUBTYPE=0, STRING_ST, NET_ST, ACTIONS_ST, CMDF_ST, EXPR_ST, NUMBER_ST };

struct run_act_ctx;


struct expr{
        int type; /* exp, exp_elem */
        int op; /* and, or, not | ==,  =~ */
        int  subtype;
        union {
                struct expr* expr;
                int operand;
        }l;
        union {
                struct expr* expr;
                void* param;
                int   intval;
        }r;
};

static int eval_elem(struct run_act_ctx* h, struct expr* e, msg_t* msg);
int eval_expr(struct run_act_ctx* h, struct expr* e, msg_t* msg);
int capture_get(struct capture_list* rt, char* name);
void push(struct action* a, struct action** head);
struct expr* mk_exp(int op, struct expr* left, struct expr* right);
struct expr* mk_elem(int op, int subtype, int operand, void* param);
struct action* mk_action(int type, int p1_type, int p2_type, void* p1, void* p2);
struct action* mk_action3(int type, int p1_type, int p2_type, int p3_type, void* p1, void* p2, void* p3);
struct action* append_action(struct action* a, struct action* b);

void print_action(struct action* a);
void print_expr(struct expr* exp);

typedef  int (*response_function)(struct sip_msg*);
typedef int (*child_init_function)(int rank);

struct sr_module{
        char* path;
        void* handle;
        struct module_exports* exports;
        struct sr_module* next;
};

struct sr_module* modules; /* global module list */

int register_builtin_modules();
int load_module(char* path);
cmd_function find_export2(char* name, int param_no);
struct sr_module* find_module(void *f, int* r);
void destroy_modules();
int init_child(int rank);
int init_modules(void);

/*
 * Find a parameter with given type and return it's
 * address in memory
 * If there is no such parameter, NULL is returned
 */
void* find_param_export(char* mod, char* name, modparam_t type);

/* new */
cmd_function find_export(char* name, int param_no, int flags);
cmd_export_t* find_mod_export_record(char* mod, char* name, int param_no, int flags, unsigned* mod_if_ver);
cmd_export_t* find_export_record(char* name,  int param_no, int flags, unsigned* mod_if_ver);

#endif /* CONF_FUNCTION_H_ */
