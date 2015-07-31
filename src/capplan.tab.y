/*
*
*/

%{

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <captagent/api.h>
#include <captagent/proto_sip.h>
#include <captagent/structure.h>
#include <captagent/capture.h>
#include <captagent/modules_api.h>
#include <captagent/modules.h>
#include "conf_function.h"
#include <captagent/globals.h>
#include "config.h"

extern int yylex();
void yyerror(char* s);
char* tmp;
void* f_tmp;
static int i_tmp;
extern char *capturename;


%}

%union {
	int intval;
	unsigned uval;
	char* strval;
	struct expr* expr;
	struct action* action;
	struct net* ipnet;
}

/* terminals */


/* keywords */
%token FORWARD
%token SEND
%token DROP
%token IF
%token ELSE
%token METHOD
%token CAPTURE

/* config vars. */
%token DEBUG

/* operators */
%nonassoc EQUAL
%nonassoc EQUAL_T
%nonassoc MATCH
%left OR
%left AND
%left NOT

/* values */
%token <intval> NUMBER
%token <strval> ID
%token <strval> STRING
%token <strval> IPV6ADDR

/* other */
%token COMMA
%token SEMICOLON
%token RPAREN
%token LPAREN
%token LBRACE
%token RBRACE
%token LBRACK
%token RBRACK
%token SLASH
%token DOT
%token CR

%type <expr> exp exp_elem
%type <action> action actions cmd if_cmd stm
%type <strval> capture_name;

%%


cfg:	statements
	;

statements:	statements statement {}
		| statement {}
		| statements error { yyerror(""); YYABORT;}
	;

statement:	assign_stm 
		| capture_stm 
		| CR	/* null statement*/
	;

assign_stm:	DEBUG EQUAL NUMBER { debug=$3; }
		| error EQUAL { yyerror("unknown config variable"); }
	;


capture_name:      ID              { capturename = $1; $$=$1; }
                   |       STRING  { capturename = $1; $$=$1; }
;   



capture_stm:	CAPTURE LBRACE actions RBRACE { push($3, &main_ct.clist[DEFAULT_CT]); }

                | CAPTURE LBRACK capture_name RBRACK LBRACE actions RBRACE { 
                        
                                i_tmp=capture_get(&main_ct, $3);
                                if (i_tmp==-1){
                                        yyerror("internal error");
                                        YYABORT;
                                }
                                if (main_ct.clist[i_tmp]){
                                        yyerror("duplicate capture");
                                        YYABORT;
                                }
                                
		                push($6, &main_ct.clist[i_tmp]);
                }
		| CAPTURE error { yyerror("invalid  capture  statement"); }
	;

exp:	exp AND exp 	{ $$=mk_exp(AND_OP, $1, $3); }
	| exp OR  exp		{ $$=mk_exp(OR_OP, $1, $3);  }
	| NOT exp 			{ $$=mk_exp(NOT_OP, $2, 0);  }
	| LPAREN exp RPAREN	{ $$=$2; }
	| exp_elem			{ $$=$1; }
	;

exp_elem:	METHOD EQUAL_T STRING	{$$= mk_elem(	EQUAL_OP, STRING_ST, METHOD_O, $3);}
		| METHOD EQUAL_T ID	{$$ = mk_elem(	EQUAL_OP, STRING_ST, METHOD_O, $3); }
		| METHOD EQUAL_T error { $$=0; yyerror("string expected"); }
		| METHOD MATCH STRING	{$$ = mk_elem(	MATCH_OP, STRING_ST, METHOD_O, $3); }
		| METHOD MATCH ID	{$$ = mk_elem(	MATCH_OP, STRING_ST, METHOD_O, $3); }
		| METHOD MATCH error { $$=0; yyerror("string expected"); }
		| METHOD error	{ $$=0; yyerror("invalid operator == or =~ expected");}		
		| stm		{ $$=mk_elem( NO_OP, ACTIONS_ST, ACTION_O, $1 ); }
		| NUMBER	{$$=mk_elem( NO_OP, NUMBER_ST, NUMBER_O, (void*)$1 ); }
	;

stm:		cmd						{ $$=$1; }
		|	LBRACE actions RBRACE	{ $$=$2; }
	;

actions:	actions action	{$$=append_action($1, $2); }
		| action			{$$=$1;}
		| actions error { $$=0; yyerror("bad command"); }
	;

action:		cmd SEMICOLON {$$=$1;}
                | if_cmd {$$=$1;}
		| SEMICOLON /* null action */ {$$=0;}
		| cmd error { $$=0; yyerror("bad command: missing ';'?"); }
	;

if_cmd:		IF exp stm				{ $$=mk_action3( IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 NOSUBTYPE,
													 $2,
													 $3,
													 0);
									}
		|	IF exp stm ELSE stm		{ $$=mk_action3( IF_T,
													 EXPR_ST,
													 ACTIONS_ST,
													 ACTIONS_ST,
													 $2,
													 $3,
													 $5);
									}
	;

cmd:		SEND LPAREN STRING RPAREN { $$=mk_action(	SEND_T,
													STRING_ST,
													NUMBER_ST,
													$3,
													0);
									}
		| SEND LPAREN STRING COMMA NUMBER RPAREN {$$=mk_action(	SEND_T, STRING_ST, NUMBER_ST, $3, (void*)$5);												}
		| SEND error { $$=0; yyerror("missing '(' or ')' ?"); }
		| SEND LPAREN error RPAREN { $$=0; yyerror("bad send argument"); }
		| DROP LPAREN RPAREN	{$$=mk_action(DROP_T,0, 0, 0, 0); }
		| DROP {$$=mk_action(DROP_T,0, 0, 0, 0); }
		| ID LPAREN RPAREN			{ f_tmp=(void*)find_export($1, 0, 0);
									   if (f_tmp==0){
										yyerror("unknown command, missing"
										" loadmodule?\n");
										$$=0;
									   }else{
										$$=mk_action(	MODULE_T,
														CMDF_ST,
														0,
														f_tmp,
														0
													);
									   }
									}
		| ID LPAREN STRING RPAREN { f_tmp=(void*)find_export($1, 1, 0);
									if (f_tmp==0){
										yyerror("unknown command, missing"
										" loadmodule?\n");
										$$=0;
									}else{
										$$=mk_action(	MODULE_T,
														CMDF_ST,
														STRING_ST,
														f_tmp,
														$3
													);
									}
								  }
		| ID LPAREN STRING  COMMA STRING RPAREN 
								  { f_tmp=(void*)find_export($1, 2, 0);
									if (f_tmp==0){
										yyerror("unknown command, missing"
										" loadmodule?\n");
										$$=0;
									}else{
										$$=mk_action3(	MODULE_T,
														CMDF_ST,
														STRING_ST,
														STRING_ST,
														f_tmp,
														$3,
														$5
													);
									}
								  }
		| ID LPAREN error RPAREN { $$=0; yyerror("bad arguments"); }
		| if_cmd		{ $$=$1; }
	;


%%

extern int line;
extern int column;
extern int startcolumn;
extern int cfg_errors;

void yyerror(char* s)
{
	printf( "parse error (%d,%d-%d): %s\n", line, startcolumn,  column, s);
	cfg_errors++;
}

/*
int main(int argc, char ** argv)
{
	if (yyparse()!=0)
		fprintf(stderr, "parsing error\n");
}
*/
