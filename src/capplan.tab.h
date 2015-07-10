/* A Bison parser, made by GNU Bison 2.5.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2011 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */


/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     FORWARD = 258,
     SEND = 259,
     DROP = 260,
     IF = 261,
     ELSE = 262,
     METHOD = 263,
     CAPTURE = 264,
     DEBUG = 265,
     EQUAL = 266,
     EQUAL_T = 267,
     MATCH = 268,
     OR = 269,
     AND = 270,
     NOT = 271,
     NUMBER = 272,
     ID = 273,
     STRING = 274,
     IPV6ADDR = 275,
     COMMA = 276,
     SEMICOLON = 277,
     RPAREN = 278,
     LPAREN = 279,
     LBRACE = 280,
     RBRACE = 281,
     LBRACK = 282,
     RBRACK = 283,
     SLASH = 284,
     DOT = 285,
     CR = 286
   };
#endif



#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE
{

/* Line 2068 of yacc.c  */
#line 35 "capplan.y"

	int intval;
	unsigned uval;
	char* strval;
	struct expr* expr;
	struct action* action;
	struct net* ipnet;



/* Line 2068 of yacc.c  */
#line 92 "capplan.tab.h"
} YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
#endif

extern YYSTYPE yylval;


