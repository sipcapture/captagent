
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include "sip.h"


#define SIP_VERSION "SIP/2.0"
#define SIP_VERSION_LEN 7

enum sip_type {
	TYPE_REQUEST = 1,
	TYPE_REPLY = 2
};

/*
 * Find the first occurrence of find in s, where the search is limited to the
 * first slen characters of s (case insensitive).
 */
char *strncasestr(const char* s, const char * find, uint16_t slen) {

	char c, sc;
	uint16_t len;
	char * tmp = s;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if ((sc = *tmp++) == '\0' || slen-- < 1)
					return NULL;
			} while ((sc | 32) != (c | 32));
			if (len > slen)
				return NULL;
		} while (strncasecmp(tmp, find, len) != 0);
		tmp--;
	}
	return tmp;
}

inline static char* eat_space_end(const char* p, const char* pend)
{
	for(;(p<pend)&&(*p==' ' || *p=='\t') ;p++);
	return (char *)p;
}

#define SP(_c) ((_c)=='\t' || (_c)==' ')
inline static char* eat_lws_end(const char* p, const char* pend)
{
	while(p<pend) {
		if (SP(*p)) p++;
		else if (*p=='\n' && p+1<pend && SP(*(p+1))) p+=2;
		else if (*p=='\r' && p+2<pend && *(p+1)=='\n'
					&& SP(*(p+2))) p+=3;
		else break; /* no whitespace encountered */
	}
	return (char *)p;
}

inline static char* eat_token_end(const char* p, const char* pend)
{
	for (;(p<pend)&&(*p!=' ')&&(*p!='\t')&&(*p!='\n')&&(*p!='\r'); p++);
	return (char *)p;
}

char * get_hdr_field (char * buf, uint32_t len){

	char * tmp = buf;
	char * end = tmp + len;
	for (; tmp < end; tmp++){
		switch (*tmp){
			case ':':
				/* eliminate trailing lines */
				/* eliminate leading whitespace */
				tmp=eat_lws_end(tmp + 1, end);
				return tmp;
			default:
				continue;
		}

	}

	return NULL;
}


int sip_is_method(const char * buf, uint32_t len , const char * method){

	char * tmp = NULL;
	short int method_len = strlen (method);
	char * end = buf + len;
	enum sip_type type = TYPE_REQUEST;

	/* eat crlf from the beginning */
	for (tmp=buf; (*tmp=='\n' || *tmp=='\r')&&
			tmp-buf < len ; tmp++);
/* if SIP reply, we search for CSeq to get method*/
	if ( (*tmp=='S' || *tmp=='s') &&
			strncasecmp( tmp+1, SIP_VERSION+1, SIP_VERSION_LEN-1)==0 &&
			(*(tmp+SIP_VERSION_LEN)==' ')) {
				tmp=buf+SIP_VERSION_LEN;
				type = TYPE_REPLY;
				tmp = strncasestr(tmp, "cseq", len - SIP_VERSION_LEN );

				if (tmp){
					tmp = get_hdr_field (tmp, end -tmp );
					if (tmp ==NULL)
					{
						printf("couldn't get cseq header field\n");
						return 1;
					}
					//skip cseq number
					tmp = eat_token_end (tmp, end);
					if (tmp >=end) { printf("parsing error\n"); return 1;}
					//should reach method from cseq
					tmp = eat_space_end (tmp, end);
					if (tmp >=end) { printf("parsing error2\n"); return 1;}

				}
				else {
					printf("no cseq header found\n");
					return 0;
				}
	}


	if ( (*tmp==(method[0]) || *tmp==((method[0]) | 32)) &&
	        strncasecmp( tmp+1, method +1, method_len -1)==0 &&
	       ( type == TYPE_REQUEST ) ? (*(tmp+method_len)==' ') : ( *(tmp+method_len)=='\r' )) {
		return 0;
	}
	else {
		return 1;
	}

}
