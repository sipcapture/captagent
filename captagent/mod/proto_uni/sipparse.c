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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>       
#include "sipparse.h"

int set_hname(str *hname, int len, char *s) {
                
        char *end;

        if(hname->len  > 0) {
                return 0;
        }		
	
        end = s + len;
        for(; s < end; s++) {
                len--;
                if ((*s != ' ') && (*s != ':') && (*s != '\t')) {
                        len--;
                        break;
                }
        }           
        
        hname->s = s;        
        hname->len = len;        
        return 1;
}


int parseSdpMLine(miprtcp_t *mp, char *data, int len) {

        enum state {
                ST_TYPE,
                ST_PORT,
                ST_END
        };

        enum state st;
        int last_offset = 0, i;

        st = ST_TYPE;
        last_offset = 0;

        for(i = 0; i < len; i++) {

                switch(st) {

                        case ST_TYPE:
                                if(data[i] == ' ')  {
                                   st = ST_PORT;
                                   last_offset = i;
                                }
                                break;

                        case ST_PORT:
                        	if(data[i] == ' ')  {
                        	   st = ST_END;
                        	   mp->media_port = atoi((char *) data+last_offset);
                        	   last_offset = i;
				   return 1;	
				}
                                break;

                        default:
                                break;

                }
        }

        return 1;
}




int parseSdpALine(miprtcp_t *mp, char *data, int len) {

        enum state {
                ST_START,
                ST_PROTO,
                ST_TYPE,
                ST_IP,
                ST_END
        };

        enum state st;
        int last_offset = 0, i;

        st = ST_START;
        last_offset = 0;

        for(i = 0; i < len; i++) {

                switch(st) {

                        case ST_START:
                                if(data[i] == ' ')  {                                   
                                   mp->rtcp_port = atoi( (char *)data); 
                                   st = ST_PROTO;
                                   last_offset = i;
                                }
                                break;

                        case ST_PROTO:
                                if(data[i] == ' ')  {                                   
                                   st = ST_TYPE;
                                   last_offset = i;
                                }
                                break;

                        case ST_TYPE:
                                if(data[i] == ' ')  {                                   
                                   st = ST_IP;
                                   last_offset = i;
                                }
                                break;                                

                        case ST_IP:
                                st = ST_END;
                                mp->rtcp_ip.s = (char *) data+last_offset+1;
                                mp->rtcp_ip.len = len-last_offset-3;
                                st = ST_END;
				return 1;	
				
                                break;

                        default:
                                break;

                }
        }

        return 1;
}

int parseSdpCLine(miprtcp_t *mp, char *data, int len) {

        enum state {
                ST_NETTYPE,
                ST_ADDRTYPE,
                ST_CONNECTIONADRESS,
                ST_END
        };

        /* c=IN IP4 224.2.17.12 */
 
        enum state st;
        int last_offset = 0, i;

        st = ST_NETTYPE;
        last_offset = 0;

        for(i = 0; i < len; i++) {

                switch(st) {

                        case ST_NETTYPE:
                                if(data[i] == ' ')  {
                                   st = ST_ADDRTYPE;
                                   last_offset = i;
                                }
                                break;

                        case ST_ADDRTYPE:
                        	if(data[i] == ' ')  {
                        	       st = ST_CONNECTIONADRESS;
                        	       last_offset = i;
                        	}

                                break;
                        case ST_CONNECTIONADRESS:
				mp->media_ip.s = (char *)data+last_offset+1;
                        	mp->media_ip.len = len-last_offset-3;
                        	st = ST_END;
                                break;

                        default:
                                break;

                }
        }

        return 1;
}



int parseSdp(char *body, struct preparsed_sip *psip) {

        char *c, *tmp;
        int offset, last_offset, set_ip = 0;

        c = (char *) body;
	last_offset = 0;
	offset = 0;
	psip->mrp_size = 0;
	miprtcp_t *mp = NULL;

	//m=audio 3000 RTP/AVP 8 0 18 101
	//m=image 49170 udptl t38

	for (; *c; c++) {
	           /* END MESSAGE and START BODY */
               if (*c == '\r' && *(c+1) == '\n') {        /* end of this line */
                     //*c = '\0';
                     last_offset = offset;
                     offset = (c+2) - body;
                     tmp = (char *) (body + last_offset);

                     if(strlen(tmp) < 4) continue;

                     /* c=IN IP4 10.0.0.1 */
                     if((*tmp == 'c' && *(tmp+1) == '='))
                     {
                         memset(&psip->mrp[psip->mrp_size], 0, sizeof(miprtcp_t *));                                                     

                         mp = &psip->mrp[psip->mrp_size]; 
                         
                         mp->media_ip.len = 0;
                         mp->media_ip.s = NULL;
                         
                         mp->rtcp_ip.len = 0;
                         mp->rtcp_ip.s = NULL;
                         
                         mp->media_port = 0;
                         mp->rtcp_port = 0;
                         
                    	 parseSdpCLine(mp, tmp+2, (offset - last_offset - 2));
                    	 psip->mrp_size++;                        	 
                    	 set_ip = 1;
                    	 
                     }

                     /* m=audio 3000 RTP/AVP 8 0 18 101 */
                     if((*tmp == 'm' && *(tmp+1) == '='))
                     {   
                         if(mp == NULL) {
                            printf("BAD SDP. Couldn't parse it!\n");
                            return 0;
                         }
                     
                         if(set_ip == 1) set_ip = 0;
                         else {                                                                             

                             memset(&psip->mrp[psip->mrp_size], 0, sizeof(miprtcp_t *));                                                        
                             psip->mrp[psip->mrp_size].media_ip.s =  psip->mrp[psip->mrp_size-1].media_ip.s;                             
                             psip->mrp[psip->mrp_size].media_ip.len =  psip->mrp[psip->mrp_size-1].media_ip.len;                           
                             mp = &psip->mrp[psip->mrp_size];
                             
                             mp->media_ip.len = 0;
                             mp->media_ip.s = NULL;
                         
                             mp->rtcp_ip.len = 0;
                             mp->rtcp_ip.s = NULL;
                         
                             mp->media_port = 0;
                             mp->rtcp_port = 0;
                             
                             psip->mrp_size++;
                         }                         
                                                                       
                    	 parseSdpMLine(mp, tmp+2, (offset - last_offset - 2));                    	 
                    	 
                     }
		     /* a=rtcp:53020 IN IP4 126.16.64.4 */
		     else if((*tmp == 'a' && *(tmp+1) == '=') && !memcmp(tmp+2, "rtcp:", 5))
                     {
                          if(mp == NULL) {
                              printf("BAD SDP. Couldn't parse it [RTCP]!\n");
                              return 0;
                          }                                                                                                           
                     
                    	 parseSdpALine(mp, tmp+7, (offset - last_offset - 7));
                     }
		}
		
		if(psip->mrp_size > 10) break;
	}

	return 1;
}


int parse_message(char *message, unsigned int blen, unsigned int* bytes_parsed, struct preparsed_sip *psip)
{
	unsigned int new_len = blen;
	int header_offset = 0;
	
	if (blen <= 2) return 0;

        int offset = 0, last_offset = 0, hasSdp = 0;
        char *c, *tmp;

        c = message;

        /* Request/Response line */
        for (; *c && c-message < new_len; c++) {
                if (*c == '\n' && *(c-1) == '\r') {
                        offset = (c + 1) - message;
                        break;
                }
        }        

	if(offset == 0) { // likely Sip Message Body only...

            *bytes_parsed = c-message;
            return 0;
        }

        psip->reply = 0;
        memset(psip->reason, 0, sizeof(psip->reason));

        tmp = (char *) message;

        if(!memcmp("SIP/2.0 ", tmp, 8)) {
                psip->reply = atoi(tmp+8);
                psip->is_method = SIP_REPLY;

                // Extract Response code's reason
                char *reason = tmp+12;
                for (; *reason; reason++) {
                        if (*reason == '\n' && *(reason-1) == '\r') {
                                break;
                        }
                }
                memcpy(psip->reason, tmp+12, reason-(tmp+13/*that's covering /r/n*/));
        }
        else {
                psip->is_method = SIP_REQUEST;

                if(!memcmp(tmp, INVITE_METHOD, INVITE_LEN)) psip->method = INVITE_METHOD;
                else if(!memcmp(tmp, ACK_METHOD, ACK_LEN)) psip->method = ACK_METHOD;
		else if(!memcmp(tmp, BYE_METHOD, BYE_LEN)) psip->method = BYE_METHOD;
		else if(!memcmp(tmp, CANCEL_METHOD, CANCEL_LEN)) psip->method = CANCEL_METHOD;
		else if(!memcmp(tmp, OPTIONS_METHOD, OPTIONS_LEN)) psip->method = OPTIONS_METHOD;
		else if(!memcmp(tmp, REGISTER_METHOD, REGISTER_LEN)) psip->method = REGISTER_METHOD;
		else if(!memcmp(tmp, PRACK_METHOD, PRACK_LEN)) psip->method = PRACK_METHOD;
		else if(!memcmp(tmp, SUBSCRIBE_METHOD, SUBSCRIBE_LEN)) psip->method = SUBSCRIBE_METHOD;						
		else if(!memcmp(tmp, NOTIFY_METHOD, NOTIFY_LEN)) psip->method = NOTIFY_METHOD;						
		else if(!memcmp(tmp, PUBLISH_METHOD, PUBLISH_LEN)) psip->method = PUBLISH_METHOD;
		else if(!memcmp(tmp, INFO_METHOD, INFO_LEN)) psip->method = INFO_METHOD;
		else if(!memcmp(tmp, REFER_METHOD, REFER_LEN)) psip->method = REFER_METHOD;						
		else if(!memcmp(tmp, MESSAGE_METHOD, MESSAGE_LEN)) psip->method = MESSAGE_METHOD;
                else if(!memcmp(tmp, UPDATE_METHOD, UPDATE_LEN)) psip->method = UPDATE_METHOD;						
		else
                {
		    int offset2 = 0;
		    char *c = tmp;
		    char method[32] = {0};
		    
		    for (; *c; c++) {
		        if (*c == ' ' || (*c == '\n' && *(c-1) == '\r') || c-tmp > 31) {
			    offset2 = c - tmp;
			    break;
			}
                    }

                    snprintf(method, sizeof(method), "%.*s", offset2, tmp);
                    psip->method = UNKNOWN_METHOD;
                }
        }
	
        c=message+offset;
        int contentLength = 0;

        for (; *c && c-message < new_len; c++) {

                        /* END of Request line and START of all other headers */
                        if (*c == '\r' && *(c+1) == '\n') {        /* end of this line */

				last_offset = offset;
				offset = (c+2) - message;

				tmp = (message + last_offset);

				/* BODY */
	        	        if(contentLength > 0 && (offset - last_offset) == 2) {
        		        		        
                            	   	if( hasSdp) {
						parseSdp(c, psip);
                            	   	}
					
					break;
		                }

				if((*tmp == 'i' && *(tmp+1) == ':') || ((*tmp == 'C' || *tmp == 'c') && (*(tmp+5) == 'I' || *(tmp+5) == 'i') && *(tmp+CALLID_LEN) == ':')) 
                               {

                            		if(*(tmp+1) == ':') header_offset = 1;
					else header_offset = CALLID_LEN;
                                        set_hname(&psip->callid, (offset - last_offset - CALLID_LEN), tmp+CALLID_LEN);                                                                                         
					continue;                               
                                }
				/* Content-Length */
                                if((*tmp == 'l' && *(tmp+1) == ':') || ((*tmp == 'C' || *tmp == 'c') && ( *(tmp+8) == 'L' || *(tmp+8) == 'l') && *(tmp+CONTENTLENGTH_LEN) == ':'))
                                {

					if(*(tmp+1) == ':') header_offset = 1;
                            	   	else header_offset = CONTENTLENGTH_LEN;
					
  					contentLength = atoi(tmp+header_offset+1);
					continue;
                               }
                                /* content type  Content-Type: application/sdp  CONTENTTYPE_LEN */
                               else if(((*tmp == 'C' || *tmp == 'c') && (*(tmp+7) == '-') && ( *(tmp+8) == 't' || *(tmp+8) == 'T') && *(tmp+CONTENTTYPE_LEN) == ':'))
                               {

                            	   	if(*(tmp+CONTENTTYPE_LEN+1) == ' ') header_offset = 14;
                            	   	else header_offset = 13;

                            	   	if(!memcmp((tmp+CONTENTTYPE_LEN+header_offset), "sdp", 3)) hasSdp = 1;

                                   	continue;
                               }

	        	  }
        }

        return 1;
}

