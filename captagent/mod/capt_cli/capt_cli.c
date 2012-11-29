/*
 * $Id$
 *
 *  captagent - Homer capture agent. Modular
 *  Duplicate SIP messages in Homer Encapulate Protocol [HEP] [ipv6 version]
 *
 *  Author: Alexandr Dubovikov <alexandr.dubovikov@gmail.com>
 *  (C) Homer Project 2012 (http://www.sipcapture.org)
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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif /* __FAVOR_BSD */

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#ifdef USE_IPV6
#include <netinet/ip6.h>
#endif /* USE_IPV6 */

#include "src/api.h"
#include "capt_cli.h"

pthread_t thread;


int unload_module(void)
{
        printf("unloaded module capt_cli\n");
        
	/* Close socket */
	if(server_sock) close(server_sock);

        return 0;
}

int wait_connect (void) {

	int  client_sock;

	while( (client_sock = accept(server_sock, NULL, NULL)) ) {
	        if( pthread_create( &thread , NULL ,  read_clisocket , (void*) client_sock) < 0) {
			perror("could not create thread");
		        return 1;
	        }         
	}
	
	if(server_sock) close(server_sock);
	return 1;
}


void *read_clisocket(void *client){
    char buffer[MAX_LINE]; 
    char *message = "\r\nWelcome to CLI of Captagent\r\n";
    int ret;
    int mysocket = (int*) client;
    char *command;

    write_line(mysocket, message, strlen(message));
    
    while (1){
    
        write_line(mysocket, "\r\n>", strlen(">\r\n"));	
	ret = read_line(mysocket, buffer, MAX_LINE-1);
	if(ret == 0) return 0;

	/* SIMPLE INTERFACE */
	if(!strncmp(buffer,"quit",4)) {	
            write_line(mysocket, "Bye...\r\n", 9);	
            close(mysocket);
            return 0;
	}	
	else if(!strncmp(buffer,"stats",5)) {	

	    //message = get_basestat("core_hep");	
	    if(!strncmp(buffer,"stats hep",7)) {	
        	command = "core_hep";	        
	    }
	    else {
                command = "all";
	    }	

            message = get_basestat(command);		            
	    if(message == NULL) message = "No stats";        
	    write_line(mysocket, message, strlen(message));
	}	

	else {
	    message = "help - available commands\r\n" \
	              "quit - exit from CLI\r\n" \
	              "stats hep - show HEP statistics\r\n" \
	              "stats - show all statistics\r\n";
            write_line(mysocket, message, strlen(message));	
	}

	//write_line(mysocket, buffer, strlen(buffer));

    }
    return 0;
}


int load_module(xml_node *config)
{
	xml_node *modules;
        //struct addrinfo *ai, hints[1] = {{ 0 }};
        struct addrinfo hints[1] = {{ 0 }};
        char *key, *value;
        int s;

	/* READ CONFIG */
	modules = config;

	while(1) {
        	if(modules ==  NULL) break;
                modules = xml_get("param", modules, 1 );
                if(modules->attr[0] != NULL && modules->attr[2] != NULL) {
                        
                        /* bad parser */
                        if(strncmp(modules->attr[2], "value", 5) || strncmp(modules->attr[0], "name", 4)) {                        
                            fprintf(stderr, "bad keys in the config\n");
                            goto next;
                        
                        }

                        key =  modules->attr[1];
                        value = modules->attr[3];
                        
                        if(key == NULL || value == NULL) {
                            fprintf(stderr, "bad values in the config\n");
                            goto next;                        
                        
                        }                        

                        if(!strncmp(key, "cli-host", 8)) cli_host = value;
                        else if(!strncmp(key, "cli-port", 8)) cli_port = value;
                        else if(!strncmp(key, "cli-password", 13)) cli_password = value;                                	                	                	
		}
next:		
		
                modules = modules->next;
	}

                                           
        hints->ai_flags = AI_NUMERICSERV;
        hints->ai_family = AF_UNSPEC;
        hints->ai_socktype = SOCK_STREAM;
        hints->ai_protocol = IPPROTO_TCP;

        if ((s = getaddrinfo(cli_host, cli_port, hints, &ai)) != 0) {            
            fprintf(stderr, "capture: getaddrinfo: %s\n", gai_strerror(s));
            return 2;
        }

        if(init_clisocket()) {
              fprintf(stderr,"capture: couldn't init socket\r\n");              
              return 2;            
      	}

         printf("Loaded capt_cli\n");
         
	       if(wait_connect()){
              fprintf(stderr,"something wrong with cli socket\r\n");              
              return 3;
         }
        
        return 0;
}

int init_clisocket (void) {

    unsigned int on = 1;
    if(server_sock) close(server_sock);

    server_sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (server_sock < 0) {
             fprintf(stderr,"Sender socket creation failed: %s\n", strerror(errno));
             return 1;
    }    

    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    {
        fprintf(stderr, "setsockopt(SO_REUSEADDR) failed");
    }

    if (bind(server_sock, ai->ai_addr, (socklen_t)(ai->ai_addrlen)) < 0) {
            if (errno != EINPROGRESS) {
                    fprintf(stderr,"BIND socket creation failed: %s\n", strerror(errno));
                    return 1;
            }
    }
    
    
    if (listen(server_sock, 5) < 0) {
            fprintf(stderr,"Listener socket creation failed: %s\n", strerror(errno));
            return 1;            
    }
    

    return 0;

}

char *description(void)
{
        printf("Loaded description\n");
        char *description = "cli for captagent";
        
        return description;
}


ssize_t read_line(int sockd, void *vptr, size_t maxlen) {
    ssize_t n, rc;
    char    c, *buffer;

    buffer = vptr;

    for ( n = 1; n < maxlen; n++ ) {
	
	if ( (rc = read(sockd, &c, 1)) == 1 ) {
	    *buffer++ = c;
	    if ( c == '\n' )
		break;
	}
	else if ( rc == 0 ) {
	    if ( n == 1 )
		return 0;
	    else
		break;
	}
	else {
	    if ( errno == EINTR )
		continue;
	    return -1;
	}
    }

    *buffer = 0;
    return n;
}


ssize_t write_line(int sockd, const void *vptr, size_t n) {
    size_t      nleft;
    ssize_t     nwritten;
    const char *buffer;

    buffer = vptr;
    nleft  = n;

    while ( nleft > 0 ) {
	if ( (nwritten = write(sockd, buffer, nleft)) <= 0 ) {
	    if ( errno == EINTR )
		nwritten = 0;
	    else
		return -1;
	}
	nleft  -= nwritten;
	buffer += nwritten;
    }

    return n;
}

char* statistic(void)
{
        char buf[1024];
        snprintf(buf, 1024, "Statistic of capt_cli module\r\n");
        return &buf;
}
                        