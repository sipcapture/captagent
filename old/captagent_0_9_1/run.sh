#!/bin/sh

#Linux
cc -o captagent captagent.c -lpcap 
#-lsocket

#Solaris. Please be sure that your compiler is gcc or understand the packet attribute for structure
#cc -o captagent captagent.c -lpcap -lsocket