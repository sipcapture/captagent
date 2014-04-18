#!/bin/sh

#Linux
cc -o captagent captagent.c -lpcap 
#-lsocket

#Solaris. Please be sure that your compiler is gcc or understand the packet attribute for structure
#cc -o captagent captagent.c -lpcap -lsocket -lnsl

#Solaris 2.6 - 7
#cc -o captagent captagent.c -lpcap -lsocket -lnsl -lresolv

#If your libpcap is not in standart path. 
# LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/my_path_to_libpcap
# export LD_LIBRARY_PATH

#or add the path to /etc/ld.so.conf and run ldconfig



