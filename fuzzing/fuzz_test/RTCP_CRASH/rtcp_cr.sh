#!/bin/bash

CAPTAGENT="../../../../captagent"

clang -fsanitize=address \
	-o $CAPTAGENT/test/fuzzing/fuzz_test/RTCP_CRASH/rtcp_crash \
        -g -O0 -w -I$CAPAGENT/include \
        -I$CAPTAGENT/src \
        -I$CAPTAGENT/src/modules/protocol/rtcp \
        `find $CAPTAGENT/src/ -maxdepth 1 -name "*.c" ! -name 'captagent.c'` \
        `find $CAPTAGENT/src/modules/protocol/rtcp -maxdepth 1 -name "*.c"` \
        -ljson-c -lpcap -lexpat -ldl -lpthread -lfl -luv -lm -lcrypto -lpcre
