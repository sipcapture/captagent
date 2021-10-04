#!/bin/bash

rm -f *.profraw
rm -f *.profdata

coverage="coverage/"
if [ "$2" != "" ]; then
    coverage="$2"
fi

rm -rf $coverage
mkdir -p $coverage
mkdir -p $coverage/line
mkdir -p $coverage/source
mkdir -p $coverage/functions
LLVM_PROFILE_FILE="prof%p.profraw" \
    work/captagent/debug-build/usr/local/captagent/sbin/captagent \
    -f captagent-config/$1/captagent.xml
llvm-profdata merge -sparse *.profraw -o captagent.profdata

llvm-cov show work/captagent/debug-build/usr/local/captagent/sbin/captagent -instr-profile=captagent.profdata > $coverage/line/captagent-lines.txt
for f in work/captagent/debug-build/usr/local/captagent/lib/captpagent/modules/*.so;
do
    llvm-cov show $f -instr-profile=captagent.profdata > $coverage/line/`basename $f`-lines.txt
done

llvm-cov report work/captagent/debug-build/usr/local/captagent/sbin/captagent -instr-profile=captagent.profdata > $coverage/source/captagent-source.txt
for f in work/captagent/debug-build/usr/local/captagent/lib/captagent/modules/*.so;
do
    llvm-cov report $f -instr-profile=captagent.profdata > $coverage/source/`basename $f`-source.txt
done

llvm-cov report work/captagent/debug-build/usr/local/captagent/sbin/captagent -show-functions=true --instr-profile=captagent.profdata work/captagent
for f in work/captagent/debug-build/usr/local/captagent/lib/captagent/modules/*.so; 
do
    llvm-cov report $f -show-functions=true -instr-profile=captagent.profdata work/captagent/ > $coverage/functions/`basename $f`-functions.txt
done

# rm -f *.profraw *.profdata
chown root.root coverage
chown root.root $coverage/*
