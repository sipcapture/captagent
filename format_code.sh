#!/bin/sh

### You need to install indent
echo "indent file $1..."
indent -linux -l200 -i4 -nut "$1"
echo "format done"
