#!/bin/bash
docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/build_tls.sh debian:stretch
