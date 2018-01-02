# Syntax

docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/build.sh  alanfranz/fwd-debian-jessie:latest

docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/build_tls.sh alanfranz/fwd-debian-jessie:latest

