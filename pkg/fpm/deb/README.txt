# Syntax

docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/builder.sh  alanfranz/fwd-debian-jessie:latest

