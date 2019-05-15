## The next commands are putted in run.sh and run_tls.sh 

# run.sh
docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/build.sh  alanfranz/fwd-debian-jessie:latest

# run_tls.sh
docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/build_tls.sh alanfranz/fwd-debian-jessie:latest

