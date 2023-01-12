DIRECTORY="captagent_build"

if [ -d "$DIRECTORY" ]; then
   cd $DIRECTORY
   git pull
   cd ..
else
	git clone https://github.com/sipcapture/captagent.git $DIRECTORY
fi

docker run --rm -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/builder.sh alanfranz/fwd-centos-7:latest
