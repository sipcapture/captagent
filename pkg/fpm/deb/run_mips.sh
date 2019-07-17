#!/bin/bash
apt-get install -y qemu-user-static qemu-user

docker run --rm -v /usr/bin/qemu-qemu-mips64el-static:/usr/bin/qemu-mips64el-static -v $(pwd)/:/tmp/build -v $(pwd)/:/scripts --entrypoint=/scripts/build.sh hypnza/qemu_debian_mipsel
