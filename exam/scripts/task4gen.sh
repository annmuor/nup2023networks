#!/bin/sh
source ./scripts/init.sh
TASK_ID=36
mkdir -p output/iZJ1z1pGHZ5bRlfA/
echo "TCP_porto" > output/iZJ1z1pGHZ5bRlfA/.name
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
  if [ -f "${o}/output/iZJ1z1pGHZ5bRlfA/${NAME}" ]; then
    continue
  fi
  cd "${o}/4_tcp/"
  FLAG="$KEY" "${o}/build/writeflag" > src/flag.rs
  cargo build -r --target x86_64-pc-windows-gnu --target x86_64-unknown-linux-musl --target-dir build/
  docker run -ti -v .:/src --network=host artifactory.wgdp.io/wtp-docker/library/rust:1.74-osxcross \
  sh -c "cd /src && cargo build -r --target x86_64-apple-darwin --target aarch64-apple-darwin --target-dir build/"
  cp build/x86_64-pc-windows-gnu/release/tcprst.exe "$o/output/iZJ1z1pGHZ5bRlfA/tcp_porto.exe"
  cp build/x86_64-unknown-linux-musl/release/tcprst "$o/output/iZJ1z1pGHZ5bRlfA/tcp_porto.linux"
  cp build/x86_64-apple-darwin/release/tcprst "$o/output/iZJ1z1pGHZ5bRlfA/tcp_porto.x64mac"
  cp build/aarch64-apple-darwin/release/tcprst "$o/output/iZJ1z1pGHZ5bRlfA/tcp_porto.armmac"
  cd "${o}/output/iZJ1z1pGHZ5bRlfA/"
  strip tcp_porto.*
  file tcp_porto.*
  zip "$NAME" tcp_porto.*
  rm -vf tcp_porto.*
  cd "${o}"
done
