#!/bin/sh
source ./scripts/init.sh
TASK_ID=35
mkdir -p output/lvZWTyB0F0Nnlm2b/
echo "HTTP_1_1337" > output/lvZWTyB0F0Nnlm2b/.name
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
  if [ -f "${o}/output/lvZWTyB0F0Nnlm2b/${NAME}" ]; then
     continue
  fi
  cd "${o}/3_http/"
  FLAG="$KEY" "${o}/build/writeflag" > src/flag.rs
  cargo build -r --target x86_64-pc-windows-gnu --target x86_64-unknown-linux-musl --target-dir build/
  docker run -ti -v .:/src --network=host artifactory.wgdp.io/wtp-docker/library/rust:1.74-osxcross \
  sh -c "cd /src && cargo build -r --target x86_64-apple-darwin --target aarch64-apple-darwin --target-dir build/"
  cp build/x86_64-pc-windows-gnu/release/http_server.exe "$o/output/lvZWTyB0F0Nnlm2b/http_server.exe"
  cp build/x86_64-unknown-linux-musl/release/http_server "$o/output/lvZWTyB0F0Nnlm2b/http_server.linux"
  cp build/x86_64-apple-darwin/release/http_server "$o/output/lvZWTyB0F0Nnlm2b/http_server.x64mac"
  cp build/aarch64-apple-darwin/release/http_server "$o/output/lvZWTyB0F0Nnlm2b/http_server.armmac"
  cd "${o}/output/lvZWTyB0F0Nnlm2b/"
  strip http_server.*
  file http_server.*
  zip "$NAME" http_server.*
  rm -vf http_server.*
  cd "${o}"
done
