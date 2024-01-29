#!/bin/sh
source ./scripts/init.sh
TASK_ID=38
mkdir -p output/SCLIv8MEMsDFsKT0/
echo "TLSS" > output/SCLIv8MEMsDFsKT0/.name
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
    if [ -f "${o}/output/SCLIv8MEMsDFsKT0/${NAME}.zip" ]; then
      continue
    fi
  cd "${o}/6_tls/"
  FLAG="$KEY" "${o}/build/writeflag" > src/flag.rs
  cargo build -r --target x86_64-pc-windows-gnu --target x86_64-unknown-linux-musl --target-dir build/
  docker run -ti -v .:/src --network=host artifactory.wgdp.io/wtp-docker/library/rust:1.74-osxcross \
  sh -c "cd /src && CC=aarch64-apple-darwin20.4-clang cargo build -r --target aarch64-apple-darwin --target-dir build/"
  docker run -ti -v .:/src --network=host artifactory.wgdp.io/wtp-docker/library/rust:1.74-osxcross \
    sh -c "cd /src && CC=x86_64-apple-darwin20.4-clang cargo build -r --target x86_64-apple-darwin --target-dir build/"
  cp build/x86_64-pc-windows-gnu/release/tlss.exe "$o/output/SCLIv8MEMsDFsKT0/tlss.exe"
  cp build/x86_64-unknown-linux-musl/release/tlss "$o/output/SCLIv8MEMsDFsKT0/tlss.linux"
  cp build/x86_64-apple-darwin/release/tlss "$o/output/SCLIv8MEMsDFsKT0/tlss.x64mac"
  cp build/aarch64-apple-darwin/release/tlss "$o/output/SCLIv8MEMsDFsKT0/tlss.armmac"
  cd "${o}/output/SCLIv8MEMsDFsKT0/"
  strip tlss.*
  file tlss.*
  zip "$NAME" tlss.*
  rm -vf tlss.*
  cd "${o}"
done
