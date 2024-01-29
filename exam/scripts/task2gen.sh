#!/bin/sh
source ./scripts/init.sh
TASK_ID=34
mkdir -p output/GVCmVjVmM07NiU0Z/
echo "DNS_zone" > output/GVCmVjVmM07NiU0Z/.name
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
   if [ -f "${o}/output/GVCmVjVmM07NiU0Z/${NAME}" ]; then
       continue
   fi
  cd "${o}/2_dns/"
  FLAG="$KEY" "${o}/build/writeflag" > src/flag.rs
  cargo build -r --target x86_64-pc-windows-gnu --target x86_64-unknown-linux-musl --target-dir build/
  docker run -ti -v .:/src --network=host artifactory.wgdp.io/wtp-docker/library/rust:1.74-osxcross \
  sh -c "cd /src && cargo build -r --target x86_64-apple-darwin --target aarch64-apple-darwin --target-dir build/"
  cp build/x86_64-pc-windows-gnu/release/dns_server.exe "$o/output/GVCmVjVmM07NiU0Z/dns_zone.exe"
  cp build/x86_64-unknown-linux-musl/release/dns_server "$o/output/GVCmVjVmM07NiU0Z/dns_zone.linux"
  cp build/x86_64-apple-darwin/release/dns_server "$o/output/GVCmVjVmM07NiU0Z/dns_zone.x64mac"
  cp build/aarch64-apple-darwin/release/dns_server "$o/output/GVCmVjVmM07NiU0Z/dns_zone.armmac"
  cd "${o}/output/GVCmVjVmM07NiU0Z/"
  strip dns_zone.*
  file dns_zone.*
  zip "$NAME" dns_zone.*
  rm -vf dns_zone.*
  cd "${o}"
done
