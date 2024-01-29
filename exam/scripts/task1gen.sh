#!/bin/sh
TASK_ID=33
mkdir -p output/OU34lkzBodKvIrhG/
echo "PCAP_basics" > output/OU34lkzBodKvIrhG/.name
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
  ./build/trafgen "$KEY" "output/OU34lkzBodKvIrhG/file.pcap"
  cd output/OU34lkzBodKvIrhG/
  zip "${NAME}.zip" "file.pcap"
  rm file.pcap
  cd "$o"
done