#!/bin/sh
TASK_ID=39
mkdir -p output/4G8C9Rs4OUWxpgzB/
echo "RE_spyware" > output/4G8C9Rs4OUWxpgzB/.name
cp 7_rev/PROTOCOL.md output/4G8C9Rs4OUWxpgzB/
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
  ./build/revproto "$KEY" "output/4G8C9Rs4OUWxpgzB/file.pcap"
  cd output/4G8C9Rs4OUWxpgzB/
  zip "${NAME}.zip" "file.pcap" "PROTOCOL.md"
  rm file.pcap
  cd "$o"
done