#!/bin/sh
TASK_ID=37
mkdir -p output/QTr3OyXFrmfUJrMO/
echo "WIFI_CHAT" > output/QTr3OyXFrmfUJrMO/.name
o=$(pwd)
for i in $(seq 1 54); do
  KEY=$(./build/keygen $TASK_ID)
  NAME=$(python ./scripts/gen_id.py $i)
  ./build/wifi_gen "$KEY" "output/QTr3OyXFrmfUJrMO/file.pcap"
  cd output/QTr3OyXFrmfUJrMO/
  zip "${NAME}.zip" "file.pcap"
  rm file.pcap
  cd "$o"
done