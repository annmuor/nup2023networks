for i in $(seq 1 128); do
	dig A nup23.local. @10.10.10.65
done
dig TXT flag1.nup23.local. @10.10.10.65

for i in $(seq 1 128); do
	dig A broadcast.nup23.local. @10.10.10.65
done
