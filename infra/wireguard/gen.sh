for i in $(seq 200 200); do wg genkey > configs/$i.key; wg pubkey < configs/$i.key > configs/$i.pub
cat > configs/$i.conf <<EOF
[Interface]
Address=10.10.10.$i/32
PrivateKey=$(cat configs/$i.key)

[Peer]
Endpoint=51.89.166.139:54321
PublicKey=$(cat pub_key)
PersistentKeepalive=25
AllowedIPs=10.10.10.0/24
EOF

cat >> cpr.conf <<EOF
[Peer]
PublicKey=$(cat configs/$i.pub)
AllowedIPs=10.10.10.$i/32
PersistentKeepalive=25
EOF
 done

