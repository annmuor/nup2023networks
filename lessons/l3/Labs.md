# How to re-create the labs at home

## 1.1 - Listen for broadcast messages

- Download [bcast](https://github.com/annmuor/nup2023networks/tree/main/bcast) Rust project.
- Compile the project by typing cargo build -r. You may need to install [rust toolchain](https://rustup.rs) first.
- Run sudo ./target/release/bcast <device name>, where device name - is your physical interface name. Use **ip link** or
  **ifconfig** to find your devices.
- Now run netcat -v -l -u -k -p 25555 and collect the flag

## 1.2 - Broadcast chat

- Download [bchat.py](https://github.com/annmuor/nup2023networks/blob/main/bcast/bchat.py).
- Edit the script and change the broadcast ip address of your network

```python
address = ("255.255.255.255", 24555)
```

- Use **ifconfig** or **ip addr** to find your ip address
- Run the script
- Type GETFLAG
- Get the flag :)
- Or ask your friend from the same network to repeat the process
- You may also use this chat to chat into any network with your friends.

## 1.3 - Wireshark for broadcast IP datagrams

- Run the **bcast** project as described in 1.1
- Run **wireshark** and start listening to the same interface you used for running **bcast**.
- Type **ip.proto==253** in display filter field and press Enter
- Find the packet.
- Press Ctrl+Shift+O (on Linux)
- Read the flag

## 2.1 - DNS zones resolution

- Create a virtual ("dummy") interface and add four ip addresses. On Linux, you can use the following commands.

```shell
ip l add dum0 type dummy
ip l set dum0 up
ip a a 10.10.10.65/26 dev dum0
ip a a 10.10.10.126/26 dev dum0
ip a a 10.10.10.68/26 dev dum0
ip a a 10.10.10.69/26 dev dum0
ip a a 10.10.10.70/26 dev dum0
# check if the addresses are set
ip -o a sh dum0
# try to ping at least one address
ping 10.10.10.70
```

- Install [powerdns](https://www.powerdns.com) DNS server for your Linux distro
- Download the configuration
  files [here](https://github.com/annmuor/nup2023networks/blob/main/lessons/l3/powerdns.tar.gz)
- Unpack the configuration, starting from /
- Run (as root)

```shell
for i in 10.10.10.65 10.10.10.126 10.10.10.68; do
  pdns_server --config-name=$i &
done
```

- Try to solve the lab

## 2.2 - HTTP requests

- Create virtual interface as described in 2.1
- Install [nginx](http://nginx.org) Web server fpr your Linux distro
- Download [nginx.conf](https://github.com/annmuor/nup2023networks/blob/main/lessons/l3/nginx.conf) and put it into
  /etc/nginx/nginx.conf
- Run nginx ( e.g. by typing **sudo systemctl start nginx**)
- Try to solve the lab

## 2.3 - SMTP email sending

- Create virtual interface as described in 2.1
- Download and build [smtp server](https://github.com/annmuor/nup2023networks/tree/main/smtp) the same way as you built
  **bcast** into 1.1
- Create folder for incoming mail (e.g. **mkdir mail**)
- Run **sudo ./target/release/smtp-server -n "mx.lab2.cn.nup23.local" -m mail -p 10.10.10.69:25**
- Try to solve the lab
