# Key takeouts

- HTTP protocol is the most common protocol on the Internet
- Netcat is the best tool for working with network protocols manually
- Software WI-FI access points are weird :(

# How-tos

## Creating HTTP request

```shell
nc -v google.com 80
Connection to google.com (216.58.198.78) 80 port [tcp/http] succeeded!
GET / HTTP/1.1
Host: google.com

```

## Listening port

```shell
nc -vlup 25555
Bound on 0.0.0.0 25555
Connection received on 10.10.10.65 43803
Hello there

```

## Connecting to WI-FI via console tools

```shell
iw dev # get list of the devices
sudo iw dev <device name> connect nup23cn # connect to the network
```

## Setting ip-address manually on Linux

```shell
ip addr add 10.10.10.65/26 dev <device name> broadcast 10.10.10.127
```

# Documentation to read
* [iproute2](https://wiki.linuxfoundation.org/networking/iproute2) tools
