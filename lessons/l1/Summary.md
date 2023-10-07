# Key takeouts
- All the things in the Internet have the tree shape
- The Internet is built on trust
- BGP is the core Internet protocol

# Glossary
## Internet technologies
- BGP - [Border Gateway Protocol](https://en.wikipedia.org/wiki/Border_Gateway_Protocol)
- ISP - [Internet Service Provider](https://en.wikipedia.org/wiki/Internet_service_provider)
- AS - [Autonomous System](https://en.wikipedia.org/wiki/Autonomous_system_(Internet))
- ASN - Autonomous System Number
- [Tier 1 ISP](https://www.thousandeyes.com/learning/techtorials/isp-tiers) - ISP that does not pay for traffic
- [RIPE](https://www.ripe.net) - Provides AS Numbers in Europe
## Networking protocols
- IPv4 address - 32 bits (four bytes) address in the IPv4 protocol
- IPv4 network - 32 bits of network address + 32 bits of network mask
- IPv4 network mask - bitmask that shows how many hosts this network has
- IPv4 prefix - bitmask in a short form, just the count of the bits set to 1
- How to calculate the host count in the given network: **2^(32-prefix) - 2**
- Minimum address of the network called **the network address**
- Maximum address of the network called **the broadcast address**
- Both network and broadcast addresses cannot be used for host address
### Networking examples
- 192.168.1.0/255.255.255.0 = 192.168.1.0/24 = 253 hosts (2^8–2), broadcast = 192.168.1.255
- 192.168.0.0/255.255.254.0 = 192.168.0.0/23 = 510 hosts (2^9-2), broadcast = 192.168.1.255
- 192.168.1.0/255.255.255.128 = 192.168.1.0/25 = 126 hosts (2^7-2), broadcast = 192.168.1.127
## DNS
- ICANN - [Internet Corporation for Assigned Names and Numbers](https://www.icann.org)
- TLD - [Top Level Domain](https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains) - domains like .com, .ru, .cy, .org, etc

# Useful tools
- [IP Network Calculator](https://www.calculator.net/ip-subnet-calculator.html)
- [BGP Viewer](https://bgpview.io)
- [WHOIS](https://who.is)