# ARP POisoning

Execute de proyect wiht Docker
include the Dockerfiles
Include de docker-compse.yaml
include start.sh that automaticall  sets up the environment.

Create inquisitor.py

Arguments:
IP-src
MAC-src
IP-target
MAC-target


1.- poisong the arp in both direction (full duplex)
2.- CTRL+C finish the program and restores ARP Table
3.- only work wiht IPv4 addresee
4.- Intercept traffic to a FTP Server
5.- Show in real time file names exchanged between client and server

Sniff packer wiht libcap library
use Raw Sockets

BONUS
Verbose option mode  (-v) shows all FTP Traffic 
---
The aim of this proyect is arp poisonig.
I have to be focused on this aim. Despite that i can be very creative wiht ftp server and client
I will follow Alexander advice "Stay FOcused"

In this spirit:
I will not configure nothing in the Docker with vsftp neither in the Docker with a ftpclient.

# Introduction

Address Resolution Protocol (ARP) is a protocol that enables network communications to reach a specific device on the network. ARP translates Internet Protocol (IP) addresses to a Media Access Control (MAC) address, and vice versa. Most commonly, devices use ARP to contact the router or gateway that enables them to connect to the Internet.

Each host maintains an ARP cache, a mapping table between IP addresses and MAC addresses, and use it to connect to destinations on the network. 

If the host doesn’t know the MAC address for a certain IP address, it sends out an ARP request packet, asking other machines on the network for the matching MAC address. 

The ARP protocol was **not designed for security**, so it does not verify that a response to an ARP request really comes from an authorized party. It also lets hosts **accept ARP responses even if they never sent out a request**. This is a weak point in the ARP protocol, which opens the door to ARP spoofing attacks.

ARP only works with 32-bit IP addresses in the older IPv4 standard. The newer IPv6 protocol uses a different protocol, Neighbor Discovery Protocol (NDP), which is secure and uses cryptographic keys to verify host identities. However, since most of the Internet still uses the older IPv4 protocol, ARP remains in wide use.

in the argaparse proce



# References
![arp introduction ](https://www.imperva.com/learn/application-security/arp-spoofing/)