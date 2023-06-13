#!/usr/local/bin/python3
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

    parser.add_argument('-s', '--Sip',
                        required=True,
                        help=f'Source IP address',
                        type=correct_ip)
    parser.add_argument('-r', '--Smacadd',
                        required=True,
                        help=f'Source Mac Addres',
                        type=correct_mac)
    parser.add_argument('-t', '--Tip',
                        required=True,
                        help='Target IP address',
                        type=correct_ip)
    parser.add_argument('-g', '--Tmacadd',
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
    att_mac = uuid.getnode()
    att_addr = socket.gethostbyname(hostname)
    sou_addr = args.Sip
    des_addr = args.Tip
    if all_in_network(att_addr, sou_addr, des_addr):
        spoof = True   # Spoofing is posible
    else:
        spoof = False
        msg = f"source IP {sou_addr}, target IP {des_addr} and {att_addr} "
        msg = msg + "not in same network"
        print(msg)

    # Your main script logic goes here
    print(get_mac())

    while spoof:
        # Perform your tasks
        # ...

        # Add a delay or use a blocking operation to keep the script running
        # For example:
        try:
            # Do something that takes time
            pass
        except KeyboardInterrupt:
            # Handle CTRL+C during the blocking operation, if required
            print("CTRL+C detected during the blocking operation.")
            # Perform any necessary cleanup here
            sys.exit(0)
