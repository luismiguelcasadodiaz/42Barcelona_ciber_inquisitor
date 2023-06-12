#!/usr/local/bin/python3

import signal
import sys
import argparse

def correct_ip(text):
    """
    Verifies that the text fits an ipv4 IP address
    https://datatracker.ietf.org/doc/html/rfc4001

    fout integers reanging 0..255 
    Argument:
        text: string
    """
    text_numbers = text.split('.')
    try:
        if len(text_numbers) == 4:
            for text_number in text_numbers:
            
                num = int(text_number)
                if 0 <= num and num <= 255 :
                    pass
                else:
                    raise ValueError
            return text
        else:
            raise ValueError
    except ValueError:
        msg = f"{text} does not correspon to a correct IPv4 address"
        parser.error (msg)

    

def correct_mac(text):
    """
    Traditional MAC addresses are 12-digit (6 bytes or 48 bits) hexadecimal numbers. 
    By convention, these addresses are usually written in one of the following three formats:
    although there are variations:
    MM:MM:MM:SS:SS:SS
    MM-MM-MM-SS-SS-SS
    MMM.MMM.SSS.SSS
    """
    text_numbers = text.split(':')
    print("Splited : =", text_numbers)
    text_numbers = text.split('.')
    print("Splited . =", text_numbers)
    text_numbers = text.split('-')
    print("Splited - =", text_numbers)


def create_argument_parser():

    msg = """
    Permet d’enregistrer un mot de passe initial, et qui est capable"
    de générer un nouveau mot de passe chaque fois qu’il est demandé"""
    parser = argparse.ArgumentParser(
        prog='arpspoof',
        description=msg,
        epilog='Este es el final de la ayuda',
        usage="""
        ./arpspoof [-v] -s a.b.c.d -r -t a.b.c.d -g
        """
        )
    parser.add_argument('-v','--verbose', help='Shows all FTP traffic and not just filenames', action='store_true')

    parser.add_argument('-s','--Sip',
                       required = True,
                       help=f'Source IP address',
                       type=correct_ip)
    parser.add_argument('-r','--Smacadd',
                       required = True,
                       help=f'Source Mac Addres',
                       type=correct_mac)
    parser.add_argument('-t','--Tip',
                       required = True,
                       help='Target IP address',
                       type=correct_ip)
    parser.add_argument('-g','-Tmacadd',
                       required = True,
                       help='Target Mac address',
                       type=correct_mac)
    
    return parser

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

# Your main script logic goes here
while True:
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