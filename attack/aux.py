#!/home/luis/.venv/inquisitor/bin/python3
import pprint
ip = '192.168.0.26'
elems = ip.split('.')
result =b''
for elem in elems:
    elem_int = int(elem)
    if elem_int == 0:
        elem_hex = '00'
    else:
        elem_hex= hex(elem_int)[2:]
    elem_byte = bytes.fromhex(elem_hex)
    result += elem_byte

print(result)
