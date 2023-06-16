#!/usr/local/bin/python
#!/home/luis/.venv/inquisitor/bin/python3
import socket
import uuid

hostname = socket.gethostname()
att_mac = uuid.getnode()
att_ip = socket.gethostbyname(hostname)

print(hostname)
print(att_mac)
print(att_ip)