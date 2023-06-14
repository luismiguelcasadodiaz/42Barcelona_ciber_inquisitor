#!/home/luis/.venv/inquisitor/bin/python3
import uuid

block='0242c0a82a040242c0a82a02080600010806060400020242c0a82a04c0a82a030242c0a82a02c0a82a02'
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
print()    
