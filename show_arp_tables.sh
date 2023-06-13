#!/bin/bash
#              1         2         3         4         5         6         7 
#    012345678901234567890123456789012345678901234567890123456789012345678901234567890 
echo "------------------------------- victim arp table -------------------------------"
docker exec victim cat /proc/net/arp
echo "------------------------------- server arp table -------------------------------"
docker exec server1 cat /proc/net/arp
echo "------------------------------- attack arp table -------------------------------"
docker exec attack cat /proc/net/arp