#!/bin/bash
#              1         2         3         4         5         6         7 
#    012345678901234567890123456789012345678901234567890123456789012345678901234567890 
echo "------------------------------- victim arp table -------------------------------"
docker exec victim cat /proc/net/arp
echo "------------------------------- server 1 arp table -----------------------------"
docker exec server1 cat /proc/net/arp
echo "------------------------------- server 2 arp table -----------------------------"
docker exec server2 cat /proc/net/arp
echo "------------------------------- attack arp table -------------------------------"
docker exec attack cat /proc/net/arp
echo "********************************************************************************"
echo "********************************************************************************"
echo "------------------------------- victim arp table -------------------------------"
docker exec victim arp -a
echo "------------------------------- server 1 arp table -----------------------------"
docker exec server1 arp -a
echo "------------------------------- server 2 arp table -----------------------------"
docker exec server2 arp -a
echo "------------------------------- attack arp table -------------------------------"
docker exec attack arp -a