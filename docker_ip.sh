#!/bin/bash
docker inspect -f '{{.Name}} - {{.NetworkSettings.IPAddress }}' $(docker ps -aq)

for id in $(docker ps -aq)
do
    name=$(docker inspect $id | grep '"Hostname"'| cut -d ':' -f2 | sed -e 's/"//g' | sed -e 's/,//g')
    ip=$(docker inspect $id | grep '                    "IPAddress"'| cut -d ':' -f2 | sed -e 's/"//g' | sed -e 's/,//g')
    mac=$(docker inspect $id | grep '                    "MacAddress":'|cut -d ':' -f2-7 |sed -e 's/"//g' | sed -e 's/,//g')
    echo " container $name has IP=$ip and MAC=$mac"
done