#!/bin/bash
#docker compose up
exec ./attack/arpspoof.py  -v -s 172.18.0.3 -r 02:42:ac:12:00:03 -t 172.18.0.2 -g 02:42:ac:12:00:02