FROM python:3

# I install tcpdump cause inside there is libpcap.so a library 
# required by python module libcap
RUN apt-get update
RUN apt-get install tcpdump -y -q
RUN apt-get install scapy -y -q   
WORKDIR /usr/src/app

#COPY requirements.txt ./
RUN pip install --no-cache-dir libpcap

COPY . .

#COPY entrypoint.sh /
#ENTRYPOINT ["/entrypoint.sh"]
#CMD [ "python", "./arpspoof.py", "-v", "-s", "192.168.42.2", "-r", "02:42:c0:a8:2a:02", "-t", "192.168.42.3", "-g", "02:42:c0:a8:2a:03"]