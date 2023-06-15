# Following inspiration¡ from 
# https://github.com/epoweripione/docker-vsftpd-alpine/blob/master/Dockerfile
FROM alpine:3.13

RUN apk add --no-cache vsftpd

# adding a generic ftp user
ENV USER lcasado-
RUN adduser  -h /home/$USER -s /bin/ash -g "General FTP user" $USER; echo -n $USER':1234' |chpasswd
RUN addgroup $USER $USER

WORKDIR /home/$USER
RUN echo "vsftpd archivo de ejemplo en Server3" >> ejemplo.txt


CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]

#docker run -d --name server -p 2121:21 -p 21000-21010:21000-21010 -e USERS="one|1234|/home/in" -e ADDRESS=localhost delfer/alpine-ftp-server

