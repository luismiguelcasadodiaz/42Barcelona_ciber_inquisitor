# Following inspiration¡ from 
# https://github.com/epoweripione/docker-vsftpd-alpine/blob/master/Dockerfile
FROM busybox


# adding a generic ftp user
ENV USER lcasado-
RUN adduser  -h /home/$USER -s /bin/ash -g "Lius Miguel Casado Díaz" $USER; echo -n $USER':1234' |chpasswd
RUN addgroup $USER $USER

WORKDIR /home/$USER
RUN echo "ftpd archivo de ejemplo en Server3" >> ejemplo.txt

EXPOSE 21

CMD ["tcpsvd", "-vE", "0.0.0.0", "21", "ftpd", "-w", "-vv", "-S", "/home"]


#docker run -d --name server -p 2121:21 -p 21000-21010:21000-21010 -e USERS="one|1234|/home/in" -e ADDRESS=localhost delfer/alpine-ftp-server

