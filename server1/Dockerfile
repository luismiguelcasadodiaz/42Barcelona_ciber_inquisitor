FROM alpine:3.13

#RUN apk add tcpdump -y -q

# adding a generic ftp user
ENV USER lcasado-
RUN adduser  -h /home/$USER -s /bin/ash -g "General FTP user" $USER; echo -n $USER':1234' |chpasswd
RUN addgroup $USER $USER
WORKDIR /home/$USER
#RUN mkdir ftp
#RUN chown nobody:nogroup /home/$USER/ftp
#RUN chmod a-w /home/$USER/ftp
#WORKDIR /home/$USER/ftp
#RUN mkdir files
#RUN chown $USER:$USER /home/$USER/ftp/files
#WORKDIR /home/$USER/ftp/files
RUN echo "vsftpd archivo de ejemplo en Server1" >> ejemplo.txt
COPY vsftpd.conf .




EXPOSE 21
 
CMD ["tcpsvd", "-vE", "0.0.0.0", "21", "ftpd", "-w", "-vv", "-S", "/home"]