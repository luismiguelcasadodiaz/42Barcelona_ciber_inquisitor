FROM delfer/alpine-ftp-server

RUN apk add tcpdump -y -q

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
RUN echo "vsftpd archivo de ejemplo en Server2" >> ejemplo.txt



WORKDIR /etc/
COPY vsftpd.conf .

#RUN sed -i -e '/#chroot_local_user=YES/ s/#//' vsftpd.conf
#RUN sed -i -e '/#chroot_list_enable=YES/ s/#//' vsftpd.conf
#RUN sed -i -e '/#chroot_list_file=\/etc\/vsftpd.chroot_list/ s/#//' vsftpd.conf
#RUN sed -i -e '/chroot_list_file=\/etc\/vsftpd.chroot_list/ s/vsftpd/vsftpd\/vsftpd/' vsftpd.conf


#RUN echo -n 'pasv_min_port=2222' >> vsftpd.conf
#RUN echo -n 'pasv_max_port=2230' >> vsftpd.conf


#RUN touch /etc/vsftpd/vsftpd.chroot_list
#RUN echo -n $USER >> vsftpd.chroot_list

EXPOSE 20

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]