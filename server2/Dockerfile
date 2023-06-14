FROM delfer/alpine-ftp-server

RUN apk add tcpdump -y -q

# adding a generic ftp user
ENV USER ftpuser
RUN adduser  -h /home/ftp/ -s /sbin/sh -g "General FTP user" $USER; echo -n $USER':1234' |chpasswd
RUN addgroup $USER $USER

WORKDIR /etc/vsftpd
RUN sed -i -e '/#chroot_local_user=YES/ s/#//' vsftpd.conf
RUN sed -i -e '/#chroot_list_enable=YES/ s/#//' vsftpd.conf
RUN sed -i -e '/#chroot_list_file=\/etc\/vsftpd.chroot_list/ s/#//' vsftpd.conf
RUN sed -i -e '/chroot_list_file=\/etc\/vsftpd.chroot_list/ s/vsftpd/vsftpd\/vsftpd/' vsftpd.conf


RUN echo -n 'pasv_min_port=2222' >> vsftpd.conf
RUN echo -n 'pasv_max_port=2230' >> vsftpd.conf


RUN touch /etc/vsftpd/vsftpd.chroot_list
RUN echo -n $USER >> vsftpd.chroot_list


CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]