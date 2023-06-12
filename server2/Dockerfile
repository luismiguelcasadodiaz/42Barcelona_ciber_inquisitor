FROM delfer/alpine-ftp-server

# adding a generic ftp user

#RUN adduser ftpuser -h /home/ftp/ -s /sbin/nologin -g "General FTP user" $USER; echo -n 'ftpuser:1234' |chpasswd
#RUN addgroup ftpuser

WORKDIR /etc/vsftpd
RUN sed -i -e '/#chroot_local_user=YES/ s/#//' vsftpd.conf
RUN sed -i -e '/#chroot_list_enable=YES/ s/#//' vsftpd.conf
RUN sed -i -e '/#chroot_list_file=\/etc\/vsftpd.chroot_list/ s/#//' vsftpd.conf
RUN sed -i -e '/chroot_list_file=\/etc\/vsftpd.chroot_list/ s/vsftpd/vsftpd\/vsftpd/' vsftpd.conf


RUN echo -n 'pasv_min_port=2222' >> vsftpd.conf
RUN echo -n 'pasv_max_port=2230' >> vsftpd.conf


RUN touch /etc/vsftpd/vsftpd.chroot_list
RUN echo -n 'ftpuser' >> vsftpd.chroot_list

CMD ["/bin/sh"]