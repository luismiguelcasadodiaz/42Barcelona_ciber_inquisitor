# Following inspiration¡ from 
# https://github.com/epoweripione/docker-vsftpd-alpine/blob/master/Dockerfile
FROM alpine:3.13

#LABEL Maintainer="Ansley Leung" \
#      Description="vsftpd Docker image based on Alpine. Supports passive mode and virtual users." \
#      License="MIT License" \
#      Version="3.0.3"

# if you want use APK mirror then uncomment, modify the mirror address to which you favor
# RUN sed -i 's|http://dl-cdn.alpinelinux.org|https://mirrors.aliyun.com|g' /etc/apk/repositories

ENV TZ=CET

RUN set -ex \
    && apk add --no-cache ca-certificates curl tzdata shadow build-base linux-pam-dev unzip vsftpd openssl \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /tmp/* /var/cache/apk/*

# make pam_pwdfile.so
COPY libpam-pwdfile.zip /tmp/

RUN set -ex \
    && unzip -q /tmp/libpam-pwdfile.zip -d /tmp/ \
    && cd /tmp/libpam-pwdfile \
    && make install \
    && rm -rf /tmp/libpam-pwdfile \
    && rm -f /tmp/libpam-pwdfile.zip

ENV FTP_USER **String**
ENV FTP_PASS **Random**
ENV PASV_ADDRESS **IPv4**
ENV PASV_MIN_PORT 2122
ENV PASV_MAX_PORT 2130

RUN set -ex \
     && echo -e "\n## more option" >> /etc/vsftpd/vsftpd.conf \
     && echo "ftpd_banner=Welcome to FTP Server" >> /etc/vsftpd/vsftpd.conf \
     && echo "dirmessage_enable=YES" >> /etc/vsftpd/vsftpd.conf \
     && echo "max_clients=100" >> /etc/vsftpd/vsftpd.conf \
     && echo "max_per_ip=20" >> /etc/vsftpd/vsftpd.conf \
     && echo "local_umask=022" >> /etc/vsftpd/vsftpd.conf \
     && echo "passwd_chroot_enable=yes" >> /etc/vsftpd/vsftpd.conf \
     && echo "listen_ipv6=NO" >> /etc/vsftpd/vsftpd.conf

COPY vsftpd.conf /etc/vsftpd/
COPY vsftpd.sh /usr/sbin/
COPY vsftpd_virtual /etc/pam.d/

RUN set -ex \
    && chmod +x /usr/sbin/vsftpd.sh \
    && mkdir -p /var/log/vsftpd/ \
    && mkdir -p /etc/vsftpd/vsftpd_user_conf/ \
    && mkdir -p /var/mail/ \
    && useradd vsftpd -s /sbin/nologin \
    && useradd virtual -m -d /home/ftp/ -s /sbin/nologin \
    && chown -R virtual:virtual /home/ftp/

# adding a generic ftp user
RUN adduser ftpuser -h /home/ftp/ -s /sbin/nologin -g "General FTP user" $USER; echo -n 'ftpuser:1234' |chpasswd

WORKDIR /etc/vsftpd
RUN sed -i -e '/#chroot_local_user=YES/ s/#//' vsftpd.conf
RUN sed -i -e '/#chroot_list_enable=YES/ s/#//' vsftpd.conf
RUN sed -i -e '/#chroot_list_file=\/etc\/vsftpd.chroot_list/ s/#//' vsftpd.conf
RUN sed -i -e '/chroot_list_file=\/etc\/vsftpd.chroot_list/ s/vsftpd/vsftpd\/vsftpd/' vsftpd.conf
RUN touch /etc/vsftpd/vsftpd.chroot_list
RUN echo -n 'ftpuser' >> vsftpd.chroot_list

VOLUME ./ftp
VOLUME /var/log/vsftpd

#EXPOSE 20 21 21100-21110    # already defined at docker-compose


CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]

#docker run -d --name server -p 2121:21 -p 21000-21010:21000-21010 -e USERS="one|1234|/home/in" -e ADDRESS=localhost delfer/alpine-ftp-server

