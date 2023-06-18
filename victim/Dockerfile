FROM alpine:3.13

RUN apk add lftp -y  -q
RUN apk add tcpdump -y  -q

ENV USER lcasado-
RUN adduser  -h /home/$USER -s /bin/ash -g "General FTP user" $USER; echo -n $USER':1234' |chpasswd
RUN addgroup $USER $USER

WORKDIR /home/$USER

CMD ["/bin/sh"]