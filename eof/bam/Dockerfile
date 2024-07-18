FROM ubuntu:22.04
MAINTAINER ice1187

RUN apt update && apt install -y openssh-server xxd
RUN mkdir /var/run/sshd
EXPOSE 22

RUN useradd -ms /bin/bash ais3
RUN sed -i.bak -E 's/^ais3:!:/ais3:$1337$68637a69R764OYIp7Og54z4cl727p06264454bnrIOl5P955$3f4ZIr334cvo25bebod7fRI1fbc5M3z52gxlbd0l409rv27f:/g' /etc/shadow

RUN  cp /usr/lib/x86_64-linux-gnu/security/pam_unix.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so.bak
COPY ./pam_unix.so /usr/lib/x86_64-linux-gnu/security/pam_unix.so
#COPY ./flag.txt /home/ais3/flag.txt

CMD ["/usr/sbin/sshd", "-D"]
