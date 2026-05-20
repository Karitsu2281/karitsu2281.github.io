FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    nginx \
    mysql-server \
    curl \
    wget \
    net-tools \
    iputils-ping \
    telnet \
    ftp \
    python3 \
    python3-pip \
    iptables \
    rsyslog \
    auditd \
    fail2ban \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/#Port 22/Port 22/' /etc/ssh/sshd_config

RUN echo '<html><body><h1>Victim Web Server</h1><p>Servidor vulnerable para pruebas de emulacion de adversarios - Proyecto 11</p></body></html>' > /var/www/html/index.html

RUN echo '#!/bin/bash\nservice mysql start\nservice nginx start\nservice ssh start\nservice rsyslog start\ntail -f /dev/null' > /start.sh \
    && chmod +x /start.sh

EXPOSE 22 80 443 3306

CMD ["/start.sh"]
