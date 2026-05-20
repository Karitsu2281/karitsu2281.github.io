FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    iptables \
    iptables-persistent \
    suricata \
    suricata-update \
    rsyslog \
    tcpdump \
    net-tools \
    iputils-ping \
    iproute2 \
    curl \
    python3 \
    wget \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

RUN suricata-update update-sources \
    && suricata-update enable-source et/open \
    && suricata-update enable-source oisf/trafficid \
    && suricata-update enable-source ptresearch/attackdetection \
    && suricata-update

RUN mkdir -p /etc/filebeat /var/log/filebeat \
    && curl -L -o /tmp/filebeat.tar.gz https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.12.0-linux-x86_64.tar.gz \
    && tar xzf /tmp/filebeat.tar.gz -C /opt/ \
    && mv /opt/filebeat-8.12.0-linux-x86_64 /opt/filebeat \
    && rm /tmp/filebeat.tar.gz

RUN echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf \
    && echo 'net.ipv4.conf.all.forwarding=1' >> /etc/sysctl.conf \
    && echo 'net.ipv6.conf.all.forwarding=0' >> /etc/sysctl.conf \
    && echo 'net.ipv4.conf.all.send_redirects=0' >> /etc/sysctl.conf

RUN mkdir -p /etc/iptables && touch /etc/iptables/rules.v4

COPY suricata.yaml /etc/suricata/suricata.yaml
COPY custom.rules /var/lib/suricata/rules/custom.rules
COPY filebeat.yml /etc/filebeat/filebeat.yml
RUN chmod go-w /etc/filebeat/filebeat.yml

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV SURICATA_IFACE=eth1

ENTRYPOINT ["/entrypoint.sh"]
