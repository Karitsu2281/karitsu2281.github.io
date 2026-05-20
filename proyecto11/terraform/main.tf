terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
  }
  required_version = ">= 1.3.0"
}

provider "docker" {
  host = var.docker_host
}

resource "docker_network" "external_net" {
  name   = "monkey_external"
  driver = "bridge"
  ipam_config {
    subnet  = "192.168.100.0/24"
    gateway = "192.168.100.1"
  }
}

resource "docker_network" "internal_net" {
  name   = "monkey_internal"
  driver = "bridge"
  internal = true
  ipam_config {
    subnet  = "10.0.0.0/24"
    gateway = "10.0.0.1"
  }
}

resource "docker_image" "firewall" {
  name = "proyecto11-firewall:latest"
  build {
    context    = "${path.root}/../docker/firewall"
    dockerfile = "Dockerfile"
  }
}

resource "docker_container" "firewall" {
  name  = "firewall"
  image = docker_image.firewall.image_id
  hostname = "firewall"

  networks_advanced {
    name         = docker_network.external_net.name
    ipv4_address = "192.168.100.10"
  }
  networks_advanced {
    name         = docker_network.internal_net.name
    ipv4_address = "10.0.0.1"
  }

  capabilities {
    add = ["NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYSLOG"]
  }

  sysctl = {
    "net.ipv4.ip_forward"                  = "1"
    "net.ipv4.conf.all.forwarding"         = "1"
    "net.ipv6.conf.all.forwarding"         = "0"
    "net.ipv4.conf.all.send_redirects"     = "0"
    "net.ipv4.conf.default.send_redirects" = "0"
  }

  ports {
    internal = 514
    external = 5514
    protocol = "udp"
  }

  mounts {
    type   = "bind"
    source = "${path.root}/../docker/firewall/suricata.yaml"
    target = "/etc/suricata/suricata.yaml"
    read_only = true
  }

  volumes {
    container_path = "/var/log/suricata"
    volume_name    = docker_volume.suricata_logs.name
  }
}

resource "docker_volume" "suricata_logs" {
  name = "suricata_logs"
}

resource "docker_image" "victim" {
  name = "proyecto11-victim:latest"
  build {
    context    = "${path.root}/../docker/victim"
    dockerfile = "Dockerfile"
  }
}

resource "docker_container" "victims" {
  count = var.victim_count
  name  = "victim-${count.index + 1}"
  image = docker_image.victim.image_id
  hostname = "victim-${count.index + 1}"

  networks_advanced {
    name         = docker_network.internal_net.name
    ipv4_address = "10.0.0.${count.index + 10}"
  }

  capabilities {
    add = ["NET_ADMIN", "SYS_ADMIN"]
  }

  sysctl = {
    "net.ipv4.conf.all.accept_source_route" = "0"
  }

  env = [
    "VICTIM_ID=${count.index + 1}",
    "SSH_PASSWORD=${var.ssh_password}"
  ]
}

resource "docker_container" "monkey_island" {
  name  = "monkey_island"
  image = var.monkey_image
  hostname = "monkey_island"

  networks_advanced {
    name         = docker_network.external_net.name
    ipv4_address = "192.168.100.20"
  }

  ports {
    internal = 5000
    external = 5000
  }

  env = [
    "MONGO_URL=mongodb://mongo:27017/monkey_island"
  ]
}

resource "docker_container" "mongo" {
  name  = "monkey_mongo"
  image = "mongo:6.0"
  hostname = "mongo"

  networks_advanced {
    name         = docker_network.external_net.name
    ipv4_address = "192.168.100.21"
  }

  volumes {
    container_path = "/data/db"
    volume_name    = docker_volume.mongo_data.name
  }
}

resource "docker_volume" "mongo_data" {
  name = "monkey_mongo_data"
}

resource "docker_container" "elasticsearch" {
  name  = "elasticsearch"
  image = "docker.elastic.co/elasticsearch/elasticsearch:8.12.0"
  hostname = "elasticsearch"

  networks_advanced {
    name         = docker_network.external_net.name
    ipv4_address = "192.168.100.30"
  }

  ports {
    internal = 9200
    external = 9200
  }

  env = [
    "discovery.type=single-node",
    "xpack.security.enabled=false",
    "ES_JAVA_OPTS=-Xms512m -Xmx512m"
  ]

  volumes {
    container_path = "/usr/share/elasticsearch/data"
    volume_name    = docker_volume.es_data.name
  }
}

resource "docker_volume" "es_data" {
  name = "elasticsearch_data"
}

resource "docker_container" "logstash" {
  name  = "logstash"
  image = "docker.elastic.co/logstash/logstash:8.12.0"
  hostname = "logstash"

  networks_advanced {
    name         = docker_network.external_net.name
    ipv4_address = "192.168.100.31"
  }

  ports {
    internal = 514
    external = 5515
    protocol = "udp"
  }
  ports {
    internal = 5044
    external = 5044
  }

  volumes {
    container_path = "/usr/share/logstash/pipeline/logstash.conf"
    host_path      = "${path.root}/../docker/elk/logstash.conf"
    read_only      = true
  }
}

resource "docker_container" "kibana" {
  name  = "kibana"
  image = "docker.elastic.co/kibana/kibana:8.12.0"
  hostname = "kibana"

  networks_advanced {
    name         = docker_network.external_net.name
    ipv4_address = "192.168.100.32"
  }

  ports {
    internal = 5601
    external = 5601
  }

  env = [
    "ELASTICSEARCH_HOSTS=http://elasticsearch:9200"
  ]
}
