output "monkey_island_url" {
  description = "URL to access Infection Monkey Island web UI"
  value       = "https://localhost:5000"
}

output "kibana_url" {
  description = "URL to access Kibana for log analysis"
  value       = "http://localhost:5601"
}

output "victim_ips" {
  description = "Internal IP addresses of victim containers"
  value       = { for idx, container in docker_container.victims : container.name => container.networks_advanced[0].ipv4_address }
}

output "external_network" {
  description = "External network subnet"
  value       = "192.168.100.0/24"
}

output "internal_network" {
  description = "Internal network subnet (victim network)"
  value       = "10.0.0.0/24"
}

output "ssh_access" {
  description = "Command to SSH into victim containers"
  value       = "docker exec -it victim-1 bash"
}
