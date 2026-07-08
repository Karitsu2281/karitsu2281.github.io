variable "docker_host" {
  description = "Docker daemon socket or host"
  type        = string
  default     = "npipe:////.//pipe//docker_engine"
}

variable "victim_count" {
  description = "Number of victim containers"
  type        = number
  default     = 2
}

variable "monkey_image" {
  description = "Infection Monkey Island Docker image"
  type        = string
  default     = "infectionmonkey/monkey-island:latest"
}

variable "ssh_password" {
  description = "Default SSH password for victim containers"
  type        = string
  default     = "toor"
  sensitive   = true
}
