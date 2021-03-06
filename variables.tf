variable "azs" {
  description = ""
  type = list(string)
  default = []
}

variable "bastion_key" {
  description = ""
  type = string
  default = ""
}

variable "spoke_regions" {
  description = ""
  type = string
  default = ""
}

variable "spoke_accounts" {
  description = ""
  type = string
  default = ""
}

# OPENSEARCH DOMAIN

variable "elasticsearch_version" {
  description = ""
  type = string
  default = "7.5"
}

variable "volume_size" {
  description = ""
  type = string
  default = "10"
}

variable "volume_type" {
  description = ""
  type = string
  default = "gp2"
}

variable "dedicated_master_type" {
  description = ""
  type = string
  default = ""
}

variable "instance_count" {
  description = ""
  type = number
  default = 3
}

variable "instance_type" {
  description = ""
  type = string
  default = "r4.large.elasticsearch"
}

variable "master_node_count" {
  description = ""
  type = number
  default = 3
}

variable "availability_zone_count" {
  description = ""
  type = number
  default = 2
}

variable "admin_email" {
  description = ""
  type = string
  default = ""
}

variable "es_vpc_cidr" {
  description = ""
  type = string
  default = ""
}

variable "es_private_subnet" {
  description = ""
  type = list(string)
  default = []
}

variable "es_public_subnet" {
  description = ""
  type = list(string)
  default = []
}

variable "domain_name" {
  description = ""
  type = string
  default = ""
}

# LAMBDA

variable "ephemeral_storage" {
  description = ""
  type = number
  default = 512
}

variable "memory_size" {
  description = ""
  type = number
  default = 128
}

# KINESIS

variable "shard_count" {
  description = ""
  type = number
  default = 1
}
