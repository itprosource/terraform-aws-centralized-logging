# OPENSEARCH

variable "azs" {
  description = "List of Availability Zones."
  type = list(string)
  default = []
}

variable "es_vpc_cidr" {
  description = "CIDR block for VPC hosting Opensearch."
  type = string
  default = ""
}

variable "es_private_subnet" {
  description = "Private subnet CIDR for Opensearch VPC."
  type = list(string)
  default = []
}

variable "es_public_subnet" {
  description = "Public subnet CIDR for Opensearch VPC."
  type = list(string)
  default = []
}

variable "elasticsearch_version" {
  description = "Version or Elasticsearch or Opensearch to deploy."
  type = string
  default = "7.5"
}

variable "volume_size" {
  description = "Size of node EBS volumes."
  type = string
  default = "10"
}

variable "volume_type" {
  description = "Type of node EBS volumes."
  type = string
  default = "gp2"
}

variable "master_node_count" {
  description = "Count of dedicated master nodes."
  type = number
  default = 3
}

variable "dedicated_master_type" {
  description = "Instance type of dedicated master nodes."
  type = string
  default = ""
}

variable "warm_enabled" {
  description = "Enables ultrawarm storage nodes."
  type = bool
  default = false
}

variable "warm_count" {
  description = "Count of ultrawarm storage nodes."
  type = number
  default = 2
}

variable "warm_type" {
  description = "Instance type of ultrawarm storage nodes."
  type = string
  default = "ultrawarm1.medium.elasticsearch"
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

variable "availability_zone_count" {
  description = "Count of availability zones in use."
  type = number
  default = 2
}

variable "spoke_accounts" {
  description = "List of spoke accounts to access the CW Destination."
  type = string
  default = ""
}

variable "admin_email" {
  description = "Administrator e-mail address."
  type = string
  default = ""
}

variable "domain_name" {
  description = "Name of Opensearch domain."
  type = string
  default = ""
}

# BASTION

variable "bastion_type" {
  description = "Instance type for bastion host."
  type = string
  default = ""
}

variable "create_private_key" {
  description = "Switch for enabling creation of bastion private key."
  type = bool
  default = false
}

variable "bastion_key_name" {
  description = "Name of key pair for use with bastion host."
  type = string
  default = ""
}

variable "ingress_rules" {
  description = "List of rules for RDP access to bastion host."
  type = map(map(any))
  default = {}
}

# LAMBDA

variable "ephemeral_storage" {
  description = "Storage allocated to Lambda function."
  type = number
  default = 512
}

variable "memory_size" {
  description = "RAM allocated to Lambda function."
  type = number
  default = 128
}

# KINESIS

variable "shard_count" {
  description = "Count of shards in Kinesis stream."
  type = number
  default = 1
}


