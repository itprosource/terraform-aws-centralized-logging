# OPENSEARCH

variable "azs" {
  description = "List of Availability Zones."
  type = list(string)
}

variable "es_vpc_cidr" {
  description = "CIDR block for VPC hosting Opensearch."
  type = string
}

variable "es_private_subnet" {
  description = "Private subnet CIDR for Opensearch VPC."
  type = list(string)
}

variable "es_public_subnet" {
  description = "Public subnet CIDR for Opensearch VPC."
  type = list(string)
}

variable "elasticsearch_version" {
  description = "Version or Elasticsearch or Opensearch to deploy."
  type = string
}

variable "volume_size" {
  description = "Size of node EBS volumes."
  type = string
}

variable "volume_type" {
  description = "Type of node EBS volumes."
  type = string
}

variable "master_node_count" {
  description = "Count of dedicated master nodes."
  type = number
}

variable "dedicated_master_type" {
  description = "Instance type of dedicated master nodes."
  type = string
}

variable "warm_enabled" {
  description = "Enables ultrawarm storage nodes."
  type = bool
}

variable "warm_count" {
  description = "Count of ultrawarm storage nodes."
  type = number
}

variable "warm_type" {
  description = "Instance type of ultrawarm storage nodes."
  type = string
}

variable "instance_count" {
  description = ""
  type = number
}

variable "instance_type" {
  description = ""
  type = string
}

variable "availability_zone_count" {
  description = "Count of availability zones in use."
  type = number
}

variable "spoke_accounts" {
  description = "List of spoke accounts to access the CW Destination."
  type = string
}

variable "admin_email" {
  description = "Administrator e-mail address."
  type = string
}

variable "domain_name" {
  description = "Name of Opensearch domain."
  type = string
}

# BASTION

variable "bastion_type" {
  description = "Instance type for bastion host."
  type = string
}

variable "create_private_key" {
  description = "Switch for enabling creation of bastion private key."
  type = bool
}

variable "bastion_key_name" {
  description = "Name of key pair for use with bastion host."
  type = string
}

variable "ingress_rules" {
  description = "List of rules for RDP access to bastion host."
  type = map(map(any))
}

# LAMBDA

variable "ephemeral_storage" {
  description = "Storage allocated to Lambda function."
  type = number
}

variable "memory_size" {
  description = "RAM allocated to Lambda function."
  type = number
}

# KINESIS

variable "shard_count" {
  description = "Count of shards in Kinesis stream."
  type = number
}


