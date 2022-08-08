provider "aws" {
  region = "us-east-1"
}

module "centralized_logging" {
  source = "../"

  # Opensearch Domain
  domain_name = "testdomain08"
  elasticsearch_version = "OpenSearch_1.3"
  es_vpc_cidr = "10.0.0.0/16"
  azs = [
    "us-east-1a",
    "us-east-1b"
  ]
  es_public_subnet = [
    "10.0.1.0/24",
    "10.0.2.0/24"
  ]
  es_private_subnet = [
    "10.0.3.0/24",
    "10.0.4.0/24"
  ]

  # CLUSTER CONFIGURATION
  # Master Nodes - The default master_node_count is 3, default type is c5.large.
  # Master node defaults are sufficient for most cases except extremely large workloads.
  master_node_count = 3
  dedicated_master_type = "t3.small.elasticsearch"
  # Data Nodes - In 2-az configuration, instance_count must in multiples of 2.
  # In 3-az configuration, count can be any number above 3.
  instance_count = 2
  instance_type = "t3.small.elasticsearch"

  # EBS volumes
  volume_size = "10"
  volume_type = "gp2"

  warm_enabled = false
  warm_type = "ultrawarm1.medium.elasticsearch"
  warm_count = 2


  # LAMBDA TRANSFORMER FUNCTION
  memory_size = 128
  ephemeral_storage = 512

  # KINESIS DATA STREAM
  shard_count = 1

  spoke_accounts = "590476071401"
  spoke_regions = "us-east-1"
  admin_email = "austin.thome1@gmail.com"
  bastion_key = "austin-personal"

  ingress_addrs = [
    "0.0.0.0/0",
    "10.0.0.0/24"
    ]

}