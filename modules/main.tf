provider "aws" {
  region = "us-east-1"
}

module "centralized_logging" {
  source = "../"

  # OPENSEARCH DOMAIN DETAILS
  # For the version, you can select Opensearch or Elasticsearch versions.
  domain_name = "testdomain"
  elasticsearch_version = "OpenSearch_1.3"

  # Spoke accounts are given access to utilize the Cloudwatch Destination as a subscription filter.
  # Enter spoke account #s separated by a comma. Ex: "111111111111,222222222222,333333333333"
  spoke_accounts = "111111111111"

  # The initial admin login.
  admin_email = "your.email@message.com"

  # Define the network space for the Opensearch cluster.
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
  # Master Nodes - The default master_node_count is 3.
  # Master node defaults are sufficient for most cases except extremely large workloads.
  master_node_count = 3
  dedicated_master_type = "m5.large.elasticsearch"
  # Data Nodes - In 2-az configuration, instance_count must in multiples of 2.
  # In 3-az configuration, count can be any number above 3.
  instance_count = 2
  instance_type = "m5.large.elasticsearch"

  # EBS VOLUMES
  # Storage will need to scale with expected data ingest size.
  volume_size = "10"
  volume_type = "gp2"

  # ULTRAWARM STORAGE
  # Enables ultrawarm nodes for cost-saving data retention via hot/warm/cold storage lifecycle.
  # If enabled,an index management policy must be deployed in Opensearch before lifecycling will take effect.
  warm_enabled = false
  warm_type = "ultrawarm1.medium.elasticsearch"
  warm_count = 2

  # LAMBDA TRANSFORMER FUNCTION
  # Resources will need to scale with expected data ingest size.
  memory_size = 128
  ephemeral_storage = 512

  # KINESIS DATA STREAM
  # Shards will need to scale with expected data ingest size
  shard_count = 1

  # BASTION HOST
  # Set the instance type for the bastion host.
  # For many cases, t3.micro will be sufficient. Select larger types for cases needing multiple simultaneous logins.
  bastion_type = "t3.micro"

  # Switch to create a private key for bastion access.
  # Set to TRUE to create a key and store it in Secrets Manager during creation.
  # Set to FALSE to use an existing key identified via bastion_key_name.
  create_private_key = true
  bastion_key_name = "es-bastion-key"

  # Set the allowed RDP IP address ranges.
  # Allow All (0.0.0.0/0) is not recommended for production cases.
  ingress_rules = {
    rule01 = {
      cidr    = "0.0.0.0/0"
      desc    = "Allow All"
    },
    rule02 = {
      cidr   = "10.0.0.0/24"
      desc   = "Allow Example Corporate Range"
    }
  }

}