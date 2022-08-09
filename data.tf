# Data source which pulls the AWS account ID and region from Provider.
# Used in various IAM resources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Pulls latest Windows ami from Amzn Marketplace
data "aws_ami" "windows" {
     most_recent = true
filter {
       name   = "name"
       values = ["Windows_Server-2019-English-Full-Base-*"]
  }
filter {
       name   = "virtualization-type"
       values = ["hvm"]
  }
owners = ["801119661308"] # Canonical
}

