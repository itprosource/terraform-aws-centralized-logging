# Data source which pulls the AWS account ID and region from Provider.
# Used in various IAM resources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Pulls latest Windows AMI
data "aws_ami" "windows-2019" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["Windows_Server-2019-English-Full-Base*"]
  }
}