resource "aws_cloudwatch_log_group" "firehose_log_group" {
  name = "firehose-log-group"
  retention_in_days = 731

  tags = {
    Environment = "production"
    Application = "serviceA"
  }
}