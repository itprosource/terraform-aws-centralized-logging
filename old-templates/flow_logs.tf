resource "aws_cloudwatch_log_group" "vpc_flow_log_group" {
  name = "cl-vpc-flow-log-group"
  retention_in_days = 731

  tags = {
  }
}

resource "aws_iam_role" "flow_role" {
  name = "flow_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "flow_role_default_policy" {
  name = "flow_role_default_policy"
  role = aws_iam_role.flow_role.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "${aws_cloudwatch_log_group.vpc_flow_log_group.arn}"
            ],
            "Effect": "Allow"
        },
    ]
}
EOF
}