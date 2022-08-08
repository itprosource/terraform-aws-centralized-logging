resource "local_file" "access_policy" {
  content =<<EOF
{
  "Version" : "2012-10-17",
  "Statement" : [
    {
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "${var.spoke_accounts}"
      },
      "Action" : "logs:PutSubscriptionFilter",
      "Resource" : "${aws_cloudwatch_log_destination.cw_destination.arn}"
    }
  ]
}
EOF

  filename = "../modules/access_policy.json"

  depends_on = [aws_cloudwatch_log_destination.cw_destination]
}

resource "time_sleep" "wait_60_seconds" {
  depends_on = [local_file.access_policy]

  create_duration = "60s"
}

resource "null_resource" "put_destination_policy" {

  triggers = {
    always_run = "${timestamp()}"
  }

  provisioner "local-exec" {
    command = "aws logs put-destination-policy --destination-name ${aws_cloudwatch_log_destination.cw_destination.name} --access-policy file://access_policy.json --region ${data.aws_region.current.name}"
  }

  depends_on = [
    local_file.access_policy,
    time_sleep.wait_60_seconds
  ]
}

