# Creates access policy file used to control Destination access permissions. 
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

# Used to delay running the local-exec below - otherwise a race condition causes the command to attempt executing before the access policy file is available. 
resource "time_sleep" "wait_60_seconds" {
  depends_on = [local_file.access_policy]

  create_duration = "60s"
}

# Command to create or modify Destination access policy based on access_policy.json file. 
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

