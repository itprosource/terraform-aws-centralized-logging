resource "aws_sqs_queue" "dl_queue" {
  name                      = "dl-queue"
  kms_master_key_id = "alias/aws/sqs"

}

