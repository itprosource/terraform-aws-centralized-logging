resource "aws_sqs_queue" "es_dl_queue" {
  name = "dl-queue-${random_string.random.id}"
  kms_master_key_id = "alias/aws/sqs"

}