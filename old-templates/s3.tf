resource "aws_s3_bucket" "access_logs_bucket" {
  bucket = "access_logs_bucket"
  acl = "log_delivery_write"

  server_side_encryption_configuration {
    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "access_logs_bucket" {
  bucket = aws_s3_bucket.access_logs_bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cl-bucket-policy" {
  bucket = aws_s3_bucket.access_logs_bucket.id
  policy =<<POLICY
{
  "Version": "2012-10-17",
  "Id": "MYBUCKETPOLICY",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "${aws_iam_role.firehose_role.arn}",
      "Action": {
        "s3:Put*",
        "s3:Get*"
      }
      "Resource": "${aws_s3_bucket.access_logs_bucket.arn}/*",
    } 
  ]
}
POLICY
}
