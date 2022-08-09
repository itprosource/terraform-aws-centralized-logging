resource "aws_s3_bucket" "es_access_logs_bucket" {
  bucket = "access-logs-bucket-${var.domain_name}-${random_string.random.id}"
  acl = "log-delivery-write"

  server_side_encryption_configuration {
    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "es_access_logs_bucket" {
  bucket = aws_s3_bucket.es_access_logs_bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "es_bucket" {
  bucket = "cl-bucket-${var.domain_name}-${random_string.random.id}"

  server_side_encryption_configuration {
    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
  }
}

resource "aws_s3_bucket_logging" "es_bucket_logging" {
  bucket = aws_s3_bucket.es_bucket.id

  target_bucket = aws_s3_bucket.es_access_logs_bucket.id
  target_prefix = "cl-access-logs"
}

resource "aws_s3_bucket_public_access_block" "es_bucket" {
  bucket = aws_s3_bucket.es_bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "es_bucket_policy" {
  bucket = aws_s3_bucket.es_access_logs_bucket.id
  policy =<<POLICY
{
	"Version": "2012-10-17",
	"Id": "MYBUCKETPOLICY",
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": "${aws_iam_role.es_firehose_role.arn}"
		},
		"Action": [
			"s3:Put*",
			"s3:Get*"
		],
		"Resource": [
			"${aws_s3_bucket.es_access_logs_bucket.arn}",
			"${aws_s3_bucket.es_access_logs_bucket.arn}/*"
		]
	}]
}
POLICY
}