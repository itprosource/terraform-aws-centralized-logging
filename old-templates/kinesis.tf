resource "aws_kinesis_stream" "cl_data_stream" {
  name             = "cl_data_stream"
  shard_count      = 1
  retention_period = 24

  encryption_type = "KMS"
  kms_key_id = "alias/aws/kinesis"

}

resource "aws_iam_role" "firehose_role" {
  name = "firehose_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "firehose.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_cloudwatch_log_stream" "firehose_es_log_stream" {
  name           = "ElasticSearchDelivery"
  log_group_name = aws_cloudwatch_log_group.firehose_log_group.name
}

resource "aws_cloudwatch_log_stream" "firehose_es_log_stream" {
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose_log_group.name
}

resource "aws_iam_role_policy" "cl_firehose_policy" {
  name = "cl_firehose_policy"
  role = aws_iam_role.firehose_role.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": {
              "s3:AbortMultipartUpload",
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:ListBucket",
              "s3:ListBucketMultipartUploads",
              "s3:PutObject"
            }
            "Resource": {
              "arn:aws:s3:::${aws_s3_bucket.access_logs_bucket.name}",
              "arn:aws:s3:::${aws_s3_bucket.access_logs_bucket.name}/*"

            }
            "Effect": "Allow"
        },
        {
            "Action": [
                "kms:GenerateDataKey",
                "kms:Decrypt"
            ],
            "Resource": "arn:aws:s3:::${aws_s3_bucket.access_logs_bucket.name}/*",
            "Effect": "Allow"
        },
        {
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "es.amazonaws.com"
                }
            },
            "Action": "iam:CreateServiceLinkedRole",
            "Resource": "arn:aws:iam::*:role/aws-service-role/es.amazonaws.com/AWSServiceRoleForAmazonElasticsearchService*",
            "Effect": "Allow"
        }
    ]
}
EOF
}

resource "aws_kinesis_firehose_delivery_stream" "cl_firehose" {
  name        = "cl-firehose"
  

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_role.arn
    bucket_arn = aws_s3_bucket.bucket.arn

    processing_configuration {
      enabled = "true"

      processors {
        type = "Lambda"

        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = "${aws_lambda_function.lambda_processor.arn}:$LATEST"
        }
      }
    }
  }
}