resource "aws_iam_role" "es_firehose_role" {
  name = "firehose-role-${var.domain_name}-${random_string.random.id}"

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

resource "aws_kinesis_stream" "es_data_stream" {
  name             = "data-stream-${var.domain_name}-${random_string.random.id}"
  shard_count      = 1
  retention_period = 24

  encryption_type = "KMS"
  kms_key_id = "alias/aws/kinesis"

}

resource "aws_cloudwatch_log_group" "es_firehose_log_group" {
  name = "/aws/kinesisfirehose/${var.domain_name}-${random_string.random.id}"
  retention_in_days = 731

}

resource "aws_cloudwatch_log_stream" "es_firehose_es_log_stream" {
  name           = "ElasticSearchDelivery"
  log_group_name = aws_cloudwatch_log_group.es_firehose_log_group.name
}

resource "aws_cloudwatch_log_stream" "es_firehose_s3_log_stream" {
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.es_firehose_log_group.name
}

resource "aws_iam_role_policy" "es_firehose_policy" {
  name = "firehose-policy-${var.domain_name}-${random_string.random.id}"
  role = aws_iam_role.es_firehose_role.name

  policy = <<EOF
{
	"Version": "2012-10-17",
	"Statement": [{
			"Action": [
				"s3:AbortMultipartUpload",
				"s3:GetBucketLocation",
				"s3:GetObject",
				"s3:ListBucket",
				"s3:ListBucketMultipartUploads",
				"s3:PutObject"
			],
			"Resource": [
				"arn:aws:s3:::${aws_s3_bucket.access_logs_bucket.bucket}",
				"arn:aws:s3:::${aws_s3_bucket.access_logs_bucket.bucket}/*"
			],
			"Effect": "Allow"
		},
		{
			"Action": [
				"kms:GenerateDataKey",
				"kms:Decrypt"
			],
			"Condition": {
				"StringEquals": {
					"kms:ViaService": "s3.${data.aws_region.current.name}.amazonaws.com"
				},
				"StringLike": {
					"kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::${aws_s3_bucket.cl_bucket.bucket}/*"
				}
			},
			"Effect": "Allow",
			"Resource": "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
		},
		{
			"Action": [
				"ec2:DescribeVpcs",
				"ec2:DescribeVpcAttribute",
				"ec2:DescribeSubnets",
				"ec2:DescribeSecurityGroups",
				"ec2:DescribeNetworkInterfaces",
				"ec2:CreateNetworkInterface",
				"ec2:CreateNetworkInterfacePermission",
				"ec2:DeleteNetworkInterface"
			],
			"Resource": "*",
			"Effect": "Allow"
		},
		{
			"Action": [
				"es:DescribeElasticsearchDomain",
				"es:DescribeElasticsearchDomains",
				"es:DescribeElasticsearchDomainConfig",
				"es:ESHttpPost",
				"es:ESHttpPut"
			],
			"Resource": [
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/*"
			],
			"Effect": "Allow"
		},
		{
			"Action": "es:ESHttpGet",
			"Resource": [
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/_all/_settings",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/_cluster/stats",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/cwl-kinesis/_mapping/kinesis",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/_nodes",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/_nodes/*/stats",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/_stats",
				"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.domain_name}/cwl-kinesis/_stats"
			],
			"Effect": "Allow"
		},
		{
			"Action": [
				"logs:PutLogEvents",
				"logs:CreateLogStream"
			],
			"Resource": "${aws_cloudwatch_log_group.es_firehose_log_group.arn}",
			"Effect": "Allow"
		},
		{
			"Action": "kms:Decrypt",
			"Resource": "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*",
			"Effect": "Allow",
			"Condition": {
				"StringEquals": {
					"kms:ViaService": "kinesis.${data.aws_region.current.name}.amazonaws.com"
				},
				"StringLike": {
					"kms:EncryptionContext:aws:kinesis:arn": "${aws_kinesis_stream.es_data_stream.arn}"
				}
			}
		}
	]
}
EOF
}

resource "aws_kinesis_firehose_delivery_stream" "es_firehose" {
  name        = "firehose-${var.domain_name}-${random_string.random.id}"
  destination = "elasticsearch"

  elasticsearch_configuration {
    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/kinesisfirehose/es-firehose-${var.domain_name}-${random_string.random.id}"
      log_stream_name = "${aws_cloudwatch_log_stream.es_firehose_es_log_stream.name}"
    }

    domain_arn = aws_elasticsearch_domain.es_domain.arn
    role_arn   = aws_iam_role.es_firehose_role.arn
    index_name = "cwl"

    vpc_config {
      subnet_ids         = aws_subnet.es_private_subnet.*.id
      security_group_ids = [aws_security_group.es_sg.id]
      role_arn           = aws_iam_role.es_firehose_role.arn
    }
  }

  s3_configuration {
    bucket_arn = aws_s3_bucket.cl_bucket.arn

    cloudwatch_logging_options {
            enabled = true
            log_group_name = "/aws/kinesisfirehose/s3-firehose-${var.domain_name}-${random_string.random.id}"
            log_stream_name = aws_cloudwatch_log_stream.es_firehose_s3_log_stream.name
        }

        role_arn = aws_iam_role.es_firehose_role.arn
    }

  depends_on = [aws_iam_role_policy.es_firehose_policy]
}

resource "aws_iam_role" "es_cw_destination_role" {
  name = "cw_destination_role-${var.domain_name}-${random_string.random.id}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "logs.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "es_cw_destination_policy" {
  name = "cw_destination_policy--${var.domain_name}-${random_string.random.id}"
  role = aws_iam_role.es_cw_destination_role.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "kinesis:PutRecord",
            "Effect": "Allow",
            "Resource": "${aws_kinesis_stream.es_data_stream.arn}"
        }
    ]
}
EOF
}

resource "aws_cloudwatch_log_destination" "cw_destination" {
  name       = "cw_destination_${random_string.random.id}"
  role_arn   = aws_iam_role.es_cw_destination_role.arn
  target_arn = aws_kinesis_stream.es_data_stream.arn
}
