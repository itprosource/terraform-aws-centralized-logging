resource "aws_iam_role" "cl_transformer_svc_role" {
  name = "cl_transformer_svc_role"
  managed_policy_arns = ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"]

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cl_transformer_svc_default_policy" {
  name = "cl-transformer-svc-default-policy"
  role = aws_iam_role.cl_transformer_svc_role.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sqs:SendMessage",
            "Resource": "${aws_sqs_queue.dl_queue.arn}",
            "Effect": "Allow"
        },
        {
            "Action": [
                "kinesis:DescribeStreamSummary",
                "kinesis:GetRecords",
                "kinesis:GetShardIterator",
                "kinesis:ListShards",
                "kinesis:SubscribeToShard"
            ],
            "Resource": "${aws_kinesis_stream.cl_data_stream.arn}",
            "Effect": "Allow"
        },
        {
            "Action": [
                "kinesis:DescribeStream"
            ],
            "Effect": "Allow",
            "Resource": "${aws_kinesis_stream.cl_data_stream.arn}"
        },
        {
            "Action": "firehose:PutRecordBatch",
            "Effect": "Allow",
            "Resource": "${aws_kinesis_firehose_delivery_stream.cl_firehose.arn}"
        }
    ]
}
EOF
}

resource "aws_lambda_function" "cl_transformer_lambda" {

  s3_bucket = "solutions-${data.aws_region.current.name}"
  s3_key = "centralized-logging/v4.0.1/assetb9316d9a0f47aa8516cdc62510095e3fcad7da2127a60add35eef432d3e28c30.zip"
  function_name = "ClTransformer-${random_string.random.id}"
  role          = aws_iam_role.cl_transformer_svc_role.arn

  dead_letter_config {
    target_arn = "${aws_sqs_queue.dl_queue.arn}"
  }
  description = "centralized-logging - Lambda function to transform log events and send to kinesis firehose"

  environment {
    variables = {
      LOG_LEVEL = "info"
      SOLUTION_ID = "SO0009"
      SOLUTION_VERSION = "v4.0.1"
      #CLUSTER_SIZE = ""
      DELIVERY_STREAM = "${aws_kinesis_firehose_delivery_stream.cl_firehose.name}"
      CUSTOM_SDK_USER_AGENT = "AwsSolution/SO0009/v4.0.1"
    }
  }

  handler = "index.handler"
  runtime = "nodejs14.x"
  timeout = 300
  memory_size = var.memory_size

  ephemeral_storage {
    size = var.ephemeral_storage
  }

  depends_on = [
      aws_iam_role.cl_transformer_svc_role,
      aws_iam_role_policy.cl_transformer_svc_default_policy
  ]
}

resource "aws_lambda_event_source_mapping" "cl_transformer_event_source" {
  event_source_arn  = aws_kinesis_stream.cl_data_stream.arn
  function_name     = aws_lambda_function.cl_transformer_lambda.function_name
  batch_size = 100
  starting_position = "TRIM_HORIZON"
}

resource "aws_sns_topic" "cl_lambda_error" {
  name = "cl-lambda-error"
  kms_master_key_id = "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"
}

resource "aws_sns_topic_subscription" "topic_token_subscription" {
  topic_arn = aws_sns_topic.cl_lambda_error.arn
  protocol  = "email"
  endpoint  = var.admin_email
}

resource "aws_cloudwatch_metric_alarm" "cl_lambda_error_alarm" {
  alarm_name          = "cl_lambda_error_alarm"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "1"
  alarm_actions       = [aws_sns_topic.cl_lambda_error.arn]
  dimensions          = {
    FunctionName = aws_lambda_function.cl_transformer_lambda.function_name
  }
  metric_name = "Errors"
  namespace   = "AWS/Lambda"
  period      = "300"
  statistic   = "Sum"
  threshold   = "0.05"
}