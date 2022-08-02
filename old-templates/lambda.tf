resource "aws_iam_role" "helper_role" {
  name = "helper_role_lambda"

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

resource "aws_iam_role_policy" "helper_role_policy" {
  name = "helper_role_policy"
  role = aws_iam_policy.helper_role.id

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:CreateLogGroup"
            ],
            "Resource": [
                "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*",
                "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:*:log-stream:*"
            ],
            "Effect": "Allow"
        },
        {
            "Action": [
                "ec2:DescribeRegions",
                "logs:PutDestination",
                "logs:DeleteDestination",
                "logs:PutDestinationPolicy"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "es.amazonaws.com"
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

resource "aws_lambda_function" "helper_lambda" {

  # Need to add s3 bucket from the template

  s3_bucket = "solutions-${data.aws_caller_identity.current.account_id}-centralized-logging/v4.0.1/asset9b4c683682a0773735625e441eabc438ac1d2b4ef65d28093ba33154aaaa2a66.zip"
  function_name = var.function_name
  role          = aws_iam_role.helper_role.arn
  description = "centralized-logging -  solution helper functions"

  environment {
    variables = {
      LOG_LEVEL = ""
      METRICS_ENDPOINT = [
          "CLMap",
          "Metric",
          "MetricsEndpoint"
      ]
      SEND_METRIC = [
          "CLMap",
          "Metric",
          "SendAnonymousMetric"
      ]
      CUSTOM_SDK_USER_AGENT = "AwsSolution/SO0009/v4.0.1"
    }
  }

  handler = "index.handler"
  runtime = "nodejs14.x"
  timeout = 300

  depends_on = [
      aws_iam_role.helper_role,
      aws_iam_role_policy.helper_role_policy
  ]
}

resource "aws_iam_role" "helper_provider_event_svc" {
  name = "helper_provider_framework_event_svc_role"
  managed_policy_arns = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

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

resource "aws_iam_role_policy" "helper_provider_event_svc_default_policy" {
  name = "helper_provider_event_svc_default_policy"
  role = aws_iam_role.helper_provider_event_svc.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "lambda:InvokeFuntion",
            "Resource": "${aws_iam_role.helper_role.arn}",
            "Effect": "Allow"
        },
        {
            "Action": [
                "ec2:DescribeRegions",
                "logs:PutDestination",
                "logs:DeleteDestination",
                "logs:PutDestinationPolicy"
            ],
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "es.amazonaws.com"
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

resource "aws_lambda_function" "helper_provider_framework_lambda" {

  s3_bucket = "solutions-${data.aws_caller_identity.current.account_id}-centralized-logging/v4.0.1/ssetc691172cdeefa2c91b5a2907f9d81118e47597634943344795f1a844192dd49c.zip"
  function_name = var.function_name
  role          = aws_iam_role.helper_provider_event_svc.arn
  description = "AWS CDK resource provider framework - onEvent (CL-PrimaryStack/HelperProvider)"

  environment {
    variables = {
      USER_ON_EVENT_FUNCTION_ARN = "${aws_lambda_function.helper_lambda.arn}"
    }
  }

  handler = "solutions-${data.aws_caller_identity.current.account_id}-assetc691172cdeefa2c91b5a2907f9d81118e47597634943344795f1a844192dd49c/framework.onEvent"
  runtime = "nodejs12.x"
  timeout = 900

  depends_on = [
      aws_iam_role.helper_provider_event_svc,
      aws_iam_role_policy.helper_provider_event_svc_default_policy
  ]
}

resource "aws_iam_role" "cl_transformer_svc_role" {
  name = "cl_transformer_svc_role"
  managed_policy_arns = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"

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
  name = "helper_provider_event_svc_default_policy"
  role = aws_iam_role.helper_provider_event_svc.arn

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
            "Resource": "${CLDATASTREAM}",
            "Effect": "Allow"
        },
        {
            "Condition": {
                "StringLike": {
                    "iam:AWSServiceName": "es.amazonaws.com"
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

resource "aws_lambda_function" "cl_transformer_lambda" {

  s3_bucket = "solutions-${data.aws_caller_identity.current.account_id}-centralized-logging/v4.0.1/assetb9316d9a0f47aa8516cdc62510095e3fcad7da2127a60add35eef432d3e28c30.zip"
  function_name = var.function_name
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
      CLUSTER_SIZE = var.cluster_size
      DELIVERY_STREAM = "CL-Firehose"
      METRICS_ENDPOINT = ""
      SEND_METRIC = ""
      CUSTOM_SDK_USER_AGENT = "AwsSolution/SO0009/v4.0.1"
    }
  }

  handler = "index.handler"
  runtime = "nodejs14.x"
  timeout = 300

  depends_on = [
      aws_iam_role.cl_transformer_svc_role,
      aws_iam_role_policy.cl_transformer_svc_default_policy
  ]
}

resource "aws_lambda_event_source_mapping" "example" {
  event_source_arn  = aws_kinesis_stream.cl_data_stream.arn
  function_name     = aws_lambda_function.cl_transformer_lambda.function_name
  batch_size = 100
  starting_position = "TRIM_HORIZON"
}

resource "aws_sns_topic" "cl_lambda_error" {
  name = "cl-lambda-error"
  kms_master_key_id = "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:alias/aws/sns"
}

resource "aws_sns_topic_subscription" "user_updates_sqs_target" {
  topic_arn = "arn:aws:sns:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:cl-lambda-error"
  protocol  = "email"
  endpoint  = var.admin_email
}

resource "aws_cloudwatch_metric_alarm" "cl_lambda_error_alarm" {
  alarm_name                = "cl_lambda_error_alarm"
  comparison_operator       = "GreaterThanOrEqualToThreshold"
  evaluation_periods        = "1"
  alarm_actions = [aws_sns_topic.cl_lambda_error.arn]
  dimensions = {
    FunctionName = aws_lambda_function.cl_transformer_lambda.name
  }
  metric_name               = "Errors"
  namespace                 = "AWS/Lambda"
  period                    = "300"
  statistic                 = "Sum"
  threshold                 = "0.05"
}