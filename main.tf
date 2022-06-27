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

resource "aws_cloudformation_stack" "create_es_service_role" {
  name = "create_es_service_role"

  template_body = <<STACK
{
  "Resources" : {
    "CreateESServiceRole": {
      "Type": "Custom::CreateESServiceRole",
      "Properties": {
        "ServiceToken": "${aws_lambda_function.helper_provider_framework_lambda.arn}",
      },
      "UpdateReplacePolicy": "Delete",
      "DeletionPolicy": "Delete",
      "Metadata": {
        "aws:cdk:path": "CL-PrimaryStack/CreateESServiceRole/Default"
      }
    }
  }
}
STACK
}

resource "aws_cloudformation_stack" "launch_data" {
  name = "launch_data"

  template_body = <<STACK
{
  "Resources" : {
    "LaunchData": {
      "Type": "Custom::LaunchData",
      "Properties": {
        "ServiceToken": "${aws_lambda_function.helper_provider_framework_lambda.arn}",
        "SolutionId": "SO0009",
        "SolutionVersion": "v4.0.1",
        "Stack": "PrimaryStack"
      },
      "UpdateReplacePolicy": "Delete",
      "DeletionPolicy": "Delete",
      "Metadata": {
        "aws:cdk:path": "CL-PrimaryStack/LaunchData/Default"
      }
    }
  }
}
STACK
}

resource "aws_cognito_user_pool" "es_user_pool_cognito" {
  name = "mypool"

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  admin_create_user_config {
      allow_admin_create_user_only = true
  }

  auto_verified_attributes = "email"

  email_verification_message = "The verification code to your new account is {####}"

  email_verification_subject = "Verify your new account"

  password_policy {
      minimum_length = 8
      require_lowercase = true
      require_numbers = true
      require_symbols = true
      require_uppercase = true
      temporary_password_validity_days = 3
  }

  schema {
    mutable = true
    name = "email"
    required = true
  }

  sms_verification_message = "The verification code to your new account is {####}"
  username_attributes = "email"
  
  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_message = "The verification code to your new account is {####}"
    email_subject = "Verify your new account"
    sms_message = "The verification code to your new account is {####}"
  }
}

resource "aws_cognito_user_pool_domain" "main" {
  domain       = "example-domain"
  user_pool_id = aws_cognito_user_pool.es_user_pool_cognito.id
}

resource "aws_cognito_user" "admin_user" {
    user_pool_id = aws_cognito_user_pool.es_user_pool_cognito.id
    attributes = {
        email = ""
    }
    username = ""  
}

resource "aws_cognito_identity_pool" "es_identity_pool" {
  identity_pool_name               = "identity pool"
  allow_unauthenticated_identities = false
}

resource "aws_iam_role" "cognito_auth_role" {
  name = "cognito_auth_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Principal": {
        "Service": "cognito-identity.amazonaws.com"
      },
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.es_identity_pool.arn}"
          },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:aud": "authenticated"
        }
      },
      "Effect": "Allow",
    }
  ]
}
EOF
}

resource "aws_cognito_identity_pool_roles_attachment" "main" {
  identity_pool_id = aws_cognito_identity_pool.es_identity_pool.id

  roles = {
    "authenticated" = aws_iam_role.cognito_auth_role.arn
  }
}

resource "aws_iam_role" "es_cognito_role" {
  name = "es_cognito_role"

  inline_policy {
    name = "es_cognito_access"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = [
            "cognito-idp:DescribeUserPool",
            "cognito-idp:CreateUserPoolClient",
            "cognito-idp:DeleteUserPoolClient",
            "cognito-idp:DescribeUserPolClient",
            "cognito-idp:AdminInitiateAuth",
            "cognito-idp:AdminUserGlobalSignOut",
            "cognito-idp:ListUserPoolClients",
            "cognito-idp:DescribeIdentityPool",
            "cognito-idp:UpdateIdentityPool",
            "cognito-idp:SetIdentityPoolRoles",
            "cognito-idp:GetIdentityPoolRoles"
          ]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "cognito_role_default_policy" {
  name = "cognito_role_default_policy"
  role = aws_iam_role.es_cognito_role.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "iam:PassRole",
            "Condition": {
                "StringLike": {
                "iam:PassedToService": "cognito-identity.amazonaws.com"
                }
            },
            "Effect": "Allow",
            "Resource": "${aws_iam_role.es_cognito_role.arn}"
        }
    ]
}
EOF
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

resource "aws_cloudwatch_log_group" "vpc_flow_log_group" {
  name = "cl-vpc-flow-log-group"
  retention_in_days = 731

  tags = {
  }
}

resource "aws_iam_role" "flow_role" {
  name = "flow_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "flow_role_default_policy" {
  name = "flow_role_default_policy"
  role = aws_iam_role.flow_role.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ],
            "Resource": [
                "${aws_cloudwatch_log_group.vpc_flow_log_group.arn}"
            ],
            "Effect": "Allow"
        },
    ]
}
EOF
}


resource "aws_vpc" "es_vpc" {
    cidr_block = var.es_vpc_cidr
    enable_dns_hostnames = true
    enable_dns_support = true
    instance_tenancy = "default"

}

resource "aws_subnet" "es_private_subnet" {
    count = length(var.es_private_subnet)
    cidr_block = element(var.es_private_subnet, count.index)
    vpc_id = aws_vpc.es_vpc.id
    availability_zone = element(var.availability_zones, count.index)
    map_public_ip_on_launch = false

}

resource "aws_route_table" "es_private_rte_table" {
    vpc_id = aws_vpc.es_vpc.id

}

resource "aws_route_table_association" "es_private_rte_table_association" {
    count = length(var.es_private_subnet)
    route_table_id = aws_route_table.es_private_rte_table.id
    subnet_id = ekement(aws_subnet.es_private_subnet.*.id, count.index)
  
}

resource "aws_subnet" "es_public_subnet" {
    count = length(var.es_public_subnet)
    cidr_block = element(var.es_public_subnet, count.index)
    vpc_id = aws_vpc.es_vpc.id
    availability_zone = element(var.availability_zones, count.index)
    map_public_ip_on_launch = true

}

resource "aws_route_table" "es_public_rte_table" {
    vpc_id = aws_vpc.es_vpc.id
  
}

resource "aws_route_table_association" "es_public_rte_table_association" {
    count = length(var.es_public_subnet)
    route_table_id = aws_route_table.es_public_rte_table.id
    subnet_id = element(aws_subnet.es_public_subnet.*.id, count.index)
  
}

resource "aws_route" "es_public_deafult_rte" {
    route_table_id = aws_route_table.es_public_rte_table.id
    destination_cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.es_vpc_igw.id

    depends_on = [
        aws_internet_gateway.es_vpc_igw
    ]
  
}

resource "aws_internet_gateway" "es_vpc_igw" {
    vpc_id = aws_vpc.es_vpc.id
  
}

resource "aws_flow_log" "aws_vpc_flow_log" {
  vpc_id = aws_vpc.es_vpc.id
  traffic_type = "ALL"
  iam_role_arn = aws_iam_role.flow_role.arn
  log_destination_type = "cloud-watch_logs"
  log_destination = aws_cloudwatch_log_group.vpc_flow_log_group.name

}

resource "aws_security_group" "es_sg" {
  name        = "es_sg"
  description = "SG for ES Domain"
  vpc_id      = aws_vpc.es_vpc.id

  ingress {
    description      = "TLS from VPC"
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = [aws_vpc.es_vpc.cidr_block]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "allow_tls"
  }
}

resource "aws_elasticsearch_domain" "es_domain" {
  domain_name           = var.domain_name
  elasticsearch_version = "7.10"

  accaccess_policies = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": {
        "es:ESHttpGet",
        "es:ESHttpDelete",
        "es:ESHttpPut",
        "es:ESHttpPost",
        "es:ESHttpHead",
        "es:ESHttpPatch"
      },
      "Principal": {
        "Service": "${aws_iam_role.cognito_auth_role.arn}"
      },
      "Resource:" {
        "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain_name}/*""
      }
      "Effect": "Allow",
      "Sid": ""
    },
    {
      "Action": {
        "es:DescribeElasticsearchDomain",
        "es:DescribeElasticsearchDomains",
        "es:DescribeElasticsearchDomainConfig",
        "es:ESHttpPost",
        "es:ESHttpPut",
        "es:ESHttpGet"
      },
      "Principal": {
        "Service": "${aws_iam_role.firehose_role.arn}"
      },
      "Resource:" {
        "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain_name}/*""
      }
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF

  cognito_options {
    enabled = true
    identity_pool_id = aws_cognito_identity_pool.es_identity_pool.id
    role_arn = aws_iam_role.es_cognito_role.arn
    user_pool_id = aws_cognito_identity_pool.es_identity_pool.arn
  }

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
    volume_type = "gp2"
  }

  cluster_config {
    dedicated_master_count = 3
    dedicated_master_enabled = true
    dedicated_master_type = ""

    zone_awareness_config {
      availability_zone_count = 2
    }

    zone_awareness_enabled = true

  }

  encrypt_at_rest {
    
  }

  log_publishing_options {
  }

  node_to_node_encryption {
    enabled = true
  }

  vpc_options {
    subnet_ids = [
      var.subnet_id_1,
      var.subnet_id_2,
    ]

    security_group_ids = [aws_security_group.es.id]
  }

  depends_on = [
    aws_cognito_user_pool_domain.main
  ]

  tags = {
    Domain = "TestDomain"
  }
}

resource "aws_iam_role_policy" "auth_role_policy" {
  name = "auth_role_policy"
  role = aws_iam_role.cognito_auth_role.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "es:ESHttpGet",
                "es:ESHttpDelete",
                "es:ESHttpPut",
                "es:ESHttpPost",
                "es:ESHttpHead",
                "es:ESHttpPatch"
            ],
            "Resource": [
                "${aws_elasticsearch_domain.es_domain.arn}"
            ],
            "Effect": "Allow"
        },
    ]
}
EOF
}

resource "aws_sqs_queue" "dl_queue" {
  name                      = "dl-queue"
  kms_master_key_id = "alias/aws/sqs"

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

resource "aws_kinesis_stream" "cl_data_stream" {
  name             = "cl_data_stream"
  shard_count      = 1
  retention_period = 24

  encryption_type = "KMS"
  kms_key_id = "alias/aws/kinesis"

}

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

resource "aws_s3_bucket" "cl_bucket" {
  bucket = "cl_bucket"

  server_side_encryption_configuration {
    rule {
        apply_server_side_encryption_by_default {
            sse_algorithm = "AES256"
        }
    }
  }
}

resource "aws_s3_bucket_logging" "cl_bucket_logging" {
  bucket = aws_s3_bucket.cl_bucket.id

  target_bucket = aws_s3_bucket.access_logs_bucket.id
  target_prefix = "cl-access-logs"
}

resource "aws_s3_bucket_public_access_block" "cl_bucket" {
  bucket = aws_s3_bucket.cl_bucket.id

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

resource "aws_cloudwatch_log_group" "firehose_log_group" {
  name = "/aws/kinesisfirehose/CL-Firehose"
  retention_in_days = 731

}

resource "aws_cloudwatch_log_stream" "firehose_es_log_stream" {
  name           = "ElasticSearchDelivery"
  log_group_name = aws_cloudwatch_log_group.firehose_log_group.name
}

resource "aws_cloudwatch_log_stream" "firehose_s3_log_stream" {
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
            },
            
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
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "s3.${data.aws_region.current.name}.amazonaws.com"
                },
                "StringLike": {
                    "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::${aws_s3_bucket.cl_bucket.name}/*"
                }
            },
            "Effect": "Allow",
            "Resource": "arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"
        },
        {
            "Action": {
              "ec2:DescribeVpcs",
              "ec2:DescribeVpcAttribute",
              "ec2:DescribeSubnets",
              "ec2:DescribeSecurityGroups",
              "ec2:DescribeNetworkInterfaces",
              "ec2:CreateNetworkInterface",
              "ec2:CreateNetworkInterfacePermission",
              "ec2:DeleteNetworkInterface"
            },
            "Resource": "*",
            "Effect": "Allow"
        },
        {
            "Action": {
              "es:DescribeElasticsearchDomain",
              "es:DescribeElasticsearchDomains",
              "es:DescribeElasticsearchDomainConfig",
              "es:ESHttpPost",
              "es:ESHttpPut"
            },
            "Resource": {
                "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}",
                "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/*"
                },
            "Effect": "Allow"
        },
        {
            "Action": "es:ESHttpGet",
            "Resource": {
                "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/_all/_settings",
                "arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/_cluster/stats",
                arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/cwl-kinesis/_mapping/kinesis",
                arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/_nodes",
                arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/_nodes/*/stats",
                arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/_stats",
                arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${aws_elasticsearch_domain.es_domain.name}/cwl-kinesis/_stats"
                },
            "Effect": "Allow"
        },
        {
            "Action": {
              "logs:PutLogEvents",
              "logs:CreateLogStream"
            },
            "Resource": "${aws_cloudwatch_log_group.firehose_log_group.arn}",
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
                    "kms:EncryptionContext:aws:kinesis:arn": "${aws_kinesis_stream.cl_data_stream.arn}"
                }
        },
    ]
}
EOF
}

resource "aws_kinesis_firehose_delivery_stream" "cl_firehose" {
  name        = "cl-firehose"
  destination = "elasticsearch"

  elasticsearch_configuration {
    cloudwatch_logging_options {
      enabled = true
      log_group_name = "/aws/kinesisfirehose/CL-Firehose"
      log_stream_name = "${aws_cloudwatch_log_stream.firehose_es_log_stream.name}"
    }

    domain_arn = aws_elasticsearch_domain.es_domain.arn
    role_arn   = aws_iam_role.firehose_role.arn
    index_name = "cwl"

    s3_configuration {
        bucket_arn = aws_s3_bucket.cl_bucket.arn

        cloudwatch_logging_options {
            enabled = true
            log_group_name = "/aws/kinesisfirehose/CL-Firehose"
            log_stream_name = aws_cloudwatch_log_stream.firehose_s3_log_stream.name
        }

        role_arn = aws_iam_role.firehose_role.arn 
    }

    ### Fix subnets
    vpc_config {
      subnet_ids         = [aws_subnet.es_private_subnet.id]
      security_group_ids = [aws_security_group.es_sg.id]
      role_arn           = aws_iam_role.firehose_role.arn
    }
  }

  depends_on = [aws_iam_policy.cl_firehose_policy]
}

resource "aws_iam_role" "cw_destination_role" {
  name = "cw_destination_role"

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

resource "aws_iam_role_policy" "cw_destination_policy" {
  name = "cw_destination_policy"
  role = aws_iam_role.cw_destination_role.arn

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "kinesis:PutRecord",
            "Effect": "Allow",
            "Resource": "${aws_kinesis_firehose_delivery_stream.cl_firehose.arn}"
        }
    ]
}
EOF
}

resource "aws_iam_role_policy" "helper_policy" {
  name = "helper_policy"
  role = aws_iam_role.helper_role.name

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "iam:PassRole",
            "Effect": "Allow",
            "Resource": "${aws_iam_role.cw_destination_role.arn}"
        }
    ]
}
EOF
}

resource "aws_cloudformation_stack" "cw_destination" {
  name = "cw_destination"

  parameters = {
    SpokeRegions = var.spoke_regions
    SpokeAccounts = var.spoke_accounts
  }

  template_body = <<STACK
{
  "Parameters" : {
    "SpokeRegions" : {
      "Type" : "String",
      "Default" : "",
      "Description" : "Enter the Spoke regions for demo stack."
    }
    "SpokeAccounts" : {
      "Type" : "String",
      "Default" : "",
    }
  },
  "Resources" : {
    "CWDestination": {
      "Type": "Custom::CWDestination",
      "Properties": {
        "ServiceToken": "${aws_lambda_function.helper_provider_framework_lambda.arn}",
        "Regions": {
          "Ref": "SpokeRegions"
        },
        "DestinationName": "CL-destination",
        "Role": "${aws_iam_role.cw_destination_role.arn}",
        "DataStream": "${aws_kinesis_stream.cl_data_stream.arn}",
        "SpokeAccounts": {
          "Ref": "SpokeAccounts"
        }
      },
      "DependsOn": [
        "${aws_iam_role_policy.helper_role_policy.arn}"
      ],
      "UpdateReplacePolicy": "Delete",
      "DeletionPolicy": "Delete",
      "Metadata": {
        "aws:cdk:path": "CL-PrimaryStack/CWDestination/Default"
      }
    }
  }
}
STACK
}

resource "aws_security_group" "cl_jumpbox_sg" {
  name        = "cl_jumpbox_sg"
  description = "SG for CL jumpbox"
  vpc_id      = aws_vpc.es_vpc.id

  egress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  egress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cl_jumpbox_sg"
  }
}

resource "aws_iam_role" "cl_jumpbox_instance_role" {
  name = "cl_jumpbox_ec2_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_instance_profile" "cl_jumpbox_ec2_profile" {
  name = "cl_jumpbox_ec2_profile"
  role = aws_iam_role.cl_jumpbox_instance_role
}

resource "aws_instance" "jumpbox" {
  ami           = data.aws_ami.windows-2019
  instance_type = "t3.micro"
  availability_zone = var.ec2_az
  iam_instance_profile = aws_iam_instance_profile.cl_jumpbox_ec2_profile.id
  key_name = var.jumpbox_key
  security_groups = [aws_security_group.cl_jumpbox_sg.id]
  subnet_id = aws_subnet.es_public_subnet.id

}

resource "aws_cloudformation_stack" "cl_demo_nested_stack" {
  template_url = "https://solutions-reference.s3.amazonaws.com/centralized-logging/v4.0.1/aws-centralized-logging-demo.template"
  parameters = {
    "CWDestinationParm" = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:destination:CL-Destination"
  }

  depends_on = [
    aws_elasticsearch_domain.es_domain
  ]
}