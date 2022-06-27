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