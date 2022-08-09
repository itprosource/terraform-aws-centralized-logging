# NETWORK COMPONENTS

resource "aws_cloudwatch_log_group" "es_vpc_flow_log_group" {
  name = "vpc-flow-log-group-${var.domain_name}-${random_string.random.id}"
  retention_in_days = 731

}

resource "aws_iam_role" "es_flow_role" {
  name = "flow_role-${var.domain_name}-${random_string.random.id}"

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

resource "aws_iam_role_policy" "es_flow_role_default_policy" {
  name = "flow-role-default-policy-${var.domain_name}-${random_string.random.id}"
  role = aws_iam_role.es_flow_role.name

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
                "${aws_cloudwatch_log_group.es_vpc_flow_log_group.arn}"
            ],
            "Effect": "Allow"
        }
    ]
}
EOF
}


resource "aws_vpc" "es_vpc" {
    cidr_block = var.es_vpc_cidr
    enable_dns_hostnames = true
    enable_dns_support = true
    instance_tenancy = "default"

  tags = {
    Name = "${var.domain_name}-${random_string.random.id}"
  }

}

resource "aws_subnet" "es_private_subnet" {
    count = length(var.es_private_subnet)
    cidr_block = element(var.es_private_subnet, count.index)
    vpc_id = aws_vpc.es_vpc.id
    availability_zone = element(var.azs, count.index)
    map_public_ip_on_launch = false

    tags = {
      Name = "${var.domain_name}-${random_string.random.id}-priv-${count.index+1}"
      Tier = "Private"
  }
}

resource "aws_route_table" "es_private_rte_table" {
    vpc_id = aws_vpc.es_vpc.id

    tags = {
      Name = "${var.domain_name}-${random_string.random.id}-priv_rte"
  }

}

resource "aws_route_table_association" "es_private_rte_table_association" {
    count = length(var.es_private_subnet)
    route_table_id = aws_route_table.es_private_rte_table.id
    subnet_id = element(aws_subnet.es_private_subnet.*.id, count.index)

}

resource "aws_subnet" "es_public_subnet" {
    count = length(var.es_public_subnet)
    cidr_block = element(var.es_public_subnet, count.index)
    vpc_id = aws_vpc.es_vpc.id
    availability_zone = element(var.azs, count.index)
    map_public_ip_on_launch = true

    tags = {
      Name = "${var.domain_name}-${random_string.random.id}-pub-${count.index+1}"
      Tier = "Public"
  }

}

resource "aws_route_table" "es_public_rte_table" {
    vpc_id = aws_vpc.es_vpc.id

    tags = {
      Name = "${var.domain_name}-${random_string.random.id}-pub_rte"
  }

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

    tags = {
      Name = "${var.domain_name}-${random_string.random.id}"
  }

}

resource "aws_flow_log" "aws_vpc_flow_log" {
  vpc_id = aws_vpc.es_vpc.id
  traffic_type = "ALL"
  iam_role_arn = aws_iam_role.es_flow_role.arn
  log_destination_type = "cloud-watch-logs"
  log_destination = aws_cloudwatch_log_group.es_vpc_flow_log_group.arn

}

resource "aws_security_group" "es_sg" {
  name        = "es_sg-${var.domain_name}-${random_string.random.id}"
  description = "Security Group for ES Domain"
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
  domain_name           = "${var.domain_name}-${random_string.random.id}"
  elasticsearch_version = var.elasticsearch_version

  access_policies = <<EOF
{
   "Version":"2012-10-17",
   "Statement":[
      {
         "Effect":"Allow",
         "Principal":{
            "AWS":"${aws_iam_role.es_cognito_auth_role.arn}"
         },
         "Action":[
            "es:ESHttpGet",
            "es:ESHttpDelete",
            "es:ESHttpPut",
            "es:ESHttpPost",
            "es:ESHttpHead",
            "es:ESHttpPatch"
         ],
         "Resource":"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain_name}/*"
      },
      {
         "Effect":"Allow",
         "Principal":{
            "AWS":"${aws_iam_role.es_firehose_role.arn}"
         },
         "Action":[
            "es:DescribeElasticsearchDomain",
            "es:DescribeElasticsearchDomains",
            "es:DescribeElasticsearchDomainConfig",
            "es:ESHttpPost",
            "es:ESHttpPut",
            "es:HttpGet"
         ],
         "Resource":"arn:aws:es:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:domain/${var.domain_name}/*"
      }
   ]
}
EOF

  cognito_options {
    enabled = true
    identity_pool_id = aws_cognito_identity_pool.es_identity_pool.id
    role_arn = aws_iam_role.es_cognito_role.arn
    user_pool_id = aws_cognito_user_pool.es_user_pool_cognito.id
  }

  domain_endpoint_options {
    enforce_https = true
    tls_security_policy = "Policy-Min-TLS-1-0-2019-07"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = var.volume_size
    volume_type = var.volume_type
  }

  cluster_config {
    dedicated_master_count = var.master_node_count
    dedicated_master_enabled = true
    dedicated_master_type = var.dedicated_master_type
    instance_count = var.instance_count
    instance_type = var.instance_type
    warm_count = var.warm_count
    warm_enabled = var.warm_enabled
    warm_type = var.warm_type

    zone_awareness_config {
      availability_zone_count = var.availability_zone_count
    }

    zone_awareness_enabled = true

  }

  encrypt_at_rest {
    enabled = true
  }

  node_to_node_encryption {
    enabled = true
  }

  vpc_options {
    subnet_ids = aws_subnet.es_private_subnet.*.id
    security_group_ids = [aws_security_group.es_sg.id]
  }

  depends_on = [
    aws_cognito_user_pool_domain.es_user_pool_domain,
    aws_vpc.es_vpc
  ]

  tags = {
    Domain = "${var.domain_name}-${random_string.random.id}"
  }
}
