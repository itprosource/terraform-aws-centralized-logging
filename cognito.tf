resource "aws_cognito_user_pool" "es_user_pool_cognito" {
  name = "user_pool-${var.domain_name}-${random_string.random.id}"

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  admin_create_user_config {
      allow_admin_create_user_only = true
  }

  auto_verified_attributes = ["email"]

  password_policy {
      minimum_length = 8
      require_lowercase = true
      require_numbers = true
      require_symbols = true
      require_uppercase = true
      temporary_password_validity_days = 3
  }

  schema {
    attribute_data_type = "String"
    mutable = true
    name = "email"
    required = true

    string_attribute_constraints {
      max_length =  48
    }
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_message = "The verification code to your new account is {####}"
    email_subject = "Verify your new account"
    sms_message = "The verification code to your new account is {####}"
  }

  lifecycle {
    ignore_changes = [schema]
  }
}

resource "aws_cognito_user_pool_domain" "es_user_pool_domain" {
  domain       = "${var.domain_name}-${random_string.random.id}"
  user_pool_id = aws_cognito_user_pool.es_user_pool_cognito.id
}

resource "aws_cognito_user" "es_admin_user" {
    user_pool_id = aws_cognito_user_pool.es_user_pool_cognito.id
    attributes = {
        email = var.admin_email
    }
    username = var.admin_email
}

resource "aws_cognito_identity_pool" "es_identity_pool" {
  identity_pool_name               = "identity_pool-${var.domain_name}-${random_string.random.id}"
  allow_unauthenticated_identities = false
}

resource "aws_cognito_identity_pool_roles_attachment" "es_role_attachment" {
  identity_pool_id = aws_cognito_identity_pool.es_identity_pool.id

  roles = {
    "authenticated" = aws_iam_role.es_cognito_auth_role.arn
  }
}

resource "aws_iam_role" "es_cognito_auth_role" {
  name = "cognito_auth_role-${var.domain_name}-${random_string.random.id}"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Principal": {
        "Federated": "cognito-identity.amazonaws.com"
      },
      "Condition": {
        "StringEquals": {
          "cognito-identity.amazonaws.com:aud": "${aws_cognito_identity_pool.es_identity_pool.id}"
          },
        "ForAnyValue:StringLike": {
          "cognito-identity.amazonaws.com:amr": "authenticated"
        }
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

resource "aws_iam_role" "es_cognito_role" {
  name = "cognito_role-${var.domain_name}-${random_string.random.id}"

  inline_policy {
    name = "cognito_access-${var.domain_name}-${random_string.random.id}"

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
            "cognito-identity:DescribeIdentityPool",
            "cognito-identity:UpdateIdentityPool",
            "cognito-identity:SetIdentityPoolRoles",
            "cognito-identity:GetIdentityPoolRoles"
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

resource "aws_iam_role_policy" "es_cognito_role_default_policy" {
  name = "cognito-role-default-policy-${var.domain_name}-${random_string.random.id}"
  role = aws_iam_role.es_cognito_role.name

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

resource "aws_iam_role_policy" "es_auth_role_policy" {
  name = "auth-role-policy-${var.domain_name}-${random_string.random.id}"
  role = aws_iam_role.es_cognito_auth_role.name

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
                "${aws_elasticsearch_domain.es_domain.arn}/*"
            ],
            "Effect": "Allow"
        }
    ]
}
EOF
}