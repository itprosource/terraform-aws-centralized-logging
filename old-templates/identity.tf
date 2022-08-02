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


#### COME BACK TO THIS
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
          }
      },
      "Effect": "Allow",
      "Sid": ""
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

### COME BACK TO THIS
resource "aws_iam_role" "es_cognito_role" {
  name = "es_cognito_role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "es.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}




