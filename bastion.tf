### SECURITY GROUP
# 443 is allowed from any address but RDP access is controlled by including IP ranges and descriptions
# in ingress_rules variable
resource "aws_security_group" "es_bastion_sg" {
  name        = "bastion_sg-${var.domain_name}${random_string.random.id}"
  description = "Security group controlling Central Logging bastion host access."
  vpc_id      = aws_vpc.es_vpc.id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }

  tags = {
    Name = "bastion_sg-${var.domain_name}${random_string.random.id}"
  }
}

resource "aws_security_group_rule" "es_ingress" {
  for_each = var.ingress_rules
  type              = "ingress"
  from_port         = 3389
  to_port           = 3389
  protocol          = "tcp"
  cidr_blocks       = [each.value.cidr]
  description       = each.value.desc
  security_group_id = aws_security_group.es_bastion_sg.id
}

### IAM

resource "aws_iam_role" "es_bastion_instance_role" {
  name = "bastion_ec2_role-${var.domain_name}-${random_string.random.id}"

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

resource "aws_iam_instance_profile" "es_bastion_ec2_profile" {
  name = "cl_jumpbox_ec2_profile-${random_string.random.id}"
  role = aws_iam_role.es_bastion_instance_role.name
}

### BASTION HOST

resource "aws_instance" "es_jumpbox" {
  count = 1
  ami           = data.aws_ami.windows.id
  instance_type = var.bastion_type
  availability_zone = element(var.azs,count.index)
  iam_instance_profile = aws_iam_instance_profile.es_bastion_ec2_profile.id
  key_name = var.bastion_key
  vpc_security_group_ids = [aws_security_group.es_bastion_sg.id]
  #security_groups = [aws_security_group.cl_bastion_sg.id]
  subnet_id = element(aws_subnet.es_public_subnet.*.id,count.index)

  tags = {
    Name = "bastion-${var.domain_name}-${random_string.random.id}"
  }
}