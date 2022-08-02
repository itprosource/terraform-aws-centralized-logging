resource "aws_security_group" "cl_bastion_sg" {
  name        = "cl_bastion_sg-${random_string.random.id}"
  description = "SG for CL bastion"
  vpc_id      = aws_vpc.es_vpc.id

  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
  }
  ingress {
    from_port        = 3389
    to_port          = 3389
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
    Name = "cl_bastion_sg-${random_string.random.id}"
  }
}

resource "aws_iam_role" "cl_bastion_instance_role" {
  name = "cl_bastion_ec2_role"

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

resource "aws_iam_instance_profile" "cl_bastion_ec2_profile" {
  name = "cl_jumpbox_ec2_profile-${random_string.random.id}"
  role = aws_iam_role.cl_bastion_instance_role.name
}

resource "aws_instance" "jumpbox" {
  count = 1
  ami           = data.aws_ami.windows.id
  instance_type = "t3.micro"
  availability_zone = element(var.azs,count.index)
  iam_instance_profile = aws_iam_instance_profile.cl_bastion_ec2_profile.id
  key_name = var.bastion_key
  security_groups = [aws_security_group.cl_bastion_sg.id]
  subnet_id = element(aws_subnet.es_public_subnet.*.id,count.index)

  tags = {
    Name = "cl_bastion-${random_string.random.id}"
  }

}