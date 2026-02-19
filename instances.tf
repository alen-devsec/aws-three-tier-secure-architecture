# Fetch the latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Secure Web Server Instance
resource "aws_instance" "web_server" {
  ami           = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.public_web.id
  
  # Security group attachment
  vpc_security_group_ids = [aws_security_group.web_sg.id]

  # SECURITY BEST PRACTICE: Require IMDSv2
  metadata_options {
    http_tokens = "required"
  }

  # SECURITY BEST PRACTICE: Encrypted Root Volume
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
  }

  tags = merge(var.project_tags, {
    Name = "Secure-Web-Server"
  })
}
