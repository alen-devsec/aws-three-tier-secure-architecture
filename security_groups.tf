locals {
  web_inbound_ports = [80, 443]
}

resource "aws_security_group" "web_sg" {
  name        = "Enterprise-Web-SG"
  description = "Security group for web layer with dynamic ingress rules"
  vpc_id      = aws_vpc.main_secure_vpc.id

  dynamic "ingress" {
    for_each = local.web_inbound_ports
    content {
      description = "Allow port ${ingress.value}"
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.project_tags
}

resource "aws_security_group" "db_sg" {
  name        = "Enterprise-DB-SG"
  description = "Restrictive security group for database layer"
  vpc_id      = aws_vpc.main_secure_vpc.id

  ingress {
    description     = "Allow MySQL/Aurora from Web SG only"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = var.project_tags
}
