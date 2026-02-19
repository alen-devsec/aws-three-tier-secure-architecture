# Web Server Security Group (Allow HTTP/HTTPS)
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Allow inbound web traffic"
  vpc_id      = aws_vpc.main_secure_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Database Security Group (Restrictive Access)
resource "aws_security_group" "db_sg" {
  name        = "db-layer-sg"
  description = "Allow traffic ONLY from Web Layer"
  vpc_id      = aws_vpc.main_secure_vpc.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.web_sg.id] # Strict source check
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
