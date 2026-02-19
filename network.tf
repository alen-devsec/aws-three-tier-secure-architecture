# Main VPC Configuration
resource "aws_vpc" "main_secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true

  tags = {
    Name = "Secure-Architecture-VPC"
  }
}

# Public Web Layer
resource "aws_subnet" "public_web" {
  vpc_id                  = aws_vpc.main_secure_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "us-east-1a"

  tags = { 
    Name = "Public-Web-Subnet" 
  }
}

# Private Database Layer (Isolated)
resource "aws_subnet" "private_db" {
  vpc_id            = aws_vpc.main_secure_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"

  tags = { 
    Name = "Private-DB-Subnet" 
  }
}
