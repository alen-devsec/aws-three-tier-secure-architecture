# Advanced VPC Configuration
resource "aws_vpc" "main_secure_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = merge(var.project_tags, {
    Name = "Enterprise-Secure-VPC"
    Layer = "Networking"
  })
}

# Fetch available Availability Zones
data "aws_availability_zones" "available" {
  state = "available"
}

# Internet Gateway for External Traffic
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main_secure_vpc.id
  tags   = merge(var.project_tags, { Name = "Main-IGW" })
}

# Multi-AZ Public Subnets (For Load Balancers/Web)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main_secure_vpc.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = merge(var.project_tags, { Name = "Public-Subnet-${count.index + 1}" })
}

# Multi-AZ Private Subnets (For App/DB Isolation)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main_secure_vpc.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(var.project_tags, { Name = "Private-Subnet-${count.index + 1}" })
}

# Public Route Table & Associations
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.main_secure_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = { Name = "Public-Route-Table" }
}

resource "aws_route_table_association" "public_assoc" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public_rt.id
}
