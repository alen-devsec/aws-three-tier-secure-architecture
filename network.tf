# ============================================================================
# ENTERPRISE-GRADE AWS NETWORK INFRASTRUCTURE
# ============================================================================
# 
# This Terraform configuration creates a highly available, secure, and scalable
# network architecture following AWS best practices for production workloads.
#
# ARCHITECTURE OVERVIEW:
# ----------------------
# - Multi-AZ deployment across 3 Availability Zones for high availability
# - 3-tier subnet architecture: Public, Private, and Database subnets
# - Dedicated NAT Gateway per AZ (no single point of failure)
# - Comprehensive network segmentation for defense in depth
# - VPC Flow Logs for security auditing and compliance
# - DNS resolution enabled for service discovery
#
# SECURITY BENEFITS:
# ------------------
# 1. Network Isolation: Separate subnets for different tiers (web, app, db)
# 2. Defense in Depth: Multiple layers of network security controls
# 3. High Availability: Multi-AZ architecture ensures business continuity
# 4. Audit Trail: VPC Flow Logs capture all network traffic for forensics
# 5. Principle of Least Privilege: Private subnets have no direct internet access
# 6. Database Security: Database subnets isolated from internet traffic
#
# COMPLIANCE CONSIDERATIONS:
# --------------------------
# This architecture supports: PCI-DSS, HIPAA, SOC 2, ISO 27001, GDPR
# ============================================================================

# ============================================================================
# TERRAFORM CONFIGURATION
# ============================================================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend configuration for state management
  # Uncomment and configure for production use with remote state
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "network/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-lock"
  # }
}

# ============================================================================
# PROVIDER CONFIGURATION
# ============================================================================

provider "aws" {
  region = var.aws_region

  # Apply default tags to all resources for better resource management,
  # cost allocation, and compliance tracking
  default_tags {
    tags = {
      Environment     = var.environment
      ManagedBy       = "Terraform"
      Project         = var.project_name
      CostCenter      = var.cost_center
      SecurityLevel   = "High"
      ComplianceScope = "PCI-DSS-HIPAA-SOC2"
      Owner           = var.owner_email
      CreatedDate     = formatdate("YYYY-MM-DD", timestamp())
    }
  }
}

# ============================================================================
# DATA SOURCES
# ============================================================================

# Retrieve all available Availability Zones in the region
# This ensures the configuration is region-agnostic and automatically adapts
# to the AZs available in the selected region
data "aws_availability_zones" "available" {
  state = "available"

  # Filter out Local Zones and Wavelength Zones for standard deployment
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# Get current AWS account ID for IAM policy configurations
data "aws_caller_identity" "current" {}

# Get current AWS region for resource naming and tagging
data "aws_region" "current" {}

# ============================================================================
# LOCAL VARIABLES
# ============================================================================

locals {
  # Availability Zones: Select first 3 AZs for multi-AZ deployment
  # This provides fault tolerance and high availability across physically
  # separate data centers within the region
  azs = slice(data.aws_availability_zones.available.names, 0, 3)

  # Calculate the number of AZs (should be 3 for this configuration)
  az_count = length(local.azs)

  # Common resource naming convention for consistency
  # Format: {project}-{environment}-{resource-type}
  name_prefix = "${var.project_name}-${var.environment}"

  # Network CIDR calculations using cidrsubnet function for automatic IP allocation
  # This approach eliminates manual CIDR management and prevents IP overlap errors
  
  # Public Subnets: /20 blocks (4,096 IPs each) for internet-facing resources
  # These host: Load Balancers, NAT Gateways, Bastion Hosts, VPN endpoints
  public_subnet_cidrs = [
    cidrsubnet(var.vpc_cidr, 4, 0),  # Example: 10.0.0.0/20 in AZ-1
    cidrsubnet(var.vpc_cidr, 4, 1),  # Example: 10.0.16.0/20 in AZ-2
    cidrsubnet(var.vpc_cidr, 4, 2),  # Example: 10.0.32.0/20 in AZ-3
  ]

  # Private Subnets: /20 blocks (4,096 IPs each) for application workloads
  # These host: EC2 instances, ECS tasks, Lambda functions, internal services
  # No direct internet access - must route through NAT Gateway
  private_subnet_cidrs = [
    cidrsubnet(var.vpc_cidr, 4, 3),  # Example: 10.0.48.0/20 in AZ-1
    cidrsubnet(var.vpc_cidr, 4, 4),  # Example: 10.0.64.0/20 in AZ-2
    cidrsubnet(var.vpc_cidr, 4, 5),  # Example: 10.0.80.0/20 in AZ-3
  ]

  # Database Subnets: /20 blocks (4,096 IPs each) for data tier
  # These host: RDS, Aurora, ElastiCache, Redshift, DocumentDB
  # Completely isolated from internet - no internet gateway or NAT access
  database_subnet_cidrs = [
    cidrsubnet(var.vpc_cidr, 4, 6),  # Example: 10.0.96.0/20 in AZ-1
    cidrsubnet(var.vpc_cidr, 4, 7),  # Example: 10.0.112.0/20 in AZ-2
    cidrsubnet(var.vpc_cidr, 4, 8),  # Example: 10.0.128.0/20 in AZ-3
  ]

  # Merge default tags with resource-specific tags
  common_tags = merge(
    var.additional_tags,
    {
      NetworkArchitecture = "3-Tier-Multi-AZ"
      HighAvailability    = "Enabled"
      DisasterRecovery    = "Multi-AZ"
    }
  )
}

# ============================================================================
# VPC (VIRTUAL PRIVATE CLOUD)
# ============================================================================

# Create the VPC - The foundational network construct in AWS
# SECURITY BENEFITS:
# - Network isolation from other AWS accounts and VPCs
# - Complete control over IP addressing scheme
# - Private network space for secure communication
# - Foundation for implementing security groups and NACLs
resource "aws_vpc" "main" {
  cidr_block = var.vpc_cidr

  # Enable DNS hostnames for service discovery and easier management
  # This allows resources to have DNS names like: ec2-xxx.compute.amazonaws.com
  enable_dns_hostnames = true

  # Enable DNS resolution for VPC resources
  # Required for services like RDS, ElastiCache to resolve internal DNS names
  enable_dns_support = true

  # Enable IPv6 if required for future compatibility (optional)
  # assign_generated_ipv6_cidr_block = true

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-vpc"
      Description = "Main VPC for ${var.project_name} ${var.environment} environment"
      CIDR        = var.vpc_cidr
    }
  )
}

# ============================================================================
# INTERNET GATEWAY
# ============================================================================

# Internet Gateway provides internet connectivity for public subnets
# SECURITY BENEFITS:
# - Controlled entry/exit point for internet traffic
# - Only public subnets have routes to IGW
# - NAT Gateway uses IGW for outbound traffic from private subnets
# - Enables stateful firewall rules at subnet level
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-igw"
      Description = "Internet Gateway for public subnet internet access"
    }
  )
}

# ============================================================================
# ELASTIC IPS FOR NAT GATEWAYS
# ============================================================================

# Elastic IPs are static, public IPv4 addresses for NAT Gateways
# SECURITY BENEFITS:
# - Static IP addresses for allowlisting in external firewalls
# - Predictable source IPs for outbound traffic from private subnets
# - Enables IP-based access control lists (ACLs) for third-party APIs
# - Facilitates security audit logging and monitoring
#
# NOTE: One EIP per NAT Gateway ensures high availability - if one NAT Gateway
# fails, traffic from that AZ's private subnets fails over to another AZ
resource "aws_eip" "nat" {
  count = local.az_count

  # domain = "vpc" is used instead of deprecated vpc = true
  domain = "vpc"

  # Ensure EIP is not created until IGW is available
  # This prevents race conditions during infrastructure creation
  depends_on = [aws_internet_gateway.main]

  tags = merge(
    local.common_tags,
    {
      Name              = "${local.name_prefix}-eip-nat-${local.azs[count.index]}"
      AvailabilityZone  = local.azs[count.index]
      Purpose           = "NAT-Gateway"
      Description       = "Elastic IP for NAT Gateway in ${local.azs[count.index]}"
    }
  )
}

# ============================================================================
# NAT GATEWAYS (ONE PER AVAILABILITY ZONE)
# ============================================================================

# NAT Gateways enable private subnet resources to initiate outbound internet
# connections while preventing inbound connections from the internet
#
# HIGH AVAILABILITY ARCHITECTURE:
# - One NAT Gateway per AZ (3 total) eliminates single point of failure
# - If an AZ fails, only that AZ's private subnets lose internet access
# - Cross-AZ failover is not automatic but can be implemented with routing
#
# SECURITY BENEFITS:
# - Private subnets maintain no direct internet access
# - Stateful connection tracking (return traffic only for initiated connections)
# - Static source IP (EIP) for external API allowlisting
# - Network Address Translation hides internal IP addresses
# - Reduces attack surface by preventing inbound connections
#
# COST CONSIDERATION:
# - Each NAT Gateway costs ~$32/month + data transfer charges
# - Total cost: ~$96/month for 3 NAT Gateways (high availability premium)
# - Alternative: Single NAT Gateway saves costs but creates single point of failure
resource "aws_nat_gateway" "main" {
  count = local.az_count

  # Allocate the Elastic IP to this NAT Gateway
  allocation_id = aws_eip.nat[count.index].id

  # NAT Gateway must be in a public subnet to access Internet Gateway
  subnet_id = aws_subnet.public[count.index].id

  # Ensure proper creation order: IGW must exist before NAT Gateway
  depends_on = [aws_internet_gateway.main]

  tags = merge(
    local.common_tags,
    {
      Name             = "${local.name_prefix}-nat-${local.azs[count.index]}"
      AvailabilityZone = local.azs[count.index]
      ElasticIP        = aws_eip.nat[count.index].public_ip
      Description      = "NAT Gateway for private subnets in ${local.azs[count.index]}"
    }
  )
}

# ============================================================================
# PUBLIC SUBNETS (INTERNET-FACING TIER)
# ============================================================================

# Public subnets host internet-facing resources that require direct internet access
# TYPICAL WORKLOADS: Load Balancers, Bastion Hosts, NAT Gateways, VPN endpoints
#
# SECURITY CONSIDERATIONS:
# - Only expose resources that absolutely require public internet access
# - Use security groups to restrict inbound traffic to specific ports
# - Enable DDoS protection with AWS Shield and WAF
# - Deploy Web Application Firewalls (WAF) in front of public endpoints
# - Use bastion hosts with MFA for administrative SSH/RDP access
resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.public_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  # Auto-assign public IP addresses to instances launched in public subnets
  # This is required for resources that need direct internet connectivity
  # Can be overridden at instance launch time
  map_public_ip_on_launch = true

  tags = merge(
    local.common_tags,
    {
      Name             = "${local.name_prefix}-public-${local.azs[count.index]}"
      Type             = "Public"
      Tier             = "Internet-Facing"
      AvailabilityZone = local.azs[count.index]
      CIDR             = local.public_subnet_cidrs[count.index]
      # Kubernetes ELB discovery tag (if using EKS)
      "kubernetes.io/role/elb" = "1"
      Description      = "Public subnet for internet-facing resources in ${local.azs[count.index]}"
    }
  )
}

# ============================================================================
# PRIVATE SUBNETS (APPLICATION TIER)
# ============================================================================

# Private subnets host application workloads without direct internet access
# TYPICAL WORKLOADS: EC2 instances, ECS tasks, Lambda functions, internal APIs
#
# SECURITY BENEFITS:
# - No direct internet access - must route through NAT Gateway for outbound
# - Not reachable from internet - requires Load Balancer or bastion host
# - Ideal for application servers, microservices, and business logic
# - Reduced attack surface - no public IP addresses assigned
# - Internal-only communication by default
#
# OUTBOUND CONNECTIVITY:
# - Internet access via NAT Gateway in same AZ (for software updates, API calls)
# - Each private subnet routes to its AZ's NAT Gateway for high availability
resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  # Do NOT auto-assign public IPs in private subnets
  # This enforces the security boundary between public and private tiers
  map_public_ip_on_launch = false

  tags = merge(
    local.common_tags,
    {
      Name             = "${local.name_prefix}-private-${local.azs[count.index]}"
      Type             = "Private"
      Tier             = "Application"
      AvailabilityZone = local.azs[count.index]
      CIDR             = local.private_subnet_cidrs[count.index]
      # Kubernetes internal ELB discovery tag (if using EKS)
      "kubernetes.io/role/internal-elb" = "1"
      Description      = "Private subnet for application workloads in ${local.azs[count.index]}"
    }
  )
}

# ============================================================================
# DATABASE SUBNETS (DATA TIER)
# ============================================================================

# Database subnets provide maximum isolation for data tier resources
# TYPICAL WORKLOADS: RDS, Aurora, ElastiCache, Redshift, DocumentDB, Neptune
#
# SECURITY BENEFITS:
# - Complete isolation from internet (no IGW or NAT Gateway routes)
# - Only accessible from private subnets via security groups
# - Cannot initiate outbound internet connections
# - Ideal for PCI-DSS, HIPAA, and SOC 2 compliance
# - Minimizes data exfiltration risks
# - Implements principle of least privilege at network layer
#
# DATABASE SUBNET GROUP:
# - RDS requires a DB Subnet Group spanning at least 2 AZs
# - This configuration provides 3 AZs for maximum availability
# - Multi-AZ RDS deployments automatically use these subnets
resource "aws_subnet" "database" {
  count = local.az_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.database_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  # Database subnets NEVER get public IPs
  map_public_ip_on_launch = false

  tags = merge(
    local.common_tags,
    {
      Name             = "${local.name_prefix}-database-${local.azs[count.index]}"
      Type             = "Database"
      Tier             = "Data"
      AvailabilityZone = local.azs[count.index]
      CIDR             = local.database_subnet_cidrs[count.index]
      Description      = "Database subnet for data tier workloads in ${local.azs[count.index]}"
      DataClassification = "Sensitive"
    }
  )
}

# RDS Database Subnet Group - Required for RDS instance creation
# This groups database subnets across multiple AZs for RDS Multi-AZ deployments
resource "aws_db_subnet_group" "main" {
  name        = "${local.name_prefix}-db-subnet-group"
  description = "Database subnet group for RDS instances spanning 3 AZs"
  subnet_ids  = aws_subnet.database[*].id

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-db-subnet-group"
      Description = "Subnet group for Multi-AZ RDS deployments"
    }
  )
}

# ============================================================================
# ROUTE TABLES - PUBLIC SUBNETS
# ============================================================================

# Public subnet route table directs internet traffic to Internet Gateway
# SECURITY IMPLICATION: This route table makes subnets "public" by definition
# Any subnet associated with this route table can send/receive internet traffic
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-public-rt"
      Type        = "Public"
      Description = "Route table for public subnets with internet gateway route"
    }
  )
}

# Default route to Internet Gateway for public subnet outbound internet access
# DESTINATION: 0.0.0.0/0 (all internet traffic)
# TARGET: Internet Gateway
# This enables bidirectional internet connectivity for public subnet resources
resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

# Associate public subnets with the public route table
# This establishes the routing rules for all resources in public subnets
resource "aws_route_table_association" "public" {
  count = local.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ============================================================================
# ROUTE TABLES - PRIVATE SUBNETS (ONE PER AZ)
# ============================================================================

# Each private subnet gets its own route table for AZ-specific NAT Gateway routing
# WHY SEPARATE ROUTE TABLES?
# - High availability: Each AZ's private subnets use their own AZ's NAT Gateway
# - Fault isolation: NAT Gateway failure only affects its own AZ
# - Cost optimization: No cross-AZ data transfer charges for NAT traffic
# - Performance: Lower latency by keeping traffic within same AZ
#
# ALTERNATIVE APPROACH (NOT RECOMMENDED):
# - Single route table with one NAT Gateway: Lower cost but single point of failure
# - Cross-AZ failover: More complex, incurs data transfer charges
resource "aws_route_table" "private" {
  count = local.az_count

  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name             = "${local.name_prefix}-private-rt-${local.azs[count.index]}"
      Type             = "Private"
      AvailabilityZone = local.azs[count.index]
      NATGateway       = aws_nat_gateway.main[count.index].id
      Description      = "Route table for private subnets in ${local.azs[count.index]} using NAT Gateway"
    }
  )
}

# Default route for private subnets to NAT Gateway (outbound internet only)
# DESTINATION: 0.0.0.0/0 (all internet traffic)
# TARGET: NAT Gateway in same AZ
# SECURITY: This is OUTBOUND ONLY - no inbound connections possible from internet
resource "aws_route" "private_nat" {
  count = local.az_count

  route_table_id         = aws_route_table.private[count.index].id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.main[count.index].id
}

# Associate private subnets with their AZ-specific route tables
# Each private subnet in an AZ uses that AZ's NAT Gateway
resource "aws_route_table_association" "private" {
  count = local.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# ============================================================================
# ROUTE TABLES - DATABASE SUBNETS
# ============================================================================

# Database subnet route table with NO internet routes
# SECURITY ENFORCEMENT: No routes to Internet Gateway or NAT Gateway
# Database resources can only communicate within VPC
#
# INTER-VPC COMMUNICATION OPTIONS:
# - VPC Peering: Connect to other VPCs
# - Transit Gateway: Hub-and-spoke VPC connectivity
# - PrivateLink: Access AWS services without internet
# - VPN: Secure connection to on-premises data centers
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.main.id

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-database-rt"
      Type        = "Database"
      Tier        = "Isolated"
      Internet    = "Disabled"
      Description = "Route table for database subnets - no internet access"
    }
  )
}

# Associate database subnets with the database route table
# All database subnets share the same route table since they don't need NAT
resource "aws_route_table_association" "database" {
  count = local.az_count

  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}

# ============================================================================
# VPC FLOW LOGS - S3 BUCKET FOR LOG STORAGE
# ============================================================================

# S3 bucket for storing VPC Flow Logs
# SECURITY & COMPLIANCE BENEFITS:
# - Network traffic audit trail for forensic investigation
# - Detect unusual traffic patterns and potential security threats
# - Compliance requirements: PCI-DSS 10.3, HIPAA §164.312(b)
# - Cost-effective long-term log retention
# - Analyze traffic with Amazon Athena or CloudWatch Logs Insights
#
# FLOW LOG DATA CAPTURED:
# - Source/destination IP addresses and ports
# - Protocol number
# - Number of packets and bytes
# - Action (ACCEPT or REJECT)
# - Log status
resource "aws_s3_bucket" "flow_logs" {
  bucket = "${local.name_prefix}-vpc-flow-logs-${data.aws_caller_identity.current.account_id}"

  # Prevent accidental deletion of flow logs bucket
  # Must be disabled before bucket can be destroyed
  force_destroy = false

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-vpc-flow-logs"
      Purpose     = "VPC-Flow-Logs-Storage"
      Compliance  = "PCI-DSS-HIPAA-SOC2"
      Description = "S3 bucket for VPC Flow Logs storage and analysis"
    }
  )
}

# Enable versioning for flow logs bucket to prevent data loss
# Protects against accidental deletion and supports compliance requirements
resource "aws_s3_bucket_versioning" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable server-side encryption for flow logs at rest
# SECURITY: Protects sensitive network traffic data using AES-256 encryption
# COMPLIANCE: Required for HIPAA, PCI-DSS, and most security frameworks
resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true  # Reduces KMS costs if using KMS encryption
  }
}

# Block all public access to flow logs bucket
# CRITICAL SECURITY CONTROL: Flow logs contain sensitive network information
resource "aws_s3_bucket_public_access_block" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy to transition old logs to cheaper storage classes
# COST OPTIMIZATION: Move logs to Glacier after 90 days, delete after 1 year
resource "aws_s3_bucket_lifecycle_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  rule {
    id     = "flow-logs-lifecycle"
    status = "Enabled"

    # Transition to Infrequent Access after 30 days
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # Transition to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Delete logs after 365 days (adjust based on compliance requirements)
    expiration {
      days = 365
    }
  }
}

# S3 bucket policy allowing VPC Flow Logs service to write logs
resource "aws_s3_bucket_policy" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.flow_logs.arn}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.flow_logs.arn
      },
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.flow_logs.arn,
          "${aws_s3_bucket.flow_logs.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ============================================================================
# VPC FLOW LOGS
# ============================================================================

# Enable VPC Flow Logs to capture all network traffic
# MONITORING CAPABILITIES:
# - Track all IP traffic going to/from network interfaces in VPC
# - Troubleshoot connectivity issues
# - Detect security threats and anomalous behavior
# - Monitor application performance
# - Ensure network access rules are working as expected
#
# USE CASES:
# - Diagnose overly restrictive security group rules
# - Monitor traffic reaching your instances
# - Determine direction of traffic to/from network interfaces
# - Security forensics after incident
# - Compliance audit trail
resource "aws_flow_log" "main" {
  vpc_id = aws_vpc.main.id

  # Log destination: S3 bucket
  # ALTERNATIVE: CloudWatch Logs (more expensive but better for real-time analysis)
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.flow_logs.arn

  # Traffic type to capture:
  # - ACCEPT: Only accepted traffic
  # - REJECT: Only rejected traffic
  # - ALL: Both accepted and rejected traffic (RECOMMENDED for security)
  traffic_type = "ALL"

  # Maximum aggregation interval: 1 minute (faster) or 10 minutes (cheaper)
  # 1 minute provides near real-time visibility, 10 minutes reduces cost
  max_aggregation_interval = 600  # 10 minutes

  # Custom log format for additional fields
  # Available fields: action, bytes, dstaddr, dstport, end, interface-id,
  # log-status, packets, pkt-dstaddr, pkt-srcaddr, protocol, srcaddr, srcport,
  # start, tcp-flags, type, version, vpc-id, subnet-id, instance-id, account-id, flow-direction
  log_format = "$${account-id} $${action} $${bytes} $${dstaddr} $${dstport} $${end} $${flow-direction} $${instance-id} $${interface-id} $${log-status} $${packets} $${pkt-dstaddr} $${pkt-srcaddr} $${protocol} $${srcaddr} $${srcport} $${start} $${subnet-id} $${tcp-flags} $${type} $${version} $${vpc-id}"

  tags = merge(
    local.common_tags,
    {
      Name        = "${local.name_prefix}-vpc-flow-log"
      Description = "VPC Flow Logs capturing all network traffic for security monitoring"
      TrafficType = "ALL"
      Destination = "S3"
    }
  )
}

# ============================================================================
# OUTPUTS
# ============================================================================

# VPC Information
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "vpc_arn" {
  description = "The ARN of the VPC"
  value       = aws_vpc.main.arn
}

# Availability Zones
output "availability_zones" {
  description = "List of Availability Zones used in this deployment"
  value       = local.azs
}

# Internet Gateway
output "internet_gateway_id" {
  description = "The ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

# Public Subnet Information
output "public_subnet_ids" {
  description = "List of IDs of public subnets"
  value       = aws_subnet.public[*].id
}

output "public_subnet_cidrs" {
  description = "List of CIDR blocks of public subnets"
  value       = aws_subnet.public[*].cidr_block
}

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

# Private Subnet Information
output "private_subnet_ids" {
  description = "List of IDs of private subnets"
  value       = aws_subnet.private[*].id
}

output "private_subnet_cidrs" {
  description = "List of CIDR blocks of private subnets"
  value       = aws_subnet.private[*].cidr_block
}

output "private_route_table_ids" {
  description = "List of IDs of private route tables (one per AZ)"
  value       = aws_route_table.private[*].id
}

# Database Subnet Information
output "database_subnet_ids" {
  description = "List of IDs of database subnets"
  value       = aws_subnet.database[*].id
}

output "database_subnet_cidrs" {
  description = "List of CIDR blocks of database subnets"
  value       = aws_subnet.database[*].cidr_block
}

output "database_subnet_group_name" {
  description = "Name of the database subnet group for RDS"
  value       = aws_db_subnet_group.main.name
}

output "database_route_table_id" {
  description = "ID of the database route table"
  value       = aws_route_table.database.id
}

# NAT Gateway Information
output "nat_gateway_ids" {
  description = "List of NAT Gateway IDs (one per AZ)"
  value       = aws_nat_gateway.main[*].id
}

output "nat_gateway_public_ips" {
  description = "List of Elastic IPs associated with NAT Gateways"
  value       = aws_eip.nat[*].public_ip
}

output "elastic_ip_ids" {
  description = "List of Elastic IP allocation IDs"
  value       = aws_eip.nat[*].id
}

# VPC Flow Logs Information
output "flow_logs_s3_bucket_name" {
  description = "Name of S3 bucket storing VPC Flow Logs"
  value       = aws_s3_bucket.flow_logs.id
}

output "flow_logs_s3_bucket_arn" {
  description = "ARN of S3 bucket storing VPC Flow Logs"
  value       = aws_s3_bucket.flow_logs.arn
}

output "flow_log_id" {
  description = "ID of the VPC Flow Log"
  value       = aws_flow_log.main.id
}

# Summary Output for Easy Reference
output "network_summary" {
  description = "Summary of network architecture"
  value = {
    vpc_id              = aws_vpc.main.id
    vpc_cidr            = aws_vpc.main.cidr_block
    availability_zones  = local.azs
    public_subnets      = length(aws_subnet.public)
    private_subnets     = length(aws_subnet.private)
    database_subnets    = length(aws_subnet.database)
    nat_gateways        = length(aws_nat_gateway.main)
    flow_logs_enabled   = true
    multi_az            = true
  }
}
