# ============================================================================
# TERRAFORM OUTPUTS - ENTERPRISE AWS INFRASTRUCTURE
# ============================================================================
#
# This file defines all output values for the enterprise-grade AWS infrastructure.
# Outputs provide visibility into deployed resources and enable integration with
# external systems, CI/CD pipelines, and monitoring tools.
#
# PURPOSE:
# --------
# - Infrastructure Documentation: Export resource identifiers for reference
# - Integration: Enable connections to other Terraform modules/workspaces
# - CI/CD Pipelines: Provide deployment information to automation
# - Monitoring: Feed resource IDs to monitoring and alerting systems
# - Troubleshooting: Quick reference for infrastructure components
# - Client Reporting: Professional summary of deployed resources
#
# USAGE:
# ------
# After deployment, view outputs with:
#   terraform output                    # All outputs
#   terraform output vpc_id             # Specific output
#   terraform output -json              # JSON format for automation
#   terraform output -json > infra.json # Export to file
#
# INTEGRATION EXAMPLE:
# -------------------
# Reference outputs in another Terraform configuration:
#   data "terraform_remote_state" "network" {
#     backend = "s3"
#     config = {
#       bucket = "terraform-state"
#       key    = "network/terraform.tfstate"
#       region = "us-east-1"
#     }
#   }
#   
#   vpc_id = data.terraform_remote_state.network.outputs.vpc_id
#
# ============================================================================

# ============================================================================
# SECTION 1: NETWORK INFRASTRUCTURE OUTPUTS
# ============================================================================
#
# This section exports core networking components including VPC, subnets,
# route tables, NAT gateways, and internet gateway information.
#
# Use these outputs to:
# - Configure application deployment scripts
# - Set up VPN connections
# - Establish VPC peering
# - Configure DNS and routing
# - Integrate with monitoring systems
# ============================================================================

# ----------------------------------------------------------------------------
# VPC (Virtual Private Cloud) Information
# ----------------------------------------------------------------------------

output "vpc_id" {
  description = <<-EOT
    The ID of the Virtual Private Cloud (VPC).
    
    This is the primary network container for all AWS resources in this deployment.
    Use this VPC ID when:
    - Creating additional resources that need to be in this VPC
    - Setting up VPC peering connections
    - Configuring VPN connections
    - Establishing Direct Connect virtual interfaces
    - Creating VPC endpoints for AWS services
    
    Example usage:
    - EC2 Instance Launch: --subnet-id subnet-xxx --vpc-id <this_vpc_id>
    - VPC Peering: Create peering connection between VPCs
    - Security Group: All security groups must reference this VPC
    
    Format: vpc-xxxxxxxxxxxxxxxxx (17 characters after vpc-)
  EOT
  value       = aws_vpc.main.id
}

output "vpc_arn" {
  description = <<-EOT
    Amazon Resource Name (ARN) of the VPC.
    
    The ARN uniquely identifies this VPC across all AWS services and accounts.
    Required for:
    - IAM policy resource specifications
    - CloudWatch Events rules
    - AWS Config rules
    - Cross-account resource sharing
    - Service Control Policies (SCPs)
    
    Format: arn:aws:ec2:region:account-id:vpc/vpc-id
  EOT
  value       = aws_vpc.main.arn
}

output "vpc_cidr_block" {
  description = <<-EOT
    The IPv4 CIDR block assigned to the VPC.
    
    This defines the IP address range available for all subnets and resources
    within this VPC. Default: 10.0.0.0/16 (65,536 IP addresses).
    
    Important for:
    - Network planning and IP allocation
    - Security group and NACL rule configuration
    - VPC peering CIDR conflict detection
    - VPN and Direct Connect routing
    - Calculating subnet CIDR blocks
    
    Example: 10.0.0.0/16
    Available IPs: 65,536 (minus 5 reserved per subnet)
  EOT
  value       = aws_vpc.main.cidr_block
}

output "vpc_main_route_table_id" {
  description = <<-EOT
    The ID of the main (default) route table for the VPC.
    
    The main route table is automatically created with the VPC and contains
    the local route for VPC internal communication. Custom route tables are
    created for public, private, and database subnets.
    
    Note: It's a best practice to leave the main route table unused and
    create explicit route tables for all subnets.
  EOT
  value       = aws_vpc.main.main_route_table_id
}

output "vpc_enable_dns_support" {
  description = <<-EOT
    Whether DNS resolution is enabled for the VPC.
    
    When enabled (true), instances can resolve AWS service endpoints and
    custom DNS names within the VPC. Required for:
    - RDS database DNS names
    - ElastiCache cluster endpoints
    - Private Route 53 hosted zones
    - VPC endpoints (S3, DynamoDB, etc.)
    
    Value: true (enabled) or false (disabled)
  EOT
  value       = aws_vpc.main.enable_dns_support
}

output "vpc_enable_dns_hostnames" {
  description = <<-EOT
    Whether DNS hostnames are enabled for the VPC.
    
    When enabled (true), instances with public IP addresses receive public
    DNS hostnames (ec2-xx-xx-xx-xx.compute.amazonaws.com).
    
    Required for:
    - Public-facing instances that need DNS names
    - ELB DNS name resolution
    - Some AWS services (RDS, ElastiCache)
  EOT
  value       = aws_vpc.main.enable_dns_hostnames
}

# ----------------------------------------------------------------------------
# Availability Zones
# ----------------------------------------------------------------------------

output "availability_zones" {
  description = <<-EOT
    List of Availability Zones used in this deployment.
    
    This infrastructure is deployed across multiple AZs for high availability
    and fault tolerance. Each AZ is a physically separate data center with
    independent power, networking, and cooling.
    
    High Availability Strategy:
    - Resources distributed across all listed AZs
    - Automatic failover if one AZ experiences issues
    - Load balancing across zones
    
    Typical configuration: 3 AZs (e.g., us-east-1a, us-east-1b, us-east-1c)
    
    Use for:
    - Understanding infrastructure distribution
    - Disaster recovery planning
    - Capacity planning across zones
  EOT
  value       = local.azs
}

output "availability_zone_count" {
  description = <<-EOT
    Number of Availability Zones used in this deployment.
    
    Indicates the level of redundancy and fault tolerance.
    - 1 AZ: No redundancy (not recommended for production)
    - 2 AZs: Basic redundancy (minimum for production)
    - 3 AZs: High availability (recommended)
    - 4+ AZs: Maximum availability (enterprise)
  EOT
  value       = length(local.azs)
}

# ----------------------------------------------------------------------------
# Internet Gateway
# ----------------------------------------------------------------------------

output "internet_gateway_id" {
  description = <<-EOT
    The ID of the Internet Gateway attached to the VPC.
    
    The Internet Gateway enables communication between resources in public
    subnets and the internet. It provides:
    - Outbound internet access for instances with public IPs
    - Inbound internet access to public-facing resources
    - NAT functionality for elastic IPs
    
    Security Note:
    - Only public subnets have routes to this gateway
    - Private subnets use NAT Gateways for outbound access
    - Database subnets have no internet access
    
    Use for:
    - Verifying internet connectivity configuration
    - Troubleshooting routing issues
    - Creating additional route table entries
  EOT
  value       = aws_internet_gateway.main.id
}

output "internet_gateway_arn" {
  description = <<-EOT
    Amazon Resource Name (ARN) of the Internet Gateway.
    
    Required for IAM policies that control internet gateway operations
    and CloudWatch Events monitoring.
  EOT
  value       = aws_internet_gateway.main.arn
}

# ----------------------------------------------------------------------------
# Public Subnets (Internet-facing tier)
# ----------------------------------------------------------------------------

output "public_subnet_ids" {
  description = <<-EOT
    List of IDs for all public subnets (internet-facing tier).
    
    Public subnets are used for resources that require direct internet access:
    - Application Load Balancers (ALB)
    - Network Load Balancers (NLB)
    - NAT Gateways
    - Bastion hosts (jump boxes)
    - VPN endpoints
    
    Characteristics:
    - Route to Internet Gateway (0.0.0.0/0 → igw-xxx)
    - Auto-assign public IP addresses (optional)
    - Network ACLs allow HTTP/HTTPS from internet
    
    Subnet Count: ${length(aws_subnet.public)}
    Distribution: One subnet per Availability Zone
    
    Use for:
    - Deploying internet-facing load balancers
    - Launching bastion hosts
    - Configuring public-facing services
    
    Security Recommendation:
    - Minimize resources in public subnets
    - Use security groups for strict access control
    - Enable VPC Flow Logs for traffic monitoring
  EOT
  value       = aws_subnet.public[*].id
}

output "public_subnet_arns" {
  description = <<-EOT
    List of ARNs for all public subnets.
    
    Amazon Resource Names for public subnets, required for:
    - IAM policy resource specifications
    - AWS Config compliance rules
    - CloudWatch Events and EventBridge rules
    - Resource-level permissions
  EOT
  value       = aws_subnet.public[*].arn
}

output "public_subnet_cidr_blocks" {
  description = <<-EOT
    List of CIDR blocks for all public subnets.
    
    IPv4 address ranges assigned to each public subnet.
    Default configuration: /20 subnets (4,096 IP addresses each)
    
    Example:
    - us-east-1a: 10.0.0.0/20   (10.0.0.0 - 10.0.15.255)
    - us-east-1b: 10.0.16.0/20  (10.0.16.0 - 10.0.31.255)
    - us-east-1c: 10.0.32.0/20  (10.0.32.0 - 10.0.47.255)
    
    Reserved IPs per subnet: 5 (AWS reserved)
    - .0: Network address
    - .1: VPC router
    - .2: DNS server
    - .3: Future use
    - .255: Broadcast address
    
    Usable IPs per subnet: 4,091
    
    Use for:
    - Network planning and documentation
    - Security group rule configuration
    - NACL rule configuration
    - IP address allocation planning
  EOT
  value       = aws_subnet.public[*].cidr_block
}

output "public_subnet_availability_zones" {
  description = <<-EOT
    Availability Zones where public subnets are deployed.
    
    Maps each public subnet to its physical location (AZ).
    Ensures load balancers and NAT gateways are distributed
    across multiple data centers for high availability.
  EOT
  value       = aws_subnet.public[*].availability_zone
}

output "public_route_table_id" {
  description = <<-EOT
    Route table ID for public subnets.
    
    This route table contains:
    - Local route: VPC CIDR → local (automatic)
    - Internet route: 0.0.0.0/0 → Internet Gateway
    
    All public subnets share this route table, enabling:
    - Outbound internet access for instances with public IPs
    - Inbound internet access through Internet Gateway
    - Direct communication with other VPC resources
    
    Route Table Rules:
    | Destination    | Target              | Purpose                    |
    |---------------|---------------------|----------------------------|
    | 10.0.0.0/16   | local               | VPC internal communication |
    | 0.0.0.0/0     | igw-xxxxxxxxxx      | Internet access            |
    
    Use for:
    - Verifying internet routing configuration
    - Adding custom routes (VPN, peering)
    - Troubleshooting connectivity issues
  EOT
  value       = aws_route_table.public.id
}

output "public_route_table_arn" {
  description = "ARN of the public subnet route table for IAM policies and monitoring"
  value       = aws_route_table.public.arn
}

# ----------------------------------------------------------------------------
# Private Subnets (Application tier)
# ----------------------------------------------------------------------------

output "private_subnet_ids" {
  description = <<-EOT
    List of IDs for all private subnets (application tier).
    
    Private subnets host the core application workloads without direct
    internet exposure. This is where most of your infrastructure runs:
    
    Typical Workloads:
    - EC2 application servers (web tier, app tier)
    - ECS containers and EKS pods
    - Lambda functions (VPC-attached)
    - ElastiCache clusters
    - Internal microservices
    - Batch processing instances
    
    Security Characteristics:
    - NO direct internet access (no route to Internet Gateway)
    - Outbound internet via NAT Gateway (for updates, API calls)
    - No public IP addresses assigned
    - Protected from direct internet attacks
    - Traffic only from ALB or other internal sources
    
    Subnet Count: ${length(aws_subnet.private)}
    Distribution: One subnet per Availability Zone
    CIDR Size: /20 (4,096 IPs per subnet)
    
    High Availability:
    - Each AZ has its own private subnet
    - Auto Scaling distributes instances across AZs
    - Automatic failover if one AZ fails
    
    Use for:
    - Deploying application EC2 instances
    - Launching ECS tasks and EKS pods
    - Configuring Auto Scaling Groups
    - Setting up internal load balancers
    
    Security Best Practices:
    - Keep application logic in private subnets
    - Use security groups for inter-tier communication
    - Enable VPC Flow Logs for traffic analysis
    - Implement least privilege access controls
  EOT
  value       = aws_subnet.private[*].id
}

output "private_subnet_arns" {
  description = <<-EOT
    List of ARNs for all private subnets.
    
    Required for IAM policies, AWS Config rules, and resource-level permissions.
  EOT
  value       = aws_subnet.private[*].arn
}

output "private_subnet_cidr_blocks" {
  description = <<-EOT
    List of CIDR blocks for all private subnets.
    
    IPv4 address ranges for application tier subnets.
    
    Example allocation:
    - us-east-1a: 10.0.48.0/20  (10.0.48.0 - 10.0.63.255)
    - us-east-1b: 10.0.64.0/20  (10.0.64.0 - 10.0.79.255)
    - us-east-1c: 10.0.80.0/20  (10.0.80.0 - 10.0.95.255)
    
    Usable IPs per subnet: 4,091 (4,096 minus 5 AWS reserved)
    
    Capacity Planning:
    - Typical EC2 instance: 1 IP
    - ECS task (awsvpc mode): 1 IP per task
    - EKS pod: 1 IP per pod
    - Lambda function: Dynamic (from pool)
    
    With 4,091 IPs per subnet across 3 AZs, you can support:
    - ~12,000 concurrent EC2 instances
    - ~12,000 concurrent ECS tasks
    - ~12,000 concurrent EKS pods
    
    Use for:
    - Capacity planning
    - IP address management (IPAM)
    - Security group rule configuration
  EOT
  value       = aws_subnet.private[*].cidr_block
}

output "private_subnet_availability_zones" {
  description = <<-EOT
    Availability Zones where private subnets are deployed.
    
    Ensures application instances are distributed across multiple
    data centers for fault tolerance and high availability.
  EOT
  value       = aws_subnet.private[*].availability_zone
}

output "private_route_table_ids" {
  description = <<-EOT
    List of route table IDs for private subnets (one per AZ).
    
    Each Availability Zone has its own route table for high availability.
    This ensures if one NAT Gateway fails, only that AZ's traffic is affected.
    
    Route Table Configuration (per AZ):
    | Destination    | Target              | Purpose                    |
    |---------------|---------------------|----------------------------|
    | 10.0.0.0/16   | local               | VPC internal communication |
    | 0.0.0.0/0     | nat-xxxxxxxxxx      | Internet via NAT Gateway   |
    
    High Availability Design:
    - AZ-1: Private subnet → NAT Gateway in AZ-1 → Internet
    - AZ-2: Private subnet → NAT Gateway in AZ-2 → Internet
    - AZ-3: Private subnet → NAT Gateway in AZ-3 → Internet
    
    Benefits:
    - No single point of failure
    - Reduced cross-AZ data transfer costs
    - Lower latency (traffic stays in same AZ)
    
    Count: ${length(aws_route_table.private)}
  EOT
  value       = aws_route_table.private[*].id
}

output "private_route_table_arns" {
  description = "ARNs of private subnet route tables for IAM and monitoring"
  value       = aws_route_table.private[*].arn
}

# ----------------------------------------------------------------------------
# Database Subnets (Data tier)
# ----------------------------------------------------------------------------

output "database_subnet_ids" {
  description = <<-EOT
    List of IDs for all database subnets (data tier).
    
    Database subnets provide the highest level of isolation for data storage:
    
    Supported Database Services:
    - Amazon RDS (MySQL, PostgreSQL, Oracle, SQL Server, MariaDB)
    - Amazon Aurora (MySQL-compatible, PostgreSQL-compatible)
    - Amazon ElastiCache (Redis, Memcached)
    - Amazon Redshift (Data warehouse)
    - Amazon DocumentDB (MongoDB-compatible)
    - Amazon Neptune (Graph database)
    - Self-managed databases on EC2
    
    Security Characteristics:
    - MAXIMUM ISOLATION: No internet access (inbound or outbound)
    - No route to Internet Gateway
    - No route to NAT Gateway
    - Only accessible from application tier via security groups
    - Network ACLs restrict traffic to database ports only
    
    Subnet Count: ${length(aws_subnet.database)}
    Distribution: One subnet per Availability Zone
    CIDR Size: /20 (4,096 IPs per subnet)
    
    Multi-AZ Deployment:
    - Primary database in one AZ
    - Standby replica in different AZ
    - Automatic failover on primary failure
    - Read replicas can span multiple AZs
    
    Compliance Benefits:
    - PCI-DSS: Database isolated from DMZ (Requirement 1.3.6)
    - HIPAA: ePHI database access controls (§164.312(a))
    - SOC 2: Logical access controls (CC6.1)
    - ISO 27001: Network segregation (A.13.1.3)
    
    Use for:
    - Creating RDS DB Subnet Groups
    - Launching ElastiCache clusters
    - Deploying Redshift clusters
    - Configuring database security groups
    
    Security Best Practices:
    - NEVER allow direct internet access
    - Enforce SSL/TLS for all database connections
    - Enable encryption at rest (KMS)
    - Enable encryption in transit
    - Use IAM database authentication where possible
    - Implement least privilege database user permissions
    - Enable database audit logging
    - Regular security patching
  EOT
  value       = aws_subnet.database[*].id
}

output "database_subnet_arns" {
  description = <<-EOT
    List of ARNs for all database subnets.
    
    Required for IAM policies governing database subnet operations
    and compliance monitoring tools.
  EOT
  value       = aws_subnet.database[*].arn
}

output "database_subnet_cidr_blocks" {
  description = <<-EOT
    List of CIDR blocks for all database subnets.
    
    IPv4 address ranges for data tier subnets.
    
    Example allocation:
    - us-east-1a: 10.0.96.0/20   (10.0.96.0 - 10.0.111.255)
    - us-east-1b: 10.0.112.0/20  (10.0.112.0 - 10.0.127.255)
    - us-east-1c: 10.0.128.0/20  (10.0.128.0 - 10.0.143.255)
    
    Usable IPs per subnet: 4,091
    
    Database IP Requirements:
    - RDS instance: 1 IP (primary) + 1 IP (standby in Multi-AZ)
    - Aurora cluster: 1 IP per instance (writer + readers)
    - ElastiCache: 1 IP per node
    - Redshift: 1 IP per node
    
    With 4,091 IPs per subnet, capacity is more than sufficient
    for most database deployments.
  EOT
  value       = aws_subnet.database[*].cidr_block
}

output "database_subnet_availability_zones" {
  description = <<-EOT
    Availability Zones where database subnets are deployed.
    
    Enables Multi-AZ database deployments for automatic failover
    and disaster recovery.
  EOT
  value       = aws_subnet.database[*].availability_zone
}

output "database_subnet_group_name" {
  description = <<-EOT
    Name of the RDS DB Subnet Group.
    
    This subnet group is required when creating RDS database instances.
    It defines which subnets RDS can use for deployment.
    
    Contains: All database subnets across ${length(aws_subnet.database)} Availability Zones
    
    Use this when creating RDS instances:
      aws rds create-db-instance \
        --db-subnet-group-name <this_value> \
        --multi-az \
        --engine postgres
    
    Terraform example:
      resource "aws_db_instance" "main" {
        db_subnet_group_name = <this_output>
        # ... other configuration
      }
    
    Supports:
    - RDS MySQL, PostgreSQL, MariaDB, Oracle, SQL Server
    - Amazon Aurora MySQL-compatible
    - Amazon Aurora PostgreSQL-compatible
  EOT
  value       = aws_db_subnet_group.main.name
}

output "database_subnet_group_id" {
  description = "ID of the RDS DB Subnet Group"
  value       = aws_db_subnet_group.main.id
}

output "database_subnet_group_arn" {
  description = "ARN of the RDS DB Subnet Group for IAM policies"
  value       = aws_db_subnet_group.main.arn
}

output "database_route_table_id" {
  description = <<-EOT
    Route table ID for database subnets.
    
    This route table intentionally has NO route to internet.
    
    Route Table Rules:
    | Destination    | Target              | Purpose                    |
    |---------------|---------------------|----------------------------|
    | 10.0.0.0/16   | local               | VPC internal communication |
    
    Security Enforcement:
    - No Internet Gateway route (maximum security)
    - No NAT Gateway route (no outbound internet)
    - VPC local traffic only
    
    Database Communication:
    - Inbound: Application tier via security groups
    - Outbound: Response to application tier
    - Management: AWS Systems Manager Session Manager
    
    Updates and Patching:
    - RDS: AWS manages via service endpoints
    - EC2 databases: Use VPC endpoints or scheduled maintenance windows
  EOT
  value       = aws_route_table.database.id
}

output "database_route_table_arn" {
  description = "ARN of the database subnet route table"
  value       = aws_route_table.database.arn
}

# ----------------------------------------------------------------------------
# NAT Gateways (Network Address Translation)
# ----------------------------------------------------------------------------

output "nat_gateway_ids" {
  description = <<-EOT
    List of NAT Gateway IDs (one per Availability Zone).
    
    NAT Gateways enable private subnet instances to access the internet
    for outbound traffic while preventing inbound connections.
    
    High Availability Configuration:
    - AZ-1: NAT Gateway in public subnet of AZ-1
    - AZ-2: NAT Gateway in public subnet of AZ-2
    - AZ-3: NAT Gateway in public subnet of AZ-3
    
    Count: ${length(aws_nat_gateway.main)}
    
    Use Cases:
    - Software updates (yum, apt, pip, npm)
    - API calls to external services
    - S3/DynamoDB access (consider VPC endpoints instead)
    - Webhook callbacks
    - External service integrations
    
    Cost: ~$32/month per NAT Gateway + data transfer charges
    Total Monthly Cost: ~$${length(aws_nat_gateway.main) * 32} (for ${length(aws_nat_gateway.main)} NAT Gateways)
    
    Benefits of Multiple NAT Gateways:
    - No single point of failure
    - If one AZ fails, others continue operating
    - Reduced cross-AZ data transfer costs
    - Better performance (traffic stays in same AZ)
    
    Alternative: Single NAT Gateway
    - Cost savings: ~$64/month (2 fewer gateways)
    - Trade-off: Single point of failure
    - Not recommended for production
    
    Monitoring:
    - CloudWatch Metrics: BytesOutToDestination, BytesInFromSource
    - Set alarms for unusual traffic patterns
    - Monitor for data transfer costs
  EOT
  value       = aws_nat_gateway.main[*].id
}

output "nat_gateway_public_ips" {
  description = <<-EOT
    List of Elastic IP addresses assigned to NAT Gateways.
    
    These are the source IP addresses for all outbound internet traffic
    from private subnet instances. Static and predictable.
    
    IPs: ${join(", ", aws_eip.nat[*].public_ip)}
    
    Important Uses:
    - IP Allowlisting: Provide these IPs to third-party services
    - Firewall Rules: Configure external firewalls to allow these IPs
    - API Rate Limiting: Some APIs track by source IP
    - Security Monitoring: Track outbound connections by source IP
    - Compliance: Document external IP addresses for audit
    
    Examples:
    - Payment Gateway: Allowlist these IPs for API access
    - SaaS Provider: Add to firewall for webhooks
    - Partner API: Configure IP-based authentication
    
    Note: These IPs are static and will not change unless NAT Gateway
    is recreated. Document these IPs in your network documentation.
    
    Security Consideration:
    - These IPs are visible to external services
    - All private subnet instances share these IPs
    - Use application-level authentication (API keys, OAuth)
    - Don't rely solely on IP-based security
  EOT
  value       = aws_eip.nat[*].public_ip
}

output "elastic_ip_ids" {
  description = <<-EOT
    List of Elastic IP allocation IDs for NAT Gateways.
    
    Elastic IP allocation IDs (eipalloc-xxxxx) are used for:
    - Associating/disassociating EIPs
    - CloudWatch metrics and alarms
    - AWS CLI operations
    - Terraform resource references
    
    Count: ${length(aws_eip.nat)}
  EOT
  value       = aws_eip.nat[*].id
}

output "elastic_ip_allocation_ids" {
  description = "Allocation IDs for Elastic IPs (alternative format)"
  value       = aws_eip.nat[*].allocation_id
}

# ============================================================================
# SECTION 2: COMPUTE INFRASTRUCTURE OUTPUTS
# ============================================================================
#
# This section exports information about compute resources including
# Auto Scaling Groups, Launch Templates, Load Balancers, and Target Groups.
# ============================================================================

# ----------------------------------------------------------------------------
# Application Load Balancer
# ----------------------------------------------------------------------------

output "alb_id" {
  description = <<-EOT
    The ID of the Application Load Balancer.
    
    Internal identifier for the ALB. Use the DNS name for actual connections.
  EOT
  value       = aws_lb.main.id
}

output "alb_arn" {
  description = <<-EOT
    Amazon Resource Name (ARN) of the Application Load Balancer.
    
    Required for:
    - AWS WAF web ACL associations
    - CloudWatch Logs subscriptions
    - IAM policy resource specifications
    - AWS Config compliance rules
    - Target group attachments
    
    Format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
  EOT
  value       = aws_lb.main.arn
}

output "alb_dns_name" {
  description = <<-EOT
    DNS name of the Application Load Balancer (PRIMARY CONNECTION ENDPOINT).
    
    ⭐ THIS IS THE MAIN ENTRY POINT TO YOUR APPLICATION ⭐
    
    Use this DNS name to:
    - Access your application: http://<this_dns_name> or https://<this_dns_name>
    - Create Route 53 ALIAS records pointing to this ALB
    - Configure CNAME records in external DNS
    - Test application deployment
    - Set up monitoring and health checks
    
    Format: <name>-<id>.<region>.elb.amazonaws.com
    Example: myapp-prod-alb-123456789.us-east-1.elb.amazonaws.com
    
    DNS Configuration Examples:
    
    Route 53 ALIAS Record (Recommended):
      Type: A (IPv4) or AAAA (IPv6)
      Name: www.example.com
      Alias: Yes
      Alias Target: <this_dns_name>
      Benefits: Free, automatic IP updates, health checks
    
    CNAME Record (External DNS):
      Type: CNAME
      Name: www.example.com
      Value: <this_dns_name>
      TTL: 300
      Note: Cannot use CNAME for apex domain (example.com)
    
    Testing:
      curl http://<this_dns_name>/health
      curl https://<this_dns_name>  # If HTTPS enabled
    
    Security Notes:
    - ALB terminates SSL/TLS (HTTPS → HTTP to backend)
    - Use AWS Certificate Manager (ACM) for SSL certificates
    - Configure security groups to allow traffic
    - Enable access logs for security monitoring
    
    High Availability:
    - ALB spans ${length(aws_subnet.public)} Availability Zones
    - Automatic failover to healthy targets
    - No single point of failure
  EOT
  value       = aws_lb.main.dns_name
}

output "alb_zone_id" {
  description = <<-EOT
    Route 53 Hosted Zone ID for the Application Load Balancer.
    
    Required when creating Route 53 ALIAS records pointing to this ALB.
    
    Route 53 ALIAS Record Example:
      resource "aws_route53_record" "www" {
        zone_id = aws_route53_zone.primary.zone_id
        name    = "www.example.com"
        type    = "A"
        
        alias {
          name                   = <alb_dns_name output>
          zone_id                = <this_output>
          evaluate_target_health = true
        }
      }
    
    This is NOT your Route 53 hosted zone ID.
    This is the ALB's internal zone ID used by AWS for DNS routing.
  EOT
  value       = aws_lb.main.zone_id
}

output "alb_security_group_id" {
  description = <<-EOT
    Security Group ID attached to the Application Load Balancer.
    
    This security group controls inbound traffic to the ALB.
    
    Current Configuration:
    - Inbound: HTTP (80), HTTPS (443) from 0.0.0.0/0 (internet)
    - Outbound: All traffic (to reach target instances)
    
    Security Recommendations:
    - Keep HTTP open for redirect to HTTPS
    - Restrict HTTPS to specific IPs if not public
    - Enable AWS WAF for application-layer protection
    - Monitor with VPC Flow Logs
  EOT
  value       = aws_security_group.alb.id
}

# ----------------------------------------------------------------------------
# Target Groups
# ----------------------------------------------------------------------------

output "web_tier_target_group_arn" {
  description = <<-EOT
    ARN of the Target Group for web tier instances.
    
    The target group manages the pool of web tier instances that
    receive traffic from the Application Load Balancer.
    
    Configuration:
    - Protocol: HTTP
    - Port: 80
    - Health Check: /health endpoint
    - Health Check Interval: 30 seconds
    - Healthy Threshold: 2 consecutive successes
    - Unhealthy Threshold: 3 consecutive failures
    - Deregistration Delay: 30 seconds (connection draining)
    - Stickiness: Enabled/Disabled based on var.enable_sticky_sessions
    
    Instance Registration:
    - Auto Scaling Group automatically registers/deregisters instances
    - Manual registration: aws elbv2 register-targets
    
    Health Check Logic:
    - ALB sends HTTP GET to http://instance-ip/health
    - Expected response: 200 OK
    - If unhealthy: Instance removed from rotation
    - If healthy again: Instance added back to rotation
    
    Use for:
    - Monitoring target health in AWS Console
    - CloudWatch metrics: HealthyHostCount, UnHealthyHostCount
    - Manual target registration/deregistration
    - Blue/Green deployments
  EOT
  value       = aws_lb_target_group.web_tier.arn
}

output "web_tier_target_group_name" {
  description = "Name of the web tier target group"
  value       = aws_lb_target_group.web_tier.name
}

# ----------------------------------------------------------------------------
# Auto Scaling Groups
# ----------------------------------------------------------------------------

output "web_tier_asg_name" {
  description = <<-EOT
    Name of the Web Tier Auto Scaling Group.
    
    Auto Scaling Group manages a fleet of EC2 instances that automatically
    scale up/down based on demand (CPU utilization).
    
    Current Configuration:
    - Minimum Capacity: ${var.web_tier_min_size} instances
    - Maximum Capacity: ${var.web_tier_max_size} instances
    - Desired Capacity: ${var.web_tier_desired_size} instances
    - Instance Type: ${var.web_tier_instance_type}
    - Availability Zones: ${length(aws_subnet.private)} (${join(", ", local.azs)})
    
    Scaling Policies:
    - Target Tracking: Maintain ${var.target_cpu_utilization}% average CPU utilization
    - Scale Out: Add instances when CPU > target
    - Scale In: Remove instances when CPU < target
    - Cooldown: 300 seconds between scaling activities
    
    Health Checks:
    - Type: ELB (Target Group health checks)
    - Grace Period: 300 seconds
    - Unhealthy instances automatically replaced
    
    High Availability:
    - Instances distributed across ${length(local.azs)} AZs
    - Automatic replacement on instance failure
    - Zero-downtime deployments via instance refresh
    
    AWS CLI Operations:
      # View current capacity
      aws autoscaling describe-auto-scaling-groups \
        --auto-scaling-group-names <this_name>
      
      # Manual scaling
      aws autoscaling set-desired-capacity \
        --auto-scaling-group-name <this_name> \
        --desired-capacity 5
      
      # Terminate specific instance
      aws autoscaling terminate-instance-in-auto-scaling-group \
        --instance-id i-xxxxxxxxx \
        --should-decrement-desired-capacity
    
    Use for:
    - Monitoring current capacity in CloudWatch
    - Manual scaling operations
    - Viewing scaling history
    - Troubleshooting instance launches
  EOT
  value       = aws_autoscaling_group.web_tier.name
}

output "web_tier_asg_arn" {
  description = <<-EOT
    ARN of the Web Tier Auto Scaling Group.
    
    Required for IAM policies, CloudWatch Events, and EventBridge rules.
  EOT
  value       = aws_autoscaling_group.web_tier.arn
}

output "app_tier_asg_name" {
  description = <<-EOT
    Name of the Application Tier Auto Scaling Group.
    
    Manages backend application instances that process business logic.
    
    Current Configuration:
    - Minimum Capacity: ${var.app_tier_min_size} instances
    - Maximum Capacity: ${var.app_tier_max_size} instances
    - Desired Capacity: ${var.app_tier_desired_size} instances
    - Instance Type: ${var.app_tier_instance_type}
    
    This tier handles:
    - Backend API processing
    - Business logic execution
    - Database interactions
    - External service integrations
    
    Not directly attached to load balancer (receives traffic from web tier).
  EOT
  value       = aws_autoscaling_group.app_tier.name
}

output "app_tier_asg_arn" {
  description = "ARN of the Application Tier Auto Scaling Group"
  value       = aws_autoscaling_group.app_tier.arn
}

# ----------------------------------------------------------------------------
# Launch Templates
# ----------------------------------------------------------------------------

output "web_tier_launch_template_id" {
  description = <<-EOT
    ID of the Web Tier Launch Template.
    
    Launch Template defines the instance configuration:
    - AMI: Amazon Linux 2023 (latest)
    - Instance Type: ${var.web_tier_instance_type}
    - Root Volume: ${var.web_tier_root_volume_size} GB gp3 (encrypted)
    - Security Groups: Web tier security group
    - IAM Role: CloudWatch Logs, Systems Manager access
    - User Data: Security hardening script
    - Metadata Service: IMDSv2 (required)
    
    Security Features:
    - EBS volumes encrypted with KMS
    - IMDSv2 enforcement (prevents SSRF attacks)
    - No SSH key pair (use AWS Systems Manager)
    - Detailed monitoring enabled
    - Security hardening via user data script
    
    Version: Auto Scaling uses $Latest version
  EOT
  value       = aws_launch_template.web_tier.id
}

output "web_tier_launch_template_latest_version" {
  description = <<-EOT
    Latest version number of the Web Tier Launch Template.
    
    Increments each time launch template is updated.
    Auto Scaling Group uses this version to launch new instances.
  EOT
  value       = aws_launch_template.web_tier.latest_version
}

output "app_tier_launch_template_id" {
  description = "ID of the Application Tier Launch Template"
  value       = aws_launch_template.app_tier.id
}

output "app_tier_launch_template_latest_version" {
  description = "Latest version of the Application Tier Launch Template"
  value       = aws_launch_template.app_tier.latest_version
}

# ============================================================================
# SECTION 3: SECURITY GROUP OUTPUTS
# ============================================================================
#
# This section exports all security group IDs and ARNs for reference
# in other configurations and security auditing.
# ============================================================================

output "security_group_ids" {
  description = <<-EOT
    Map of all security group IDs for easy reference.
    
    Security groups act as virtual firewalls controlling inbound and
    outbound traffic at the instance level (stateful).
    
    Architecture:
    - ALB Security Group: Allows HTTP/HTTPS from internet
    - Web Tier: Allows traffic only from ALB
    - App Tier: Allows traffic only from Web Tier
    - Database: Allows traffic only from App Tier
    - Bastion: Allows SSH only from corporate VPN (if enabled)
    
    Use this map to reference security groups in other resources:
      security_groups = [local.security_group_ids.web_tier]
  EOT
  value = {
    alb      = aws_security_group.alb.id
    web_tier = aws_security_group.web_tier.id
    app_tier = aws_security_group.app_tier.id
    database = aws_security_group.database.id
    bastion  = var.enable_bastion ? aws_security_group.bastion[0].id : null
  }
}

output "alb_security_group_arn" {
  description = <<-EOT
    ARN of the ALB Security Group.
    
    Controls inbound traffic to the Application Load Balancer.
    
    Rules:
    - Inbound: HTTP (80), HTTPS (443) from 0.0.0.0/0
    - Outbound: All traffic (to reach backend instances)
  EOT
  value       = aws_security_group.alb.arn
}

output "web_tier_security_group_id" {
  description = "Security Group ID for Web Tier instances"
  value       = aws_security_group.web_tier.id
}

output "web_tier_security_group_arn" {
  description = <<-EOT
    ARN of the Web Tier Security Group.
    
    Controls traffic to web tier application instances.
    
    Rules:
    - Inbound: HTTP (80), HTTPS (443) from ALB security group only
    - Inbound: Health check port (8081) from ALB security group
    - Outbound: All traffic (for updates, API calls, database connections)
    
    Zero Trust: Instances only accept traffic from load balancer.
  EOT
  value       = aws_security_group.web_tier.arn
}

output "app_tier_security_group_id" {
  description = "Security Group ID for Application Tier instances"
  value       = aws_security_group.app_tier.id
}

output "app_tier_security_group_arn" {
  description = <<-EOT
    ARN of the Application Tier Security Group.
    
    Controls traffic to backend application instances.
    
    Rules:
    - Inbound: Backend API port (8080) from Web Tier security group only
    - Inbound: Metrics port (9090) from Web Tier security group
    - Outbound: All traffic (for database, external APIs, updates)
    
    Network Segmentation: Further isolated from internet and ALB.
  EOT
  value       = aws_security_group.app_tier.arn
}

output "database_security_group_id" {
  description = "Security Group ID for Database instances"
  value       = aws_security_group.database.id
}

output "database_security_group_arn" {
  description = <<-EOT
    ARN of the Database Security Group (MOST RESTRICTIVE).
    
    Controls access to database instances (highest security tier).
    
    Rules:
    - Inbound: MySQL (3306), PostgreSQL (5432) from App Tier only
    - Inbound: Redis (6379), MongoDB (27017) from App Tier only
    - Outbound: All traffic (for managed service updates)
    
    Maximum Security:
    - No internet access
    - Only application tier can connect
    - Database ports only (no SSH, RDP)
    - Protects sensitive data from unauthorized access
    
    Compliance:
    - PCI-DSS: Database isolation (Req 1.3.6)
    - HIPAA: Access controls (§164.312)
    - SOC 2: Logical access (CC6.1)
  EOT
  value       = aws_security_group.database.arn
}

output "bastion_security_group_id" {
  description = <<-EOT
    Security Group ID for Bastion Host (if enabled).
    
    Bastion hosts provide secure SSH access to private instances.
    
    Rules:
    - Inbound: SSH (22) from corporate VPN/office IPs only
    - Outbound: SSH (22) to private subnets
    
    Note: AWS Systems Manager Session Manager is recommended instead
    of bastion hosts for better security (no SSH port exposure).
    
    Value: null if bastion is disabled
  EOT
  value       = var.enable_bastion ? aws_security_group.bastion[0].id : null
}

output "bastion_security_group_arn" {
  description = "ARN of the Bastion Security Group (null if disabled)"
  value       = var.enable_bastion ? aws_security_group.bastion[0].arn : null
}

# ============================================================================
# SECTION 4: ENCRYPTION AND KEY MANAGEMENT
# ============================================================================

output "ebs_kms_key_id" {
  description = <<-EOT
    KMS Key ID for EBS volume encryption.
    
    This customer-managed KMS key encrypts all EBS volumes for:
    - Web tier instances
    - Application tier instances
    - Snapshots and backups
    
    Encryption Details:
    - Algorithm: AES-256
    - Key Rotation: Enabled (automatic annual rotation)
    - FIPS 140-2 Level 2: AWS KMS is FIPS validated
    
    Benefits over AWS-managed keys:
    - Full control over key policies
    - CloudTrail logging of key usage
    - Custom access controls
    - Compliance requirements (HIPAA, PCI-DSS)
    
    Use for:
    - Encrypting additional EBS volumes
    - Creating encrypted snapshots
    - Cross-region encrypted snapshot copies
  EOT
  value       = aws_kms_key.ebs.id
}

output "ebs_kms_key_arn" {
  description = <<-EOT
    ARN of the KMS key for EBS encryption.
    
    Required for IAM policies, cross-account access, and service integrations.
  EOT
  value       = aws_kms_key.ebs.arn
}

# ============================================================================
# SECTION 5: LOGGING AND MONITORING
# ============================================================================

output "vpc_flow_logs_s3_bucket" {
  description = <<-EOT
    S3 bucket name storing VPC Flow Logs.
    
    VPC Flow Logs capture information about IP traffic to/from
    network interfaces in the VPC.
    
    Captured Data:
    - Source and destination IP addresses
    - Source and destination ports
    - Protocol (TCP, UDP, ICMP)
    - Number of packets and bytes
    - Action (ACCEPT or REJECT)
    - Start and end timestamps
    
    Use Cases:
    - Security forensics and incident response
    - Troubleshooting connectivity issues
    - Understanding traffic patterns
    - Detecting unusual activity
    - Compliance requirements (PCI-DSS, HIPAA)
    
    Log Format: Parquet (queryable with Amazon Athena)
    Retention: ${var.flow_logs_retention_days} days (then deleted by lifecycle policy)
    
    Querying Logs:
      # Using Athena (SQL)
      SELECT sourceaddress, destinationaddress, action, packets
      FROM vpc_flow_logs
      WHERE action = 'REJECT'
      AND date >= '2024-01-01'
      LIMIT 100;
    
    Cost: ~$0.50 per GB of flow log data
  EOT
  value       = aws_s3_bucket.flow_logs.id
}

output "alb_access_logs_s3_bucket" {
  description = <<-EOT
    S3 bucket name storing ALB access logs.
    
    ALB access logs contain detailed information about every request:
    - Timestamp
    - Client IP address
    - Request URL and method
    - Response status code
    - User agent
    - SSL cipher and protocol
    - Request and response sizes
    
    Use Cases:
    - Security analysis (detect attacks)
    - Troubleshooting client issues
    - Understanding traffic patterns
    - Performance analysis
    - Compliance auditing
    
    Log Format: Plain text (space-delimited)
    Retention: ${var.alb_log_retention_days} days
    
    Example Log Entry:
      https 2024-01-15T10:30:00.123456Z app/my-alb/50dc6c495c0c9188 
      192.0.2.1:12345 10.0.1.5:80 0.001 0.002 0.000 200 200 154 365 
      "GET https://example.com:443/ HTTP/1.1" "Mozilla/5.0..." 
      ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2
  EOT
  value       = aws_s3_bucket.alb_logs.id
}

# ============================================================================
# SECTION 6: COMPREHENSIVE INFRASTRUCTURE SUMMARY
# ============================================================================

output "infrastructure_summary" {
  description = <<-EOT
    ═══════════════════════════════════════════════════════════════════════
    ENTERPRISE AWS INFRASTRUCTURE - DEPLOYMENT SUMMARY
    ═══════════════════════════════════════════════════════════════════════
    
    This output provides a comprehensive overview of your deployed
    infrastructure for documentation, client reporting, and operations.
    
    Use this summary for:
    - Executive reporting
    - Documentation
    - Handoff to operations team
    - Disaster recovery planning
    - Compliance auditing
  EOT
  value = {
    # Environment Information
    environment = {
      name                 = var.environment
      project              = var.project_name
      region               = data.aws_region.current.name
      availability_zones   = local.azs
      deployment_date      = timestamp()
    }
    
    # Network Configuration
    network = {
      vpc_id               = aws_vpc.main.id
      vpc_cidr             = aws_vpc.main.cidr_block
      public_subnets       = length(aws_subnet.public)
      private_subnets      = length(aws_subnet.private)
      database_subnets     = length(aws_subnet.database)
      nat_gateways         = length(aws_nat_gateway.main)
      internet_gateway     = aws_internet_gateway.main.id
    }
    
    # Compute Resources
    compute = {
      alb_dns_name            = aws_lb.main.dns_name
      web_tier_min_instances  = var.web_tier_min_size
      web_tier_max_instances  = var.web_tier_max_size
      app_tier_min_instances  = var.app_tier_min_size
      app_tier_max_instances  = var.app_tier_max_size
      instance_type_web       = var.web_tier_instance_type
      instance_type_app       = var.app_tier_instance_type
    }
    
    # Security Configuration
    security = {
      security_groups_count   = 5  # ALB, Web, App, DB, Bastion
      encryption_at_rest      = "AES-256 (KMS)"
      encryption_in_transit   = "TLS 1.2+"
      imdsv2_enforced         = true
      vpc_flow_logs_enabled   = true
      alb_access_logs_enabled = var.enable_alb_access_logs
    }
    
    # High Availability
    high_availability = {
      multi_az_deployment     = true
      availability_zones      = length(local.azs)
      auto_scaling_enabled    = true
      load_balancer_redundant = true
      nat_gateway_per_az      = true
    }
    
    # Compliance & Governance
    compliance = {
      frameworks_supported = ["PCI-DSS", "HIPAA", "SOC 2", "ISO 27001", "GDPR"]
      encryption_required  = true
      logging_enabled      = true
      access_controls      = "Least Privilege"
      network_segmentation = "3-Tier Architecture"
    }
  }
}

# ============================================================================
# SECTION 7: CONNECTION INFORMATION (QUICK REFERENCE)
# ============================================================================

output "connection_endpoints" {
  description = <<-EOT
    Quick reference for connecting to deployed resources.
    
    Use these endpoints to access your infrastructure:
  EOT
  value = {
    application_url = "http://${aws_lb.main.dns_name}"
    health_check    = "http://${aws_lb.main.dns_name}/health"
    
    ssh_access = var.enable_bastion ? (
      "SSH via bastion host (deprecated - use AWS Systems Manager instead)"
    ) : (
      "Use AWS Systems Manager Session Manager (no bastion required)"
    )
    
    nat_gateway_ips = aws_eip.nat[*].public_ip
  }
}

# ============================================================================
# END OF OUTPUTS
# ============================================================================
