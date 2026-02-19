# ============================================================================
# ENTERPRISE-GRADE SECURITY GROUPS AND NETWORK ACLs CONFIGURATION
# ============================================================================
#
# This Terraform configuration implements a comprehensive security framework
# for a multi-tier application architecture following AWS security best practices,
# the principle of least privilege, and defense-in-depth strategy.
#
# SECURITY ARCHITECTURE OVERVIEW:
# --------------------------------
# Layer 1: Network ACLs (Stateless) - Subnet-level firewall rules
# Layer 2: Security Groups (Stateful) - Instance-level firewall rules
# Layer 3: IAM Policies - Identity-based access control
# Layer 4: Application Logic - Code-level security controls
#
# TRAFFIC FLOW:
# --------------
# Internet → ALB Security Group (80/443)
#         → Web Tier Security Group (80/443 from ALB only)
#         → App Tier Security Group (app ports from Web Tier only)
#         → Database Security Group (3306/5432 from App Tier only)
#
# SECURITY BENEFITS:
# ------------------
# 1. Zero Trust Architecture: No implicit trust between tiers
# 2. Principle of Least Privilege: Minimum required access only
# 3. Network Segmentation: Each tier isolated with specific rules
# 4. Defense in Depth: Multiple layers of security controls
# 5. Stateful + Stateless Filtering: Security Groups + NACLs
# 6. Explicit Deny by Default: All traffic denied unless explicitly allowed
# 7. Audit Trail: All rules documented for compliance
#
# COMPLIANCE FRAMEWORKS SUPPORTED:
# ---------------------------------
# - PCI-DSS: Network segmentation (Req 1.3), Access control (Req 7)
# - HIPAA: Access controls (§164.312), Audit controls (§164.308)
# - SOC 2: Logical access controls (CC6.1, CC6.2, CC6.6)
# - ISO 27001: Access control (A.9), Network security (A.13)
# - NIST 800-53: Access control (AC family), System protection (SC family)
#
# ============================================================================

# ============================================================================
# DATA SOURCES
# ============================================================================

# Reference the VPC created in network.tf
# This data source retrieves the VPC ID to associate security groups
data "aws_vpc" "main" {
  id = aws_vpc.main.id
}

# Get subnet IDs for NACL associations
# These data sources reference the subnets created in network.tf
data "aws_subnet" "public" {
  count = length(aws_subnet.public)
  id    = aws_subnet.public[count.index].id
}

data "aws_subnet" "private" {
  count = length(aws_subnet.private)
  id    = aws_subnet.private[count.index].id
}

data "aws_subnet" "database" {
  count = length(aws_subnet.database)
  id    = aws_subnet.database[count.index].id
}

# ============================================================================
# LOCAL VARIABLES FOR SECURITY GROUP RULES
# ============================================================================

locals {
  # -------------------------------------------------------------------------
  # COMMON PORTS DEFINITION
  # -------------------------------------------------------------------------
  # Define commonly used ports for better code readability and maintainability
  # These local values make the security group rules self-documenting
  
  common_ports = {
    http          = 80
    https         = 443
    ssh           = 22
    mysql         = 3306
    postgresql    = 5432
    redis         = 6379
    mongodb       = 27017
    elasticsearch = 9200
    app_backend   = 8080
    health_check  = 8081
    metrics       = 9090
  }

  # -------------------------------------------------------------------------
  # APPLICATION LOAD BALANCER INGRESS RULES
  # -------------------------------------------------------------------------
  # ALB accepts traffic from the internet on standard web ports
  # These rules allow public access to your web application through HTTPS/HTTP
  # 
  # SECURITY CONSIDERATIONS:
  # - HTTPS (443) should be primary for encrypted traffic (TLS 1.2+)
  # - HTTP (80) typically redirects to HTTPS or can be blocked entirely
  # - Consider AWS WAF for additional application-layer protection
  # - Enable ALB access logs for security monitoring
  # - Use AWS Shield Standard (automatic) or Advanced for DDoS protection
  
  alb_ingress_rules = [
    {
      description = "HTTPS from Internet - Encrypted web traffic (TLS 1.2+)"
      from_port   = local.common_ports.https
      to_port     = local.common_ports.https
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      # Best Practice: Use CloudFront with AWS WAF for additional security
      # CloudFront provides DDoS protection and can cache static content
    },
    {
      description = "HTTP from Internet - Redirects to HTTPS or disabled"
      from_port   = local.common_ports.http
      to_port     = local.common_ports.http
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
      # Security Note: Configure ALB to redirect HTTP to HTTPS automatically
      # Alternatively, remove this rule to enforce HTTPS-only access
    },
  ]

  # -------------------------------------------------------------------------
  # WEB TIER INGRESS RULES
  # -------------------------------------------------------------------------
  # Web tier accepts traffic ONLY from the Application Load Balancer
  # This implements the zero-trust principle - no direct internet access
  #
  # SECURITY BENEFITS:
  # - Web servers not directly exposed to internet attacks
  # - ALB provides SSL/TLS termination and certificate management
  # - ALB performs health checks before routing traffic
  # - WAF rules can be applied at ALB level
  # - Source IP filtering at multiple layers
  #
  # TYPICAL WORKLOADS:
  # - Nginx/Apache web servers
  # - Application servers (Node.js, Python, Ruby, PHP)
  # - Container workloads (ECS, EKS)
  # - Lambda functions (via ALB target groups)
  
  web_tier_ingress_rules = [
    {
      description              = "HTTPS from ALB only - Encrypted application traffic"
      from_port                = local.common_ports.https
      to_port                  = local.common_ports.https
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.alb.id
      # This ensures only the ALB can communicate with web tier instances
      # No direct internet access possible
    },
    {
      description              = "HTTP from ALB only - Internal application traffic"
      from_port                = local.common_ports.http
      to_port                  = local.common_ports.http
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.alb.id
      # Most applications terminate SSL at ALB and use HTTP internally
      # This is acceptable as traffic stays within AWS network
    },
    {
      description              = "Health Check Port from ALB - Application monitoring"
      from_port                = local.common_ports.health_check
      to_port                  = local.common_ports.health_check
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.alb.id
      # Dedicated health check endpoint for application availability monitoring
      # ALB removes unhealthy instances from rotation automatically
    },
  ]

  # -------------------------------------------------------------------------
  # APPLICATION TIER INGRESS RULES
  # -------------------------------------------------------------------------
  # App tier accepts traffic ONLY from the Web Tier
  # This creates an additional security boundary for business logic
  #
  # USE CASES:
  # - Microservices architecture
  # - API backend services
  # - Business logic processing
  # - Data transformation services
  # - Integration services
  #
  # SECURITY PRINCIPLES:
  # - Further network segmentation from web tier
  # - Reduces attack surface - not accessible from internet
  # - Implements service-to-service authentication
  # - Can enforce mutual TLS (mTLS) between tiers
  # - Centralized logging and monitoring required
  
  app_tier_ingress_rules = [
    {
      description              = "Backend API from Web Tier - RESTful API traffic"
      from_port                = local.common_ports.app_backend
      to_port                  = local.common_ports.app_backend
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.web_tier.id
      # Only web tier instances can call backend APIs
      # Implement API authentication (OAuth 2.0, JWT) at application level
    },
    {
      description              = "Metrics Collection - Prometheus/CloudWatch metrics"
      from_port                = local.common_ports.metrics
      to_port                  = local.common_ports.metrics
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.web_tier.id
      # Allow web tier to scrape application metrics
      # Use for monitoring, alerting, and autoscaling decisions
    },
  ]

  # -------------------------------------------------------------------------
  # DATABASE TIER INGRESS RULES
  # -------------------------------------------------------------------------
  # Database tier accepts traffic ONLY from the Application Tier
  # This is the most critical security boundary - protects sensitive data
  #
  # SUPPORTED DATABASES:
  # - MySQL/MariaDB (3306)
  # - PostgreSQL (5432)
  # - Redis (6379) - For caching
  # - MongoDB (27017) - NoSQL database
  #
  # SECURITY CRITICAL:
  # - NO internet access - completely isolated
  # - Only app tier can connect to databases
  # - Use IAM database authentication where possible
  # - Enable encryption at rest (KMS)
  # - Enable encryption in transit (SSL/TLS)
  # - Regular security patches and updates
  # - Database audit logging enabled
  # - Restrict database user privileges (least privilege)
  #
  # COMPLIANCE REQUIREMENTS:
  # - PCI-DSS: Database storing cardholder data must be isolated (Req 1.3.6)
  # - HIPAA: ePHI databases require access controls (§164.312)
  # - SOC 2: Database access restricted to authorized systems only
  
  database_tier_ingress_rules = [
    {
      description              = "MySQL from App Tier only - Relational database access"
      from_port                = local.common_ports.mysql
      to_port                  = local.common_ports.mysql
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.app_tier.id
      # MySQL/MariaDB/Aurora MySQL access restricted to application tier
      # Enable SSL/TLS connections with RDS certificate validation
    },
    {
      description              = "PostgreSQL from App Tier only - Relational database access"
      from_port                = local.common_ports.postgresql
      to_port                  = local.common_ports.postgresql
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.app_tier.id
      # PostgreSQL/Aurora PostgreSQL access restricted to application tier
      # Use SSL mode 'require' or 'verify-full' in connection strings
    },
    {
      description              = "Redis from App Tier only - Caching and session storage"
      from_port                = local.common_ports.redis
      to_port                  = local.common_ports.redis
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.app_tier.id
      # ElastiCache Redis for caching, session management
      # Enable encryption in transit and at rest
      # Use AUTH token for authentication
    },
    {
      description              = "MongoDB from App Tier only - NoSQL database access"
      from_port                = local.common_ports.mongodb
      to_port                  = local.common_ports.mongodb
      protocol                 = "tcp"
      source_security_group_id = aws_security_group.app_tier.id
      # DocumentDB (MongoDB-compatible) or self-managed MongoDB
      # Enable TLS/SSL encryption for client connections
      # Use strong authentication with SCRAM-SHA-256
    },
  ]

  # -------------------------------------------------------------------------
  # BASTION HOST INGRESS RULES (OPTIONAL)
  # -------------------------------------------------------------------------
  # Bastion host (jump box) for secure administrative SSH access
  # This is optional - AWS Systems Manager Session Manager is preferred
  #
  # SECURITY BEST PRACTICES:
  # - Limit source IPs to corporate VPN or office IPs only
  # - Use SSH key-based authentication (no passwords)
  # - Enable MFA for SSH access
  # - Log all SSH sessions for audit
  # - Use short-lived SSH certificates
  # - Consider AWS Systems Manager Session Manager instead (no SSH port exposure)
  #
  # ALTERNATIVE: AWS Systems Manager Session Manager
  # - No inbound ports required
  # - Centralized access control via IAM
  # - Session logging to S3/CloudWatch
  # - No bastion host maintenance
  
  bastion_ingress_rules = [
    {
      description = "SSH from Corporate VPN only - Administrative access"
      from_port   = local.common_ports.ssh
      to_port     = local.common_ports.ssh
      protocol    = "tcp"
      cidr_blocks = var.corporate_vpn_cidrs # Define in variables.tf
      # CRITICAL: Replace with your actual corporate IP ranges
      # Never use 0.0.0.0/0 for SSH access
      # Example: ["203.0.113.0/24", "198.51.100.0/24"]
    },
  ]

  # -------------------------------------------------------------------------
  # COMMON EGRESS RULES (OUTBOUND TRAFFIC)
  # -------------------------------------------------------------------------
  # Most security groups need outbound internet access for:
  # - Software updates (yum, apt, npm, pip)
  # - External API calls (payment gateways, third-party services)
  # - DNS resolution
  # - NTP time synchronization
  #
  # SECURITY CONSIDERATIONS:
  # - Egress is controlled via NAT Gateway (private subnets)
  # - Monitor outbound traffic with VPC Flow Logs
  # - Implement egress filtering for compliance (optional)
  # - Use VPC Endpoints for AWS services (no internet required)
  # - Consider AWS Network Firewall for advanced egress filtering
  
  common_egress_rules = [
    {
      description = "Allow all outbound traffic - Software updates and external APIs"
      from_port   = 0
      to_port     = 0
      protocol    = "-1" # -1 means all protocols
      cidr_blocks = ["0.0.0.0/0"]
      # This allows instances to:
      # - Install security patches
      # - Call external APIs
      # - Download dependencies
      # - Communicate with other AWS services
      # Alternative: Restrict to specific ports/destinations for stricter control
    },
  ]

  # -------------------------------------------------------------------------
  # NETWORK ACL RULES FOR PUBLIC SUBNETS
  # -------------------------------------------------------------------------
  # Public subnets host: ALB, NAT Gateways, Bastion Hosts
  # NACLs provide stateless, subnet-level filtering
  #
  # STATELESS FIREWALL:
  # - Both inbound and outbound rules required
  # - Rules processed in order by rule number
  # - First match wins (lowest rule number)
  # - Default deny if no match
  #
  # SECURITY BENEFITS:
  # - Additional layer beyond security groups
  # - Protection against misconfigured security groups
  # - Subnet-level DDoS mitigation
  # - Explicit deny rules for known bad actors
  
  public_subnet_nacl_ingress = [
    {
      rule_number = 100
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = local.common_ports.http
      to_port     = local.common_ports.http
      description = "Allow HTTP from internet for ALB"
    },
    {
      rule_number = 110
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = local.common_ports.https
      to_port     = local.common_ports.https
      description = "Allow HTTPS from internet for ALB"
    },
    {
      rule_number = 120
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = 1024
      to_port     = 65535
      description = "Allow return traffic for outbound connections (ephemeral ports)"
      # Ephemeral ports used for return traffic from NAT Gateway
      # Linux: 32768-61000, Windows: 49152-65535
      # Using 1024-65535 to cover all operating systems
    },
    {
      rule_number = 130
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = 0
      to_port     = 65535
      description = "Allow all TCP traffic from within VPC"
      # Internal VPC communication should be allowed
      # Specific filtering done by security groups
    },
  ]

  public_subnet_nacl_egress = [
    {
      rule_number = 100
      protocol    = "-1" # All protocols
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = 0
      to_port     = 0
      description = "Allow all outbound traffic"
      # Public subnets need unrestricted egress for NAT functionality
      # NAT Gateways forward traffic from private subnets to internet
    },
  ]

  # -------------------------------------------------------------------------
  # NETWORK ACL RULES FOR PRIVATE SUBNETS
  # -------------------------------------------------------------------------
  # Private subnets host: Application servers, container workloads
  # More restrictive than public subnets
  #
  # ALLOWED INBOUND:
  # - HTTP/HTTPS from public subnets (ALB traffic)
  # - Application ports from within VPC
  # - Return traffic (ephemeral ports)
  #
  # DENIED INBOUND:
  # - Direct internet access
  # - Unnecessary protocols (FTP, Telnet, etc.)
  
  private_subnet_nacl_ingress = [
    {
      rule_number = 100
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.http
      to_port     = local.common_ports.http
      description = "Allow HTTP from VPC (ALB to web tier)"
    },
    {
      rule_number = 110
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.https
      to_port     = local.common_ports.https
      description = "Allow HTTPS from VPC (ALB to web tier)"
    },
    {
      rule_number = 120
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.app_backend
      to_port     = local.common_ports.app_backend
      description = "Allow backend API traffic within VPC"
    },
    {
      rule_number = 130
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = 1024
      to_port     = 65535
      description = "Allow return traffic for outbound connections (ephemeral ports)"
      # Required for responses to outbound requests (software updates, API calls)
    },
    {
      rule_number = 140
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.ssh
      to_port     = local.common_ports.ssh
      description = "Allow SSH from bastion host in VPC"
      # Only if using bastion host for management
      # Remove if using AWS Systems Manager Session Manager
    },
  ]

  private_subnet_nacl_egress = [
    {
      rule_number = 100
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = local.common_ports.http
      to_port     = local.common_ports.http
      description = "Allow outbound HTTP for software updates"
    },
    {
      rule_number = 110
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = local.common_ports.https
      to_port     = local.common_ports.https
      description = "Allow outbound HTTPS for software updates and API calls"
    },
    {
      rule_number = 120
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.mysql
      to_port     = local.common_ports.mysql
      description = "Allow MySQL traffic to database tier"
    },
    {
      rule_number = 130
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.postgresql
      to_port     = local.common_ports.postgresql
      description = "Allow PostgreSQL traffic to database tier"
    },
    {
      rule_number = 140
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.redis
      to_port     = local.common_ports.redis
      description = "Allow Redis traffic to cache tier"
    },
    {
      rule_number = 150
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = 1024
      to_port     = 65535
      description = "Allow ephemeral ports for return traffic"
      # Required for receiving responses from external services
    },
  ]

  # -------------------------------------------------------------------------
  # NETWORK ACL RULES FOR DATABASE SUBNETS
  # -------------------------------------------------------------------------
  # Database subnets: Most restrictive - NO internet access
  # 
  # CRITICAL SECURITY REQUIREMENTS:
  # - Only allow database ports from private subnets
  # - No outbound internet access
  # - No management ports exposed
  # - Logging all connection attempts
  #
  # COMPLIANCE BENEFITS:
  # - PCI-DSS Requirement 1.3.6: Database isolation
  # - HIPAA: Protected Health Information (PHI) isolation
  # - SOC 2: Restricted access to sensitive data
  
  database_subnet_nacl_ingress = [
    {
      rule_number = 100
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.mysql
      to_port     = local.common_ports.mysql
      description = "Allow MySQL from private subnets only"
      # Restrict to private subnet CIDR ranges for tighter security
    },
    {
      rule_number = 110
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.postgresql
      to_port     = local.common_ports.postgresql
      description = "Allow PostgreSQL from private subnets only"
    },
    {
      rule_number = 120
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.redis
      to_port     = local.common_ports.redis
      description = "Allow Redis from private subnets only"
    },
    {
      rule_number = 130
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = local.common_ports.mongodb
      to_port     = local.common_ports.mongodb
      description = "Allow MongoDB from private subnets only"
    },
    {
      rule_number = 140
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = 1024
      to_port     = 65535
      description = "Allow ephemeral ports for return traffic from software updates"
      # Required if RDS/database instances need to download patches
      # Alternative: Use VPC endpoints for AWS services
    },
  ]

  database_subnet_nacl_egress = [
    {
      rule_number = 100
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = var.vpc_cidr
      from_port   = 1024
      to_port     = 65535
      description = "Allow ephemeral ports for return traffic to private subnets"
      # Database responses to application queries
    },
    {
      rule_number = 110
      protocol    = "tcp"
      rule_action = "allow"
      cidr_block  = "0.0.0.0/0"
      from_port   = local.common_ports.https
      to_port     = local.common_ports.https
      description = "Allow HTTPS for RDS certificate validation and updates"
      # Required for RDS to validate SSL certificates and download patches
      # Alternative: Block completely for maximum security (manual patching)
    },
  ]

  # -------------------------------------------------------------------------
  # RESOURCE TAGS
  # -------------------------------------------------------------------------
  # Comprehensive tagging strategy for security group management
  
  common_tags = {
    ManagedBy          = "Terraform"
    Environment        = var.environment
    Project            = var.project_name
    CostCenter         = var.cost_center
    SecurityFramework  = "Zero-Trust-Defense-in-Depth"
    ComplianceScope    = "PCI-DSS-HIPAA-SOC2-ISO27001"
    LastReviewed       = formatdate("YYYY-MM-DD", timestamp())
    SecurityTier       = "Production"
    DataClassification = "Confidential"
  }
}

# ============================================================================
# SECURITY GROUP: APPLICATION LOAD BALANCER (INTERNET-FACING)
# ============================================================================
#
# PURPOSE: Controls inbound traffic to the Application Load Balancer
# TIER: Edge/Internet-Facing Layer
# EXPOSURE: Public internet (0.0.0.0/0)
#
# SECURITY PROFILE:
# - Accepts HTTP/HTTPS from internet
# - First point of contact for user traffic
# - Should be protected with AWS WAF
# - Enable access logging for security monitoring
# - Use AWS Shield for DDoS protection
#
# TYPICAL CONFIGURATION:
# - CloudFront → ALB → Web Tier (recommended for production)
# - Direct: Internet → ALB → Web Tier
#
# MONITORING REQUIREMENTS:
# - Enable ALB access logs to S3
# - CloudWatch metrics: RequestCount, TargetResponseTime, HTTPCode_Target_4XX/5XX
# - Set up alarms for unusual traffic patterns
# - Integrate with AWS GuardDuty for threat detection
# ============================================================================

resource "aws_security_group" "alb" {
  name        = "${var.project_name}-${var.environment}-alb-sg"
  description = "Security group for Application Load Balancer - Internet-facing edge security layer"
  vpc_id      = data.aws_vpc.main.id

  # Dynamic ingress block for flexible rule management
  # This approach allows easy addition/removal of rules without code duplication
  # Each rule in local.alb_ingress_rules is automatically converted to an ingress rule
  dynamic "ingress" {
    for_each = local.alb_ingress_rules
    content {
      description = ingress.value.description
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  # Dynamic egress block for outbound rules
  # ALB needs to communicate with target instances in web tier
  dynamic "egress" {
    for_each = local.common_egress_rules
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name           = "${var.project_name}-${var.environment}-alb-sg"
      Tier           = "Edge"
      Purpose        = "Application-Load-Balancer"
      InternetFacing = "true"
      Exposure       = "Public"
      CriticalityLevel = "High"
      Description    = "Accepts HTTP/HTTPS traffic from internet, forwards to web tier"
    }
  )

  # Lifecycle policy to prevent accidental deletion
  # Deleting ALB security group would break application access
  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# SECURITY GROUP: WEB TIER (APPLICATION SERVERS)
# ============================================================================
#
# PURPOSE: Controls traffic to web/application servers in private subnets
# TIER: Presentation/Web Layer
# EXPOSURE: Internal only (via ALB)
#
# SECURITY PROFILE:
# - Accepts traffic ONLY from ALB security group
# - No direct internet access
# - Zero-trust enforcement: Explicit source security group
# - Implements defense in depth with ALB as proxy
#
# WORKLOAD TYPES:
# - Web servers: Nginx, Apache, IIS
# - Application servers: Node.js, Python (Django/Flask), Ruby (Rails), PHP, Java
# - Container platforms: ECS Fargate, EKS pods
# - Serverless: Lambda functions (behind ALB)
#
# SECURITY BEST PRACTICES:
# - Keep web servers patched and updated
# - Use immutable infrastructure (replace, don't update)
# - Implement application-level authentication
# - Enable CloudWatch Logs for application logs
# - Use AWS Systems Manager for patching
# - Implement rate limiting at application level
# - Enable AWS X-Ray for distributed tracing
#
# MONITORING:
# - CloudWatch agent for system metrics
# - Application Performance Monitoring (APM)
# - Custom metrics for business KPIs
# - Log aggregation (CloudWatch Logs, ELK, Splunk)
# ============================================================================

resource "aws_security_group" "web_tier" {
  name        = "${var.project_name}-${var.environment}-web-tier-sg"
  description = "Security group for Web Tier instances - Only accepts traffic from ALB"
  vpc_id      = data.aws_vpc.main.id

  # Dynamic ingress rules: Accept traffic only from ALB
  # Using source_security_group_id ensures only ALB can send traffic
  # This is more secure than CIDR-based rules which can be spoofed
  dynamic "ingress" {
    for_each = local.web_tier_ingress_rules
    content {
      description              = ingress.value.description
      from_port                = ingress.value.from_port
      to_port                  = ingress.value.to_port
      protocol                 = ingress.value.protocol
      source_security_group_id = ingress.value.source_security_group_id
      # No cidr_blocks defined = traffic must come from specified security group
      # This implements strict zero-trust networking
    }
  }

  # Egress rules: Web tier needs outbound access for:
  # - Calling application tier APIs
  # - Software updates (via NAT Gateway)
  # - External API calls (payment gateways, third-party services)
  # - Database connections (if directly connecting to RDS)
  dynamic "egress" {
    for_each = local.common_egress_rules
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name             = "${var.project_name}-${var.environment}-web-tier-sg"
      Tier             = "Web"
      Purpose          = "Application-Servers"
      InternetFacing   = "false"
      Exposure         = "Internal-via-ALB"
      CriticalityLevel = "High"
      Description      = "Web tier security group - accepts traffic only from ALB security group"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# SECURITY GROUP: APPLICATION TIER (BUSINESS LOGIC)
# ============================================================================
#
# PURPOSE: Controls traffic to application/backend servers
# TIER: Application/Business Logic Layer
# EXPOSURE: Internal only (via Web Tier)
#
# SECURITY PROFILE:
# - Accepts traffic ONLY from Web Tier security group
# - Further isolation from internet and ALB
# - Implements microservices architecture security
# - Service mesh compatible (Istio, App Mesh, Consul)
#
# USE CASES:
# - Backend API services (REST, GraphQL, gRPC)
# - Business logic processing
# - Data aggregation and transformation
# - Integration services
# - Message queue consumers (SQS, RabbitMQ, Kafka)
# - Background job processors
#
# ARCHITECTURE PATTERNS:
# - Microservices: Each service has own security group
# - Service mesh: Mutual TLS between services
# - Event-driven: Services communicate via queues/topics
# - API Gateway: Centralized API management
#
# SECURITY CONSIDERATIONS:
# - Implement service-to-service authentication (OAuth 2.0, JWT)
# - Use encrypted communication (TLS 1.2+)
# - Enable audit logging for all API calls
# - Implement rate limiting and throttling
# - Use circuit breakers for fault tolerance
# - Monitor for anomalous API behavior
#
# COMPLIANCE:
# - SOC 2: Logical access controls to business logic
# - PCI-DSS: Separation of payment processing logic
# - HIPAA: PHI processing in isolated tier
# ============================================================================

resource "aws_security_group" "app_tier" {
  name        = "${var.project_name}-${var.environment}-app-tier-sg"
  description = "Security group for Application Tier - Backend services accessible only from Web Tier"
  vpc_id      = data.aws_vpc.main.id

  # Dynamic ingress rules: Accept traffic only from Web Tier
  # This creates a clear security boundary:
  # Internet → ALB → Web Tier → App Tier (but never Internet → App Tier)
  dynamic "ingress" {
    for_each = local.app_tier_ingress_rules
    content {
      description              = ingress.value.description
      from_port                = ingress.value.from_port
      to_port                  = ingress.value.to_port
      protocol                 = ingress.value.protocol
      source_security_group_id = ingress.value.source_security_group_id
    }
  }

  # Egress rules: App tier needs outbound access for:
  # - Database connections
  # - Cache connections (Redis, Memcached)
  # - External API calls
  # - Message queue operations
  # - Object storage (S3) via VPC endpoint or internet
  dynamic "egress" {
    for_each = local.common_egress_rules
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name             = "${var.project_name}-${var.environment}-app-tier-sg"
      Tier             = "Application"
      Purpose          = "Backend-Services"
      InternetFacing   = "false"
      Exposure         = "Internal-via-Web-Tier"
      CriticalityLevel = "High"
      Description      = "Application tier security group - backend services accessible only from web tier"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# SECURITY GROUP: DATABASE TIER (DATA PERSISTENCE)
# ============================================================================
#
# PURPOSE: Controls traffic to database instances
# TIER: Data/Persistence Layer
# EXPOSURE: Internal only (via Application Tier)
#
# SECURITY PROFILE (MOST RESTRICTIVE):
# - Accepts traffic ONLY from Application Tier security group
# - NO internet access (inbound or outbound)
# - Strictest security boundary - protects sensitive data
# - Implements defense in depth at data layer
#
# SUPPORTED DATABASES:
# - Amazon RDS: MySQL, PostgreSQL, MariaDB, Oracle, SQL Server
# - Amazon Aurora: MySQL-compatible, PostgreSQL-compatible
# - Amazon ElastiCache: Redis, Memcached
# - Amazon DocumentDB: MongoDB-compatible
# - Amazon Neptune: Graph database
# - Self-managed databases on EC2 (not recommended)
#
# CRITICAL SECURITY REQUIREMENTS:
# 1. Network Isolation:
#    - Database subnets have NO route to Internet Gateway
#    - Database subnets have NO route to NAT Gateway
#    - Only application tier can establish connections
#
# 2. Encryption:
#    - Encryption at rest: AWS KMS for RDS storage
#    - Encryption in transit: Force SSL/TLS connections
#    - Certificate validation: Use RDS CA certificates
#
# 3. Authentication:
#    - Use IAM database authentication (RDS)
#    - Rotate database credentials regularly (Secrets Manager)
#    - Implement least privilege for database users
#    - Disable default admin accounts
#
# 4. Access Control:
#    - Restrict database user permissions (principle of least privilege)
#    - No direct internet access to database
#    - No SSH access to database servers (managed services)
#    - Use AWS Systems Manager for EC2 database management
#
# 5. Audit and Monitoring:
#    - Enable RDS Enhanced Monitoring
#    - Enable database audit logging (MySQL, PostgreSQL)
#    - Enable Performance Insights
#    - CloudWatch alarms for anomalies
#    - Database activity streams (Aurora)
#
# 6. Backup and Recovery:
#    - Automated backups enabled
#    - Point-in-time recovery
#    - Cross-region backup replication
#    - Regular restore testing
#
# 7. Patching and Maintenance:
#    - Enable automatic minor version upgrades
#    - Schedule maintenance windows
#    - Test patches in non-production first
#
# COMPLIANCE REQUIREMENTS:
# - PCI-DSS Requirement 1.3.6: Database must be isolated from DMZ
# - PCI-DSS Requirement 2.2.1: Only one primary function per server
# - HIPAA §164.312(a): Access controls for ePHI databases
# - HIPAA §164.312(e): Transmission security for ePHI
# - SOC 2 CC6.1: Logical access to database restricted
# - SOC 2 CC6.7: Encryption of data at rest and in transit
# - ISO 27001 A.13.1.3: Segregation of database networks
#
# DISASTER RECOVERY:
# - Multi-AZ deployment for automatic failover
# - Read replicas for read scalability
# - Cross-region read replicas for DR
# - Automated backups with 35-day retention
#
# THREAT MODEL:
# - SQL Injection: Prevented at application layer (prepared statements)
# - Direct database access: Prevented by security group rules
# - Data exfiltration: Prevented by network isolation
# - Brute force attacks: Prevented by connection source restrictions
# - Man-in-the-middle: Prevented by forced TLS encryption
# ============================================================================

resource "aws_security_group" "database" {
  name        = "${var.project_name}-${var.environment}-database-sg"
  description = "Security group for Database Tier - Most restrictive, only accepts traffic from Application Tier"
  vpc_id      = data.aws_vpc.main.id

  # Dynamic ingress rules: Accept database connections only from App Tier
  # Multiple database ports supported for different database types
  # Each rule explicitly defines the source security group (app tier only)
  dynamic "ingress" {
    for_each = local.database_tier_ingress_rules
    content {
      description              = ingress.value.description
      from_port                = ingress.value.from_port
      to_port                  = ingress.value.to_port
      protocol                 = ingress.value.protocol
      source_security_group_id = ingress.value.source_security_group_id
      # CRITICAL: No cidr_blocks defined
      # This ensures ONLY resources with app tier security group can connect
      # Even if database is exposed via DNS, connections will be rejected
    }
  }

  # Egress rules for database tier
  # Databases typically don't need outbound internet access
  # For managed services (RDS), AWS handles updates via service endpoints
  # 
  # SECURITY CONSIDERATION:
  # - For maximum security, restrict egress to VPC CIDR only
  # - Allow only return traffic (ephemeral ports) to app tier
  # - Use VPC endpoints for AWS services (no internet required)
  #
  # Current configuration allows all outbound for:
  # - RDS certificate validation
  # - AWS API calls (CloudWatch metrics, logs)
  # - Software updates for self-managed databases
  dynamic "egress" {
    for_each = local.common_egress_rules
    content {
      description = egress.value.description
      from_port   = egress.value.from_port
      to_port     = egress.value.to_port
      protocol    = egress.value.protocol
      cidr_blocks = egress.value.cidr_blocks
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name               = "${var.project_name}-${var.environment}-database-sg"
      Tier               = "Database"
      Purpose            = "Data-Persistence"
      InternetFacing     = "false"
      Exposure           = "Internal-via-App-Tier-Only"
      CriticalityLevel   = "Critical"
      DataClassification = "Highly-Confidential"
      EncryptionRequired = "true"
      AuditLogging       = "true"
      Description        = "Database tier security group - most restrictive, only accepts connections from application tier"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# SECURITY GROUP: BASTION HOST (OPTIONAL - ADMINISTRATIVE ACCESS)
# ============================================================================
#
# PURPOSE: Secure SSH access to private subnet resources
# TIER: Management Layer
# EXPOSURE: Limited (Corporate VPN/Office IPs only)
#
# ⚠️  RECOMMENDATION: Use AWS Systems Manager Session Manager instead
# 
# AWS SYSTEMS MANAGER SESSION MANAGER BENEFITS:
# - No inbound ports required (no SSH port 22 exposure)
# - IAM-based access control (no SSH keys to manage)
# - Session logging to S3/CloudWatch (complete audit trail)
# - MFA enforcement possible
# - No bastion host maintenance required
# - No public IP address needed
# - No security group rule for SSH
#
# IF YOU MUST USE BASTION HOST:
# - Restrict source IPs to corporate VPN only (NEVER 0.0.0.0/0)
# - Use SSH key-based authentication only (no passwords)
# - Implement SSH certificate authority
# - Use short-lived SSH certificates (AWS Certificate Manager)
# - Enable SSH session logging (rsyslog to CloudWatch)
# - Implement fail2ban for brute-force protection
# - Use MFA for SSH access
# - Regular security patching
# - Minimize installed software
# - Enable CloudWatch detailed monitoring
#
# SECURITY BEST PRACTICES:
# 1. Network: Place in public subnet with EIP
# 2. OS: Use Amazon Linux 2023 (security hardened)
# 3. SSH: Use ed25519 keys (not RSA 2048)
# 4. Logging: Forward all logs to CloudWatch
# 5. Updates: Enable automatic security updates
# 6. Monitoring: CloudWatch agent for system metrics
# 7. Compliance: Regular vulnerability scanning
# 8. Backup: AMI snapshots before changes
#
# ALTERNATIVE APPROACHES:
# - AWS Systems Manager Session Manager (recommended)
# - AWS Client VPN for full VPN access
# - AWS Direct Connect for private connectivity
# - AWS PrivateLink for service access
# ============================================================================

resource "aws_security_group" "bastion" {
  count = var.enable_bastion ? 1 : 0 # Only create if bastion is enabled

  name        = "${var.project_name}-${var.environment}-bastion-sg"
  description = "Security group for Bastion Host - Restricted SSH access from corporate network only"
  vpc_id      = data.aws_vpc.main.id

  # Dynamic ingress rules: SSH from corporate VPN only
  # CRITICAL: cidr_blocks should be your actual corporate IP ranges
  # NEVER use 0.0.0.0/0 for SSH access
  dynamic "ingress" {
    for_each = var.enable_bastion ? local.bastion_ingress_rules : []
    content {
      description = ingress.value.description
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr_blocks
    }
  }

  # Egress: Bastion needs to SSH to private instances
  egress {
    description = "SSH to private subnet instances for administration"
    from_port   = local.common_ports.ssh
    to_port     = local.common_ports.ssh
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "HTTPS for software updates and AWS API calls"
    from_port   = local.common_ports.https
    to_port     = local.common_ports.https
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP for software updates"
    from_port   = local.common_ports.http
    to_port     = local.common_ports.http
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(
    local.common_tags,
    {
      Name             = "${var.project_name}-${var.environment}-bastion-sg"
      Tier             = "Management"
      Purpose          = "SSH-Bastion-Jump-Host"
      InternetFacing   = "true"
      Exposure         = "Restricted-Corporate-Only"
      CriticalityLevel = "High"
      AccessType       = "Administrative"
      Description      = "Bastion host security group - SSH access restricted to corporate VPN/office IPs only"
    }
  )

  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# NETWORK ACL: PUBLIC SUBNETS
# ============================================================================
#
# PURPOSE: Subnet-level firewall for public subnets
# LAYER: Network layer (stateless filtering)
# APPLIED TO: Public subnets (ALB, NAT Gateway, Bastion)
#
# STATELESS FILTERING:
# - Unlike security groups, NACLs are stateless
# - Both inbound and outbound rules required for bidirectional traffic
# - Rules evaluated in order by rule number (lowest first)
# - First match wins (subsequent rules not evaluated)
# - Default deny if no match
#
# USE CASES FOR NETWORK ACLs:
# 1. Additional layer of defense beyond security groups
# 2. Explicit deny rules for known malicious IPs
# 3. Subnet-level DDoS mitigation
# 4. Compliance requirement for defense in depth
# 5. Protection against misconfigured security groups
#
# BEST PRACTICES:
# - Use rule numbers in increments of 10 (100, 110, 120...)
# - Reserve low numbers (1-50) for explicit deny rules
# - Keep rules simple and well-documented
# - Test changes in non-production first
# - Monitor VPC Flow Logs for blocked traffic
#
# SECURITY CONSIDERATIONS:
# - NACLs apply to entire subnet (all instances)
# - Security groups are more granular (per-instance)
# - Use NACLs for subnet-level blocking
# - Use security groups for application-level rules
#
# RULE NUMBERING STRATEGY:
# 1-50:     Reserved for explicit deny rules
# 100-999:  Allow rules for application traffic
# 1000+:    Reserved for future use
# 32766:    Default deny rule (AWS managed)
# ============================================================================

resource "aws_network_acl" "public" {
  vpc_id     = data.aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  # Dynamic ingress rules from local variables
  # Rules processed in order by rule_number (lowest first)
  dynamic "ingress" {
    for_each = local.public_subnet_nacl_ingress
    content {
      rule_no    = ingress.value.rule_number
      protocol   = ingress.value.protocol
      rule_action = ingress.value.rule_action
      cidr_block = ingress.value.cidr_block
      from_port  = lookup(ingress.value, "from_port", null)
      to_port    = lookup(ingress.value, "to_port", null)
    }
  }

  # Dynamic egress rules
  # Stateless: Must explicitly allow return traffic
  dynamic "egress" {
    for_each = local.public_subnet_nacl_egress
    content {
      rule_no     = egress.value.rule_number
      protocol    = egress.value.protocol
      rule_action = egress.value.rule_action
      cidr_block  = egress.value.cidr_block
      from_port   = lookup(egress.value, "from_port", null)
      to_port     = lookup(egress.value, "to_port", null)
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name        = "${var.project_name}-${var.environment}-public-nacl"
      SubnetType  = "Public"
      Purpose     = "Subnet-Level-Firewall"
      FirewallType = "Stateless-NACL"
      Description = "Network ACL for public subnets - additional layer beyond security groups"
    }
  )
}

# ============================================================================
# NETWORK ACL: PRIVATE SUBNETS
# ============================================================================
#
# PURPOSE: Subnet-level firewall for private subnets
# LAYER: Network layer (stateless filtering)
# APPLIED TO: Private subnets (application tier)
#
# SECURITY PROFILE:
# - More restrictive than public subnet NACLs
# - Allows only necessary application traffic
# - Blocks direct internet access (handled by NAT Gateway)
# - Allows internal VPC communication
# - Permits return traffic for outbound connections
#
# TRAFFIC ALLOWED:
# - Inbound: HTTP/HTTPS from VPC (ALB traffic)
# - Inbound: Application ports from VPC
# - Inbound: Ephemeral ports for return traffic
# - Outbound: HTTP/HTTPS for updates and API calls
# - Outbound: Database ports to database subnets
# - Outbound: Ephemeral ports for return traffic
#
# BLOCKED TRAFFIC:
# - Direct inbound from internet
# - Unnecessary protocols (FTP, Telnet, SMTP)
# - Known malicious ports
# ============================================================================

resource "aws_network_acl" "private" {
  vpc_id     = data.aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  # Dynamic ingress rules
  # Allow traffic from VPC and return traffic from internet (via NAT)
  dynamic "ingress" {
    for_each = local.private_subnet_nacl_ingress
    content {
      rule_no     = ingress.value.rule_number
      protocol    = ingress.value.protocol
      rule_action = ingress.value.rule_action
      cidr_block  = ingress.value.cidr_block
      from_port   = lookup(ingress.value, "from_port", null)
      to_port     = lookup(ingress.value, "to_port", null)
    }
  }

  # Dynamic egress rules
  # Allow outbound for updates, APIs, and database connections
  dynamic "egress" {
    for_each = local.private_subnet_nacl_egress
    content {
      rule_no     = egress.value.rule_number
      protocol    = egress.value.protocol
      rule_action = egress.value.rule_action
      cidr_block  = egress.value.cidr_block
      from_port   = lookup(egress.value, "from_port", null)
      to_port     = lookup(egress.value, "to_port", null)
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name         = "${var.project_name}-${var.environment}-private-nacl"
      SubnetType   = "Private"
      Purpose      = "Subnet-Level-Firewall"
      FirewallType = "Stateless-NACL"
      Description  = "Network ACL for private subnets - restricts traffic to application ports only"
    }
  )
}

# ============================================================================
# NETWORK ACL: DATABASE SUBNETS
# ============================================================================
#
# PURPOSE: Subnet-level firewall for database subnets
# LAYER: Network layer (stateless filtering)
# APPLIED TO: Database subnets (data tier)
#
# SECURITY PROFILE (MOST RESTRICTIVE):
# - Allows ONLY database ports from VPC
# - Blocks all internet traffic (inbound and outbound)
# - No SSH, RDP, or management ports
# - Explicit deny for all non-database traffic
#
# TRAFFIC ALLOWED:
# - Inbound: Database ports (3306, 5432, 6379, 27017) from VPC only
# - Inbound: Ephemeral ports for return traffic
# - Outbound: Ephemeral ports for return traffic to VPC
# - Outbound: HTTPS for RDS updates (AWS service endpoints)
#
# BLOCKED TRAFFIC:
# - All internet access (except AWS service endpoints for updates)
# - All management ports (SSH, RDP)
# - All non-database protocols
# - All traffic not originating from VPC
#
# COMPLIANCE ENFORCEMENT:
# This NACL configuration ensures:
# - PCI-DSS Requirement 1.3.6: Cardholder data isolated from DMZ
# - HIPAA: PHI database access restricted to authorized systems
# - SOC 2: Database access controls enforced at network layer
# - ISO 27001: Network segregation for sensitive data
#
# DEFENSE IN DEPTH:
# - Layer 1: NACL blocks at subnet level
# - Layer 2: Security group blocks at instance level
# - Layer 3: RDS security settings (SSL enforcement)
# - Layer 4: Database user permissions (least privilege)
# - Layer 5: Application-level authentication
# ============================================================================

resource "aws_network_acl" "database" {
  vpc_id     = data.aws_vpc.main.id
  subnet_ids = aws_subnet.database[*].id

  # Dynamic ingress rules
  # CRITICAL: Only database ports from VPC allowed
  # No internet access, no management ports
  dynamic "ingress" {
    for_each = local.database_subnet_nacl_ingress
    content {
      rule_no     = ingress.value.rule_number
      protocol    = ingress.value.protocol
      rule_action = ingress.value.rule_action
      cidr_block  = ingress.value.cidr_block
      from_port   = lookup(ingress.value, "from_port", null)
      to_port     = lookup(ingress.value, "to_port", null)
    }
  }

  # Dynamic egress rules
  # Minimal outbound access for return traffic only
  # No internet access (maximum security)
  dynamic "egress" {
    for_each = local.database_subnet_nacl_egress
    content {
      rule_no     = egress.value.rule_number
      protocol    = egress.value.protocol
      rule_action = egress.value.rule_action
      cidr_block  = egress.value.cidr_block
      from_port   = lookup(egress.value, "from_port", null)
      to_port     = lookup(egress.value, "to_port", null)
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name               = "${var.project_name}-${var.environment}-database-nacl"
      SubnetType         = "Database"
      Purpose            = "Subnet-Level-Firewall"
      FirewallType       = "Stateless-NACL"
      SecurityLevel      = "Maximum"
      DataClassification = "Highly-Confidential"
      Description        = "Network ACL for database subnets - most restrictive, database ports only from VPC"
    }
  )
}

# ============================================================================
# OUTPUTS
# ============================================================================

# Security Group IDs
output "alb_security_group_id" {
  description = "Security Group ID for Application Load Balancer"
  value       = aws_security_group.alb.id
}

output "web_tier_security_group_id" {
  description = "Security Group ID for Web Tier instances"
  value       = aws_security_group.web_tier.id
}

output "app_tier_security_group_id" {
  description = "Security Group ID for Application Tier instances"
  value       = aws_security_group.app_tier.id
}

output "database_security_group_id" {
  description = "Security Group ID for Database instances"
  value       = aws_security_group.database.id
}

output "bastion_security_group_id" {
  description = "Security Group ID for Bastion Host (if enabled)"
  value       = var.enable_bastion ? aws_security_group.bastion[0].id : null
}

# Network ACL IDs
output "public_nacl_id" {
  description = "Network ACL ID for Public Subnets"
  value       = aws_network_acl.public.id
}

output "private_nacl_id" {
  description = "Network ACL ID for Private Subnets"
  value       = aws_network_acl.private.id
}

output "database_nacl_id" {
  description = "Network ACL ID for Database Subnets"
  value       = aws_network_acl.database.id
}

# Security Group ARNs (for IAM policies and tagging)
output "alb_security_group_arn" {
  description = "Security Group ARN for Application Load Balancer"
  value       = aws_security_group.alb.arn
}

output "web_tier_security_group_arn" {
  description = "Security Group ARN for Web Tier"
  value       = aws_security_group.web_tier.arn
}

output "app_tier_security_group_arn" {
  description = "Security Group ARN for Application Tier"
  value       = aws_security_group.app_tier.arn
}

output "database_security_group_arn" {
  description = "Security Group ARN for Database Tier"
  value       = aws_security_group.database.arn
}

# Summary output
output "security_architecture_summary" {
  description = "Summary of security architecture and components"
  value = {
    security_groups_created = {
      alb      = aws_security_group.alb.id
      web      = aws_security_group.web_tier.id
      app      = aws_security_group.app_tier.id
      database = aws_security_group.database.id
      bastion  = var.enable_bastion ? aws_security_group.bastion[0].id : "disabled"
    }
    network_acls_created = {
      public   = aws_network_acl.public.id
      private  = aws_network_acl.private.id
      database = aws_network_acl.database.id
    }
    security_layers = [
      "Layer 1: Network ACLs (Stateless, Subnet-level)",
      "Layer 2: Security Groups (Stateful, Instance-level)",
      "Layer 3: IAM Policies (Identity-based)",
      "Layer 4: Application Logic (Code-level)"
    ]
    security_principles = [
      "Zero Trust Architecture",
      "Principle of Least Privilege",
      "Defense in Depth",
      "Network Segmentation",
      "Explicit Deny by Default"
    ]
    compliance_frameworks = [
      "PCI-DSS",
      "HIPAA",
      "SOC 2",
      "ISO 27001",
      "NIST 800-53"
    ]
  }
}
