# ============================================================================
# TERRAFORM VARIABLES DEFINITION
# ============================================================================
# 
# This file defines all input variables for the enterprise VPC configuration.
# Variables allow for flexible, reusable infrastructure code across environments.
#
# USAGE:
# - Create a terraform.tfvars file to set these values
# - Use -var="variable_name=value" CLI flag
# - Set environment variables: TF_VAR_variable_name
# ============================================================================

# ============================================================================
# AWS REGION CONFIGURATION
# ============================================================================

variable "aws_region" {
  description = "AWS region where resources will be created. Choose a region close to your users for lower latency."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = can(regex("^[a-z]{2}-[a-z]+-[0-9]{1}$", var.aws_region))
    error_message = "AWS region must be a valid region code (e.g., us-east-1, eu-west-1)."
  }
}

# ============================================================================
# VPC NETWORK CONFIGURATION
# ============================================================================

variable "vpc_cidr" {
  description = <<-EOT
    CIDR block for the VPC. This defines the IP address range for the entire VPC.
    
    RECOMMENDATIONS:
    - Use RFC 1918 private address space: 10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16
    - Minimum /16 for production VPCs (65,536 IP addresses)
    - Allow room for future growth and subnet expansion
    - Avoid overlapping with on-premises networks or other VPCs
    
    EXAMPLES:
    - 10.0.0.0/16  - 65,536 IPs (most common for production)
    - 172.16.0.0/16 - 65,536 IPs (alternative if 10.0.0.0 is in use)
    - 192.168.0.0/16 - 65,536 IPs (typically for smaller deployments)
  EOT
  type        = string
  default     = "10.0.0.0/16"

  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR block must be a valid IPv4 CIDR notation (e.g., 10.0.0.0/16)."
  }

  validation {
    condition     = tonumber(split("/", var.vpc_cidr)[1]) <= 16
    error_message = "VPC CIDR block must be /16 or larger to accommodate subnets across multiple AZs."
  }
}

# ============================================================================
# PROJECT IDENTIFICATION
# ============================================================================

variable "project_name" {
  description = <<-EOT
    Project name used for resource naming and tagging.
    This helps identify resources belonging to the same project/application.
    
    BEST PRACTICES:
    - Use lowercase letters, numbers, and hyphens only
    - Keep it short and meaningful (e.g., 'ecommerce', 'analytics', 'api-gateway')
    - Avoid special characters that may cause issues in resource names
  EOT
  type        = string
  default     = "enterprise-app"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_name))
    error_message = "Project name must contain only lowercase letters, numbers, and hyphens."
  }

  validation {
    condition     = length(var.project_name) <= 30
    error_message = "Project name must be 30 characters or less to avoid resource name length limits."
  }
}

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

variable "environment" {
  description = <<-EOT
    Environment name for this infrastructure deployment.
    Used for resource naming, tagging, and environment-specific configurations.
    
    STANDARD ENVIRONMENTS:
    - dev: Development environment for active development
    - staging: Pre-production environment for testing
    - prod: Production environment for live traffic
    
    SECURITY NOTE:
    - Production environments should use stricter security policies
    - Consider separate AWS accounts for production isolation
  EOT
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod", "test", "qa"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod, test, qa."
  }
}

# ============================================================================
# COST ALLOCATION AND MANAGEMENT
# ============================================================================

variable "cost_center" {
  description = <<-EOT
    Cost center or department responsible for this infrastructure.
    Used for AWS cost allocation tags and billing reports.
    
    EXAMPLES:
    - Engineering, Marketing, Sales, IT, Operations
    - Department codes: ENG-001, MKT-002, IT-003
    
    BENEFIT:
    - Track cloud spending by department
    - Generate detailed cost reports
    - Enable chargeback or showback models
  EOT
  type        = string
  default     = "Engineering"
}

variable "owner_email" {
  description = <<-EOT
    Email address of the infrastructure owner/team.
    Used for resource tagging and incident notification.
    
    BEST PRACTICE:
    - Use team/group email, not individual email
    - Ensures continuity when team members change
    - Examples: devops@company.com, platform-team@company.com
  EOT
  type        = string
  default     = "devops@example.com"

  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.owner_email))
    error_message = "Owner email must be a valid email address format."
  }
}

# ============================================================================
# ADDITIONAL TAGS
# ============================================================================

variable "additional_tags" {
  description = <<-EOT
    Additional custom tags to apply to all resources.
    Useful for organization-specific tagging requirements.
    
    EXAMPLES:
    {
      "BusinessUnit" = "Digital Platform"
      "Application"  = "Customer Portal"
      "CostCode"     = "CC-12345"
      "DataClassification" = "Confidential"
    }
  EOT
  type        = map(string)
  default     = {}
}

# ============================================================================
# HIGH AVAILABILITY CONFIGURATION
# ============================================================================

variable "enable_nat_gateway_per_az" {
  description = <<-EOT
    Enable one NAT Gateway per Availability Zone for high availability.
    
    COST vs. AVAILABILITY TRADEOFF:
    - true:  High availability, no single point of failure (~$96/month for 3 AZs)
    - false: Single NAT Gateway, cost savings (~$32/month), but single point of failure
    
    RECOMMENDATION:
    - Production: true (high availability required)
    - Development/Testing: false (cost savings acceptable)
  EOT
  type        = bool
  default     = true
}

variable "enable_dns_hostnames" {
  description = <<-EOT
    Enable DNS hostnames in the VPC.
    Instances will receive public DNS hostnames if they have public IP addresses.
    
    WHEN TO ENABLE:
    - Required for AWS services that use DNS (RDS, ElastiCache, etc.)
    - Recommended for most production workloads
    - Simplifies instance identification and management
  EOT
  type        = bool
  default     = true
}

variable "enable_dns_support" {
  description = <<-EOT
    Enable DNS resolution in the VPC.
    Allows resources to resolve AWS service endpoints and custom DNS names.
    
    CRITICAL FOR:
    - AWS service endpoints (S3, DynamoDB, etc.)
    - Private Route 53 hosted zones
    - Cross-VPC DNS resolution via Route 53 Resolver
  EOT
  type        = bool
  default     = true
}

# ============================================================================
# VPC FLOW LOGS CONFIGURATION
# ============================================================================

variable "enable_flow_logs" {
  description = <<-EOT
    Enable VPC Flow Logs for network traffic monitoring and security analysis.
    
    SECURITY BENEFITS:
    - Network forensics and troubleshooting
    - Detect unusual traffic patterns
    - Compliance requirements (PCI-DSS, HIPAA, SOC 2)
    
    COST CONSIDERATION:
    - S3 storage costs for log data
    - Data ingestion charges
    - Typically $10-50/month depending on traffic volume
  EOT
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = <<-EOT
    Number of days to retain VPC Flow Logs before deletion.
    Adjust based on compliance requirements.
    
    COMPLIANCE REQUIREMENTS:
    - PCI-DSS: 90 days minimum
    - HIPAA: 6 years for certain data
    - SOC 2: Typically 1 year
    - GDPR: Varies by organization's data retention policy
  EOT
  type        = number
  default     = 365

  validation {
    condition     = var.flow_logs_retention_days >= 30
    error_message = "Flow logs retention must be at least 30 days for security and compliance."
  }
}

# ============================================================================
# SUBNET CONFIGURATION
# ============================================================================

variable "single_nat_gateway" {
  description = <<-EOT
    Use a single NAT Gateway for all private subnets instead of one per AZ.
    
    WARNING: This creates a single point of failure and is NOT recommended for production.
    
    USE CASES:
    - Development/testing environments
    - Cost-sensitive deployments
    - Non-critical workloads
    
    PRODUCTION RECOMMENDATION: Set to false
  EOT
  type        = bool
  default     = false
}

variable "map_public_ip_on_launch" {
  description = <<-EOT
    Auto-assign public IP addresses to instances launched in public subnets.
    
    SECURITY CONSIDERATION:
    - Convenient for public-facing resources
    - Can be overridden at instance launch
    - Consider using Elastic IPs for static addressing
  EOT
  type        = bool
  default     = true
}
