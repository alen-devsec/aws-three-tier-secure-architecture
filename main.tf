# ============================================================================
# MAIN.TF - ENTERPRISE AWS INFRASTRUCTURE ORCHESTRATION
# ============================================================================
#
# PURPOSE:
# --------
# This file serves as the "brain" of the entire Terraform infrastructure
# deployment. It orchestrates all components including networking, compute,
# security, monitoring, and data storage across a multi-tier AWS architecture.
#
# ARCHITECTURAL OVERVIEW:
# -----------------------
# This infrastructure implements a highly available, secure, and scalable
# cloud architecture following AWS Well-Architected Framework principles:
#
#   ┌─────────────────────────────────────────────────────────────────┐
#   │                    INTERNET / END USERS                         │
#   └──────────────────────────┬──────────────────────────────────────┘
#                              │
#                              ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  AWS ROUTE 53 (DNS) - CloudFront CDN (Optional)                │
#   └──────────────────────────┬──────────────────────────────────────┘
#                              │
#                              ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  APPLICATION LOAD BALANCER (Multi-AZ, HTTPS/TLS 1.2+)         │
#   │  - SSL Termination                                             │
#   │  - Health Checks                                               │
#   │  - AWS WAF Integration                                         │
#   └──────────────────────────┬──────────────────────────────────────┘
#                              │
#         ┌────────────────────┴────────────────────┐
#         │                                         │
#         ▼                                         ▼
#   ┌─────────────────┐                    ┌─────────────────┐
#   │  WEB TIER       │                    │  WEB TIER       │
#   │  Auto Scaling   │                    │  Auto Scaling   │
#   │  Private Subnet │                    │  Private Subnet │
#   │  AZ-1           │                    │  AZ-2/AZ-3      │
#   └────────┬────────┘                    └────────┬────────┘
#            │                                      │
#            └──────────────────┬───────────────────┘
#                               │
#                               ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  APPLICATION TIER (Backend APIs, Business Logic)               │
#   │  - Auto Scaling Groups                                         │
#   │  - Private Subnets (Multi-AZ)                                  │
#   │  - Microservices Architecture                                  │
#   └──────────────────────────┬──────────────────────────────────────┘
#                              │
#                              ▼
#   ┌─────────────────────────────────────────────────────────────────┐
#   │  DATA TIER (Databases, Caching, Message Queues)                │
#   │  - RDS Multi-AZ (PostgreSQL/MySQL)                             │
#   │  - ElastiCache (Redis/Memcached)                               │
#   │  - Database Subnets (NO Internet Access)                       │
#   │  - Encrypted at Rest (KMS) and in Transit (TLS)                │
#   └─────────────────────────────────────────────────────────────────┘
#
# INFRASTRUCTURE COMPONENTS MANAGED BY THIS CONFIGURATION:
# ---------------------------------------------------------
# 1. NETWORKING (network.tf)
#    - VPC with DNS support
#    - Public, Private, and Database subnets across 3 AZs
#    - Internet Gateway for public internet access
#    - NAT Gateways (one per AZ) for private subnet internet access
#    - Route Tables with appropriate routing rules
#    - VPC Flow Logs for network traffic monitoring
#
# 2. SECURITY (security_groups.tf)
#    - Security Groups for ALB, Web Tier, App Tier, Database
#    - Network ACLs for additional subnet-level security
#    - Zero-trust architecture with tier-based isolation
#    - Encryption at rest and in transit
#
# 3. COMPUTE (instances.tf)
#    - Application Load Balancer with HTTPS/TLS
#    - Launch Templates with encrypted EBS volumes
#    - Auto Scaling Groups with CPU-based policies
#    - IAM roles and instance profiles
#    - CloudWatch monitoring and logging
#
# 4. OUTPUTS (outputs.tf)
#    - Comprehensive resource identifiers
#    - Connection endpoints
#    - Infrastructure summary
#
# COMPLIANCE AND SECURITY FRAMEWORKS SUPPORTED:
# ----------------------------------------------
# - PCI-DSS: Payment Card Industry Data Security Standard
# - HIPAA: Health Insurance Portability and Accountability Act
# - SOC 2: Service Organization Control 2
# - ISO 27001: Information Security Management
# - GDPR: General Data Protection Regulation
# - NIST 800-53: Security and Privacy Controls
# - CIS AWS Foundations Benchmark
#
# INTEGRATION WITH OTHER TERRAFORM FILES:
# ----------------------------------------
# This main.tf file provides:
# - Terraform version requirements and provider configuration
# - Remote state backend configuration for team collaboration
# - AWS provider with default tags applied to all resources
# - Data sources for account information and region details
# - Local variables for consistent resource naming
# - Foundation for all other .tf files to build upon
#
# FILES IN THIS TERRAFORM PROJECT:
# --------------------------------
# - main.tf              : This file - Core Terraform configuration
# - variables.tf         : Input variable definitions
# - outputs.tf           : Output value definitions
# - network.tf           : VPC, subnets, routing, NAT gateways
# - security_groups.tf   : Security groups and NACLs
# - instances.tf         : EC2, ALB, ASGs, Launch Templates
# - instances_variables.tf: Compute-specific variables
# - security_variables.tf: Security-specific variables
# - terraform.tfvars     : Actual variable values (NOT in Git)
# - .gitignore          : Excludes sensitive files from Git
# - README.md           : Project documentation
#
# TERRAFORM WORKFLOW:
# -------------------
# 1. Initialize:  terraform init
# 2. Validate:    terraform validate
# 3. Plan:        terraform plan -out=tfplan
# 4. Review:      Review tfplan output carefully
# 5. Apply:       terraform apply tfplan
# 6. Verify:      Check AWS Console and test endpoints
# 7. Document:    Update documentation with outputs
#
# DISASTER RECOVERY AND BACKUP:
# ------------------------------
# - Infrastructure as Code: All infrastructure is version controlled
# - State File Backup: Stored in S3 with versioning enabled
# - Multi-AZ Deployment: Automatic failover across availability zones
# - Automated Snapshots: EBS and RDS snapshots enabled
# - Cross-Region Replication: Consider for DR (future enhancement)
#
# MAINTENANCE AND OPERATIONS:
# ---------------------------
# - State Lock: DynamoDB table prevents concurrent modifications
# - Change Management: All changes via Terraform (no manual changes)
# - Version Control: Git workflow with pull request reviews
# - Testing: Changes tested in dev/staging before production
# - Monitoring: CloudWatch alarms for all critical resources
# - Incident Response: Runbooks for common scenarios
#
# COST OPTIMIZATION:
# ------------------
# - Right-sized Instances: Auto Scaling based on actual demand
# - Reserved Instances: Consider for predictable workloads
# - Spot Instances: Consider for non-critical batch processing
# - S3 Lifecycle Policies: Archive old logs to Glacier
# - NAT Gateway Optimization: VPC Endpoints for AWS services
# - Regular Cost Reviews: AWS Cost Explorer and Trusted Advisor
#
# ============================================================================

# ============================================================================
# TERRAFORM CONFIGURATION BLOCK
# ============================================================================
#
# This block defines the minimum Terraform version required and the
# required providers with their version constraints.
#
# TERRAFORM VERSION MANAGEMENT:
# -----------------------------
# Specifying minimum Terraform version ensures:
# - Consistency: All team members use compatible Terraform versions
# - Feature Availability: Required features/syntax are available
# - Stability: Avoid bugs in older versions
# - Security: Ensure security patches are applied
# - Compliance: Some compliance standards require version management
#
# VERSION CONSTRAINT SYNTAX:
# --------------------------
# - >= 1.5.0  : Minimum version (allows 1.5.0, 1.5.1, 1.6.0, 2.0.0, etc.)
# - ~> 5.0    : Pessimistic constraint (allows 5.0.x, 5.1.x, but not 6.0.0)
# - = 1.5.0   : Exact version (not recommended - too restrictive)
# - >= 1.5.0, < 2.0.0 : Range (allows 1.5.0 through 1.x.x)
#
# WHY TERRAFORM 1.5.0+?
# ---------------------
# - Configuration-driven import: Manage existing resources
# - Improved error messages: Better debugging experience
# - Enhanced state management: More reliable state operations
# - Performance improvements: Faster plan and apply operations
# - Security enhancements: Better secret handling
#
# PROVIDER VERSION CONSTRAINTS:
# ------------------------------
# AWS Provider ~> 5.0 means:
# - Allows: 5.0.x, 5.1.x, 5.2.x, etc.
# - Blocks: 6.0.0 and above (major version changes)
# - Ensures: Compatible API and resource definitions
# - Benefits: Receives bug fixes and new features within major version
#
# BEST PRACTICES:
# ---------------
# ✓ Always specify required_version to prevent version drift
# ✓ Use pessimistic constraints (~>) for providers
# ✓ Test provider upgrades in dev/staging first
# ✓ Document breaking changes when upgrading
# ✓ Use .terraform.lock.hcl to lock exact provider versions
# ✓ Commit .terraform.lock.hcl to version control
#
# ============================================================================

terraform {
  # Minimum Terraform version required for this configuration
  # Using >= ensures any version from 1.5.0 onwards is acceptable
  # 1.5.0 introduced several critical features we rely on
  required_version = ">= 1.5.0"

  # Required providers with version constraints
  # Terraform will download and install these providers during 'terraform init'
  required_providers {
    # AWS Provider - Primary cloud provider for this infrastructure
    aws = {
      source  = "hashicorp/aws"  # Official AWS provider from HashiCorp
      version = "~> 5.0"          # Allow 5.x.x versions (not 6.0+)
      
      # Provider Capabilities:
      # - Manages 1000+ AWS resources
      # - Handles authentication and API calls
      # - Supports all AWS regions
      # - Implements AWS API best practices
      # - Provides data sources for existing resources
    }

    # Random Provider - Generates random values for resource naming
    # Useful for creating unique identifiers when needed
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }

    # TLS Provider - Manages TLS private keys and certificates
    # Used for SSH keys, certificates, and cryptographic operations
    # tls = {
    #   source  = "hashicorp/tls"
    #   version = "~> 4.0"
    # }

    # Local Provider - Manages local files and resources
    # Useful for generating configuration files from templates
    # local = {
    #   source  = "hashicorp/local"
    #   version = "~> 2.4"
    # }

    # Null Provider - Implements provisioners and lifecycle operations
    # Used for executing local commands or scripts
    # null = {
    #   source  = "hashicorp/null"
    #   version = "~> 3.2"
    # }
  }

  # ============================================================================
  # TERRAFORM BACKEND CONFIGURATION (REMOTE STATE MANAGEMENT)
  # ============================================================================
  #
  # CRITICAL FOR PRODUCTION: Remote backend stores Terraform state file remotely
  # instead of locally, enabling team collaboration and state locking.
  #
  # WHY REMOTE STATE IS ESSENTIAL FOR DEVSECOPS:
  # ---------------------------------------------
  # 
  # 1. COLLABORATION:
  #    - Multiple engineers can work on infrastructure simultaneously
  #    - Shared state ensures everyone sees the same infrastructure state
  #    - Eliminates "works on my machine" state file issues
  #    - Central source of truth for infrastructure state
  #
  # 2. STATE LOCKING (via DynamoDB):
  #    - Prevents concurrent Terraform operations
  #    - Avoids race conditions and state corruption
  #    - Ensures only one person can modify infrastructure at a time
  #    - Protects against destructive simultaneous changes
  #
  # 3. ENCRYPTION & SECURITY:
  #    - State file contains sensitive data (IDs, IPs, passwords)
  #    - S3 encryption at rest protects secrets
  #    - IAM policies control who can read/write state
  #    - Audit trail via CloudTrail for compliance
  #
  # 4. VERSIONING & DISASTER RECOVERY:
  #    - S3 versioning enables state file recovery
  #    - Rollback to previous state if corruption occurs
  #    - Historical record of infrastructure changes
  #    - Backup and restore capabilities
  #
  # 5. COMPLIANCE & GOVERNANCE:
  #    - Centralized state meets compliance requirements
  #    - Audit trail for SOC 2, ISO 27001, HIPAA
  #    - Access control and logging
  #    - Disaster recovery documentation
  #
  # 6. CI/CD INTEGRATION:
  #    - Enables automated Terraform runs in pipelines
  #    - GitLab CI, GitHub Actions, Jenkins can access state
  #    - Consistent state across deployment stages
  #    - Automated testing and validation
  #
  # BACKEND CONFIGURATION COMPONENTS:
  # ----------------------------------
  # - bucket: S3 bucket name for state storage
  # - key: Path within bucket (e.g., env/prod/terraform.tfstate)
  # - region: AWS region where S3 bucket resides
  # - encrypt: Enable server-side encryption (AES-256)
  # - dynamodb_table: DynamoDB table for state locking
  # - acl: Access control list (private recommended)
  # - kms_key_id: Optional KMS key for encryption
  #
  # SETUP REQUIREMENTS:
  # -------------------
  # Before uncommenting this backend configuration, you must:
  #
  # 1. Create S3 Bucket:
  #    aws s3api create-bucket \
  #      --bucket terraform-state-mycompany-prod \
  #      --region us-east-1 \
  #      --create-bucket-configuration LocationConstraint=us-east-1
  #
  # 2. Enable Versioning:
  #    aws s3api put-bucket-versioning \
  #      --bucket terraform-state-mycompany-prod \
  #      --versioning-configuration Status=Enabled
  #
  # 3. Enable Encryption:
  #    aws s3api put-bucket-encryption \
  #      --bucket terraform-state-mycompany-prod \
  #      --server-side-encryption-configuration '{
  #        "Rules": [{
  #          "ApplyServerSideEncryptionByDefault": {
  #            "SSEAlgorithm": "AES256"
  #          }
  #        }]
  #      }'
  #
  # 4. Block Public Access:
  #    aws s3api put-public-access-block \
  #      --bucket terraform-state-mycompany-prod \
  #      --public-access-block-configuration \
  #        BlockPublicAcls=true,\
  #        IgnorePublicAcls=true,\
  #        BlockPublicPolicy=true,\
  #        RestrictPublicBuckets=true
  #
  # 5. Create DynamoDB Table:
  #    aws dynamodb create-table \
  #      --table-name terraform-state-lock \
  #      --attribute-definitions AttributeName=LockID,AttributeType=S \
  #      --key-schema AttributeName=LockID,KeyType=HASH \
  #      --billing-mode PAY_PER_REQUEST \
  #      --region us-east-1
  #
  # 6. Initial Migration:
  #    - First, deploy with local state (backend commented out)
  #    - Then, uncomment backend and run: terraform init -migrate-state
  #    - Confirm migration when prompted
  #    - Verify state in S3 bucket
  #
  # STATE FILE SECURITY:
  # --------------------
  # - NEVER commit terraform.tfstate to Git
  # - Add *.tfstate* to .gitignore
  # - Use IAM roles, not access keys for authentication
  # - Enable MFA Delete on S3 bucket
  # - Encrypt state with customer-managed KMS key (optional)
  # - Restrict S3 bucket access with IAM policies
  # - Enable CloudTrail logging for S3 bucket
  # - Regular backup verification
  #
  # TROUBLESHOOTING STATE LOCK:
  # ---------------------------
  # If state is locked and operation failed:
  #   terraform force-unlock <LOCK_ID>
  # 
  # Warning: Only force unlock if you're certain no other operation is running!
  #
  # COST CONSIDERATIONS:
  # --------------------
  # - S3 Storage: ~$0.023/GB/month (negligible for state files)
  # - S3 Requests: ~$0.005 per 1000 requests
  # - DynamoDB: Pay-per-request (pennies per month)
  # - Total Cost: Usually under $5/month for most deployments
  #
  # ============================================================================

  # IMPORTANT: Uncomment this backend block after initial deployment
  # and after setting up the S3 bucket and DynamoDB table
  #
  # backend "s3" {
  #   # S3 Bucket Configuration
  #   bucket = "terraform-state-mycompany-prod"
  #   
  #   # State File Path within Bucket
  #   # Recommended naming: <project>/<environment>/terraform.tfstate
  #   # Example: myapp/production/terraform.tfstate
  #   key = "infrastructure/production/terraform.tfstate"
  #   
  #   # AWS Region where S3 bucket is located
  #   # Must match the region where you created the bucket
  #   region = "us-east-1"
  #   
  #   # Enable Server-Side Encryption
  #   # Uses AES-256 encryption (AWS-managed keys)
  #   # For additional security, specify kms_key_id for KMS encryption
  #   encrypt = true
  #   
  #   # DynamoDB Table for State Locking
  #   # Prevents concurrent Terraform operations
  #   # Table must have a primary key named "LockID" (string type)
  #   dynamodb_table = "terraform-state-lock"
  #   
  #   # Access Control List
  #   # "private" ensures only authorized users can access state
  #   # acl = "private"
  #   
  #   # Optional: Use customer-managed KMS key for encryption
  #   # kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
  #   
  #   # Optional: Add additional tags to state file in S3
  #   # tags = {
  #   #   Name        = "Terraform State"
  #   #   Environment = "Production"
  #   #   Managed_By  = "Terraform"
  #   # }
  #   
  #   # Workspace Prefix (for Terraform workspaces)
  #   # workspace_key_prefix = "workspaces"
  #   
  #   # Skip Metadata API Check (for restricted environments)
  #   # skip_metadata_api_check = false
  #   
  #   # Skip Region Validation (advanced use cases only)
  #   # skip_region_validation = false
  # }

  # MIGRATION STEPS FROM LOCAL TO REMOTE STATE:
  # --------------------------------------------
  # 1. Ensure infrastructure is deployed with local state
  # 2. Create S3 bucket and DynamoDB table (see setup instructions above)
  # 3. Uncomment the backend block above
  # 4. Run: terraform init -migrate-state
  # 5. Type "yes" when prompted to migrate state
  # 6. Verify state file appears in S3 bucket
  # 7. Delete local terraform.tfstate file
  # 8. Test: Run terraform plan to ensure remote state works
  #
  # MULTI-ENVIRONMENT STRATEGY:
  # ---------------------------
  # Option 1: Separate State Files per Environment
  #   - dev:     infrastructure/development/terraform.tfstate
  #   - staging: infrastructure/staging/terraform.tfstate
  #   - prod:    infrastructure/production/terraform.tfstate
  #
  # Option 2: Terraform Workspaces (Single State with Namespaces)
  #   - terraform workspace new production
  #   - terraform workspace new staging
  #   - terraform workspace select production
  #
  # Recommendation: Separate state files for better isolation
}

# ============================================================================
# AWS PROVIDER CONFIGURATION
# ============================================================================
#
# The AWS provider is responsible for understanding AWS API interactions
# and managing AWS resources. This configuration block sets up authentication,
# region, and default resource tagging.
#
# PROVIDER CONFIGURATION BEST PRACTICES:
# ---------------------------------------
# 
# 1. AUTHENTICATION METHODS (in order of preference):
#    
#    a) IAM Role (RECOMMENDED for EC2, ECS, Lambda, CodeBuild):
#       - No credentials in code
#       - Automatic credential rotation
#       - Fine-grained permissions via IAM policies
#       - Audit trail via CloudTrail
#       Usage: Just specify region, AWS SDK finds credentials automatically
#    
#    b) AWS_PROFILE Environment Variable (for local development):
#       - Uses credentials from ~/.aws/credentials
#       - Supports multiple profiles for different accounts
#       - Safe for local development
#       Usage: export AWS_PROFILE=mycompany-prod
#    
#    c) Environment Variables (for CI/CD):
#       - AWS_ACCESS_KEY_ID
#       - AWS_SECRET_ACCESS_KEY
#       - AWS_SESSION_TOKEN (if using STS)
#       Usage: Set in CI/CD pipeline secrets
#    
#    d) Shared Credentials File:
#       - Default: ~/.aws/credentials
#       - Can specify custom path with shared_credentials_file
#    
#    ⚠️  NEVER HARDCODE CREDENTIALS IN TERRAFORM CODE ⚠️
#
# 2. REGION MANAGEMENT:
#    - Use variable for flexibility across environments
#    - Different regions for DR (Disaster Recovery)
#    - Consider data residency requirements (GDPR, etc.)
#    - Pricing varies by region
#
# 3. DEFAULT TAGS (CRITICAL FOR GOVERNANCE):
#    - Applied automatically to ALL resources
#    - Enables cost allocation and tracking
#    - Supports compliance and auditing
#    - Facilitates resource management and cleanup
#    - Required for many enterprise environments
#
# DEFAULT TAGS EXPLAINED:
# -----------------------
# Tags are key-value pairs attached to AWS resources for:
# - Cost Allocation: Track spending by project, environment, team
# - Resource Management: Find and manage related resources
# - Automation: Trigger actions based on tags
# - Security: Enforce tag-based policies
# - Compliance: Meet regulatory tagging requirements
#
# COMMON TAG STRATEGIES:
# ----------------------
# - Environment: dev, staging, prod
# - Project/Application: myapp, backend, frontend
# - Owner: team-devops, john.doe@company.com
# - Cost Center: engineering, marketing, sales
# - Managed By: terraform, cloudformation, manual
# - Backup: daily, weekly, none
# - Security Level: public, internal, confidential, restricted
# - Compliance: pci-dss, hipaa, sox, gdpr
# - Data Classification: public, internal, confidential, restricted
#
# TAG ENFORCEMENT:
# ----------------
# AWS Organizations Service Control Policies (SCPs) can enforce:
# - Required tags on resource creation
# - Tag value restrictions
# - Tag immutability
# - Automated compliance checks
#
# ============================================================================

provider "aws" {
  # AWS Region - Use variable for flexibility
  # Region determines:
  # - Where resources are physically located
  # - Available services and features
  # - Pricing (varies by region)
  # - Data residency compliance
  # - Network latency to users
  region = var.aws_region

  # AWS Profile (for local development with multiple AWS accounts)
  # Uncomment if using AWS CLI profiles:
  # profile = var.aws_profile

  # Assume Role Configuration (for cross-account access)
  # Uncomment if Terraform needs to assume a role:
  # assume_role {
  #   role_arn     = "arn:aws:iam::123456789012:role/TerraformDeploymentRole"
  #   session_name = "TerraformSession"
  #   external_id  = "unique-external-id"
  # }

  # Shared Credentials File (custom location)
  # Default is ~/.aws/credentials
  # shared_credentials_file = "/path/to/credentials"

  # Maximum Retries for AWS API calls
  # Helps with rate limiting and transient failures
  # max_retries = 3

  # Skip Metadata API Check (for restricted networks)
  # skip_metadata_api_check = false

  # Skip Region Validation (advanced use cases)
  # skip_region_validation = false

  # Skip Requesting Account ID (performance optimization)
  # skip_requesting_account_id = false

  # ============================================================================
  # DEFAULT TAGS - AUTOMATICALLY APPLIED TO ALL RESOURCES
  # ============================================================================
  #
  # Default tags are THE MOST IMPORTANT governance feature in Terraform.
  # They are automatically applied to every AWS resource created, ensuring
  # consistent tagging across your entire infrastructure.
  #
  # BUSINESS VALUE OF COMPREHENSIVE TAGGING:
  # ----------------------------------------
  # 
  # 1. COST MANAGEMENT & ALLOCATION:
  #    - Track AWS spending by project, team, environment
  #    - Allocate costs to correct cost centers
  #    - Identify cost optimization opportunities
  #    - Generate chargeback/showback reports
  #    Example: "How much does the production environment cost per month?"
  #    Answer: Filter AWS Cost Explorer by Environment=prod tag
  #
  # 2. RESOURCE DISCOVERY & MANAGEMENT:
  #    - Find all resources belonging to a project
  #    - Identify orphaned resources
  #    - Bulk operations on tagged resources
  #    - Automated cleanup of development resources
  #    Example: Delete all resources tagged Environment=dev after 30 days
  #
  # 3. SECURITY & COMPLIANCE:
  #    - Enforce security policies based on tags
  #    - Audit resource ownership
  #    - Data classification and handling
  #    - Compliance reporting (SOC 2, ISO 27001)
  #    Example: Encrypt all resources tagged SecurityLevel=high
  #
  # 4. AUTOMATION & ORCHESTRATION:
  #    - Trigger backup policies based on tags
  #    - Schedule instance start/stop
  #    - Disaster recovery automation
  #    - Monitoring and alerting rules
  #    Example: Backup all resources tagged Backup=daily
  #
  # 5. CHANGE MANAGEMENT & OPERATIONS:
  #    - Track who created/manages resources
  #    - Infrastructure as Code verification
  #    - Prevent manual changes to managed resources
  #    - Audit trail and accountability
  #    Example: Alert on resources not tagged ManagedBy=terraform
  #
  # TAG NAMING CONVENTIONS:
  # -----------------------
  # - Use PascalCase or snake_case consistently
  # - Be descriptive but concise
  # - Avoid special characters
  # - Document tag meanings
  # - Establish company-wide standards
  #
  # REQUIRED VS OPTIONAL TAGS:
  # --------------------------
  # Required (enforced via policy):
  # - Project, Environment, Owner, ManagedBy
  # 
  # Recommended:
  # - CostCenter, SecurityLevel, Backup, DataClassification
  #
  # Optional:
  # - Team, CreatedDate, ExpirationDate, Compliance
  #
  # TAG LIMITATIONS (AWS):
  # ----------------------
  # - Maximum 50 tags per resource
  # - Key: Max 128 characters
  # - Value: Max 256 characters
  # - Case sensitive
  # - Some characters not allowed: <, >, &, "
  #
  # ============================================================================

  default_tags {
    tags = {
      # Project Identifier
      # Purpose: Identify which application/project this resource belongs to
      # Use Case: Cost allocation, resource discovery, multi-project accounts
      # Example: "ecommerce-platform", "data-analytics", "mobile-backend"
      Project = var.project_name

      # Environment Identifier
      # Purpose: Distinguish between dev, staging, and production resources
      # Use Case: Prevents accidental deletion, different security policies
      # Common Values: dev, development, staging, uat, prod, production
      # Note: Lowercase for consistency with AWS conventions
      Environment = var.environment

      # Owner Information
      # Purpose: Identify responsible team or individual
      # Use Case: Contact for issues, cost allocation, access requests
      # Format: Team name or email address
      # Example: "devops-team", "platform-engineering", "john.doe@company.com"
      Owner = var.owner_email

      # Management Method
      # Purpose: Indicate how resource is managed (prevents manual changes)
      # Use Case: Automation, change management, compliance
      # Common Values: Terraform, CloudFormation, Manual, Ansible
      # Note: "Terraform" indicates this resource should only be changed via Terraform
      ManagedBy = "Terraform"

      # Security Classification
      # Purpose: Data sensitivity level for security policies
      # Use Case: Encryption requirements, access controls, compliance
      # Common Values: Public, Internal, Confidential, Restricted
      # Example: "Restricted" for PII/PHI, "Public" for marketing site
      SecurityLevel = var.security_level

      # Cost Center / Department
      # Purpose: Financial allocation and chargeback
      # Use Case: Budget tracking, cost allocation by department
      # Example: "Engineering", "Marketing", "IT-OPS", "DEPT-12345"
      CostCenter = var.cost_center

      # Compliance Scope
      # Purpose: Identify regulatory requirements
      # Use Case: Audit reporting, compliance automation
      # Common Values: PCI-DSS, HIPAA, SOC2, ISO27001, GDPR, None
      # Example: "PCI-DSS-HIPAA" for multi-compliance requirements
      ComplianceScope = var.compliance_scope

      # Infrastructure as Code Repository
      # Purpose: Link to source code repository
      # Use Case: Traceability, documentation, change management
      # Example: "github.com/mycompany/aws-infrastructure"
      Repository = var.repository_url

      # Backup Policy
      # Purpose: Backup schedule and retention
      # Use Case: Disaster recovery automation, backup tool configuration
      # Common Values: Daily, Weekly, Monthly, None
      # Example: "Daily-30day-retention"
      # BackupPolicy = var.backup_policy

      # Data Classification
      # Purpose: Data sensitivity and handling requirements
      # Use Case: DLP policies, encryption requirements, access controls
      # Common Values: Public, Internal, Confidential, Restricted, PII, PHI
      # DataClassification = var.data_classification

      # Created Date (for resource lifecycle management)
      # Purpose: Track resource age for cleanup policies
      # Use Case: Delete resources older than X days in dev/staging
      # Format: ISO 8601 (YYYY-MM-DD)
      CreatedDate = formatdate("YYYY-MM-DD", timestamp())

      # Terraform Version (for compatibility tracking)
      # Purpose: Know which Terraform version created this resource
      # Use Case: Troubleshooting, upgrade planning
      # TerraformVersion = "1.5.0"

      # Additional tags can be merged from variables
      # This allows environment-specific or project-specific tags
    }
  }

  # ============================================================================
  # PROVIDER FEATURES & CAPABILITIES
  # ============================================================================
  #
  # The AWS provider supports advanced features:
  #
  # 1. CUSTOM ENDPOINTS (for AWS China, GovCloud, LocalStack):
  #    endpoints {
  #      ec2 = "https://ec2.us-gov-west-1.amazonaws.com"
  #      s3  = "https://s3.us-gov-west-1.amazonaws.com"
  #    }
  #
  # 2. CUSTOM USER AGENT (for tracking Terraform usage):
  #    custom_user_agent = "TerraformEnterprise/1.0"
  #
  # 3. ALLOWED ACCOUNT IDs (prevent accidental deployment to wrong account):
  #    allowed_account_ids = ["123456789012", "210987654321"]
  #
  # 4. FORBIDDEN ACCOUNT IDs (explicitly block certain accounts):
  #    forbidden_account_ids = ["999999999999"]
  #
  # 5. IGNORE TAGS (don't track certain tags in state):
  #    ignore_tags {
  #      keys         = ["LastModified", "UpdatedBy"]
  #      key_prefixes = ["kubernetes.io/"]
  #    }
  #
  # ============================================================================
}

# Additional Provider Alias (for multi-region deployment)
# Useful for disaster recovery, global applications, or service-specific regions
# Example: CloudFront requires ACM certificates in us-east-1
#
# provider "aws" {
#   alias  = "us_east_1"
#   region = "us-east-1"
#   
#   # Inherits default_tags from main provider
# }
#
# Usage in resources:
# resource "aws_acm_certificate" "cloudfront" {
#   provider = aws.us_east_1
#   # ... certificate configuration
# }

# Provider for DR (Disaster Recovery) region
# Uncomment for cross-region replication, backups, or DR setup
#
# provider "aws" {
#   alias  = "dr_region"
#   region = var.dr_region
#   
#   default_tags {
#     tags = merge(
#       provider::aws::default_tags,
#       {
#         Region = "DR"
#         Purpose = "Disaster-Recovery"
#       }
#     )
#   }
# }

# ============================================================================
# DATA SOURCES - CONTEXTUAL INFORMATION ABOUT AWS ENVIRONMENT
# ============================================================================
#
# Data sources allow Terraform to fetch information about existing resources
# or account details without managing them. This provides context about the
# environment where infrastructure is being deployed.
#
# WHY DATA SOURCES ARE IMPORTANT:
# --------------------------------
# 
# 1. DYNAMIC CONFIGURATION:
#    - Adapt to different AWS accounts automatically
#    - No hardcoded account IDs or region information
#    - Works across dev/staging/prod accounts seamlessly
#
# 2. EXISTING RESOURCE INTEGRATION:
#    - Reference resources created outside Terraform
#    - Connect to pre-existing networking, VPCs, subnets
#    - Use existing IAM roles, security groups
#
# 3. ENVIRONMENT AWARENESS:
#    - Know which AWS account you're deploying to
#    - Detect available Availability Zones
#    - Identify region-specific AMIs and services
#
# 4. SECURITY & COMPLIANCE:
#    - Validate deployment to correct AWS account
#    - Use account ID in IAM policies and resource ARNs
#    - Ensure region compliance (data residency)
#
# 5. DOCUMENTATION & OUTPUTS:
#    - Display account and region in outputs
#    - Include in resource naming for clarity
#    - Helpful for troubleshooting and support
#
# COMMON DATA SOURCES:
# --------------------
# - aws_caller_identity: Who am I? (Account ID, User ID, ARN)
# - aws_region: Where am I? (Region name and details)
# - aws_availability_zones: What AZs are available?
# - aws_ami: Find latest AMI matching criteria
# - aws_vpc: Reference existing VPC
# - aws_subnet: Reference existing subnet
# - aws_security_group: Reference existing security group
# - aws_iam_policy_document: Generate IAM policy JSON
#
# ============================================================================

# ----------------------------------------------------------------------------
# Data Source: AWS Caller Identity
# ----------------------------------------------------------------------------
#
# Retrieves information about the AWS identity (account) making the API calls.
# This is the AWS account where resources will be created.
#
# RETURNED ATTRIBUTES:
# --------------------
# - account_id: 12-digit AWS account ID (e.g., "123456789012")
# - arn: ARN of the calling identity
#   Example: "arn:aws:iam::123456789012:user/terraform-deploy"
# - user_id: Unique identifier for the calling entity
#   Example: "AIDAI..." for IAM user, "AROA..." for assumed role
#
# USE CASES:
# ----------
# 1. Resource Naming: Include account ID in S3 bucket names
#    bucket = "myapp-logs-${data.aws_caller_identity.current.account_id}"
#
# 2. IAM Policies: Reference account in ARNs
#    arn:aws:s3:::mybucket-${data.aws_caller_identity.current.account_id}/*
#
# 3. Cross-Account Access: Verify account for trust policies
#    "AWS": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
#
# 4. Validation: Ensure deployment to correct account
#    lifecycle {
#      precondition {
#        condition     = data.aws_caller_identity.current.account_id == "123456789012"
#        error_message = "Must deploy to production account"
#      }
#    }
#
# 5. Tagging: Include account ID in resource tags
#    tags = { AccountID = data.aws_caller_identity.current.account_id }
#
# SECURITY CONSIDERATIONS:
# ------------------------
# - No sensitive data exposed (account ID is not secret)
# - Helps prevent cross-account resource creation mistakes
# - Essential for multi-account AWS Organizations
#
# PERFORMANCE:
# ------------
# - Cached after first retrieval
# - No impact on plan/apply performance
# - Single API call per Terraform run
#
data "aws_caller_identity" "current" {
  # No configuration required
  # This data source requires no inputs and is always available
}

# ----------------------------------------------------------------------------
# Data Source: AWS Region
# ----------------------------------------------------------------------------
#
# Retrieves information about the AWS region configured in the provider.
# Provides region name, description, and endpoint information.
#
# RETURNED ATTRIBUTES:
# --------------------
# - name: Short region name (e.g., "us-east-1", "eu-west-1")
# - description: Human-readable description
#   Example: "US East (N. Virginia)", "Europe (Ireland)"
# - endpoint: Regional endpoint URL
#   Example: "ec2.us-east-1.amazonaws.com"
#
# USE CASES:
# ----------
# 1. Resource Naming: Include region in resource names
#    name = "myapp-${data.aws_region.current.name}-alb"
#
# 2. Multi-Region Deployment: Know which region for logs/docs
#    log_group_name = "/aws/lambda/${var.function_name}-${data.aws_region.current.name}"
#
# 3. Region-Specific Configuration: Different settings per region
#    instance_type = data.aws_region.current.name == "us-east-1" ? "t3.large" : "t3.medium"
#
# 4. Compliance: Verify deployment to approved regions
#    lifecycle {
#      precondition {
#        condition     = contains(["us-east-1", "us-west-2"], data.aws_region.current.name)
#        error_message = "Must deploy to approved US regions only"
#      }
#    }
#
# 5. Outputs: Display region in infrastructure summary
#    output "deployed_region" {
#      value = data.aws_region.current.description
#    }
#
# REGION CONSIDERATIONS:
# ----------------------
# - Service availability varies by region
# - Pricing differs across regions (can be significant)
# - Data residency requirements (GDPR, HIPAA)
# - Latency to users (choose region closest to users)
# - Disaster recovery (use different region for DR)
#
data "aws_region" "current" {
  # No configuration required
  # Uses the region from the AWS provider configuration
}

# ----------------------------------------------------------------------------
# Data Source: AWS Availability Zones
# ----------------------------------------------------------------------------
#
# Retrieves list of Availability Zones available in the current region.
# Essential for multi-AZ high availability deployment.
#
# RETURNED ATTRIBUTES:
# --------------------
# - names: List of AZ names (e.g., ["us-east-1a", "us-east-1b", "us-east-1c"])
# - zone_ids: List of AZ IDs (e.g., ["use1-az1", "use1-az2"])
# - group_names: List of AZ group names
#
# FILTERS:
# --------
# - state: "available" (exclude unavailable AZs)
# - opt-in-status: "opt-in-not-required" (exclude Local Zones, Wavelength)
#
# USE CASES:
# ----------
# 1. Subnet Creation: Create subnet in each AZ
#    count             = length(data.aws_availability_zones.available.names)
#    availability_zone = data.aws_availability_zones.available.names[count.index]
#
# 2. Multi-AZ Deployment: Deploy resources across AZs
#    availability_zones = data.aws_availability_zones.available.names
#
# 3. High Availability: Ensure minimum number of AZs
#    lifecycle {
#      precondition {
#        condition     = length(data.aws_availability_zones.available.names) >= 2
#        error_message = "Region must have at least 2 AZs for HA"
#      }
#    }
#
# 4. NAT Gateway: One per AZ for fault tolerance
#    count      = length(data.aws_availability_zones.available.names)
#    subnet_id  = element(aws_subnet.public.*.id, count.index)
#
# 5. Auto Scaling: Distribute instances across AZs
#    vpc_zone_identifier = aws_subnet.private.*.id
#
# AVAILABILITY ZONE CONCEPTS:
# ---------------------------
# - Each AZ is one or more physically separate data centers
# - Low-latency links between AZs in same region
# - Independent power, cooling, and networking
# - Typical region has 2-6 AZs
# - Best practice: Deploy across ≥2 AZs for HA
#
# LOCAL ZONES & WAVELENGTH ZONES:
# --------------------------------
# - Local Zones: Extension of region closer to users
# - Wavelength Zones: AWS services at 5G network edge
# - Filtered out by default (opt-in-status filter)
# - Special use cases only
#
data "aws_availability_zones" "available" {
  # Filter: Only include available AZs
  # This excludes AZs that are temporarily unavailable or restricted
  state = "available"

  # Filter: Exclude Local Zones and Wavelength Zones
  # These are special-purpose zones requiring opt-in
  # Standard AZs have "opt-in-not-required"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }

  # Optional: Exclude specific AZs if needed
  # Some older AZs may have capacity constraints
  # filter {
  #   name   = "zone-name"
  #   values = ["!us-east-1e"]  # Exclude us-east-1e if problematic
  # }
}

# Additional useful data sources (commented out, uncomment as needed):

# Latest Amazon Linux 2023 AMI
# Use this to always get the newest, patched AMI
# data "aws_ami" "amazon_linux_2023" {
#   most_recent = true
#   owners      = ["amazon"]
#   
#   filter {
#     name   = "name"
#     values = ["al2023-ami-*-x86_64"]
#   }
#   
#   filter {
#     name   = "virtualization-type"
#     values = ["hvm"]
#   }
# }

# Existing VPC (if deploying into existing VPC)
# data "aws_vpc" "existing" {
#   id = var.existing_vpc_id
# }

# Existing Subnets (if using pre-existing network)
# data "aws_subnets" "private" {
#   filter {
#     name   = "vpc-id"
#     values = [data.aws_vpc.existing.id]
#   }
#   
#   tags = {
#     Tier = "Private"
#   }
# }

# Route53 Hosted Zone (for DNS management)
# data "aws_route53_zone" "main" {
#   name         = "example.com"
#   private_zone = false
# }

# ACM Certificate (for HTTPS/TLS)
# data "aws_acm_certificate" "main" {
#   domain      = "*.example.com"
#   statuses    = ["ISSUED"]
#   most_recent = true
# }

# ============================================================================
# LOCAL VALUES (COMPUTED VARIABLES)
# ============================================================================
#
# Local values are computed values that can be reused throughout the
# configuration. They are evaluated once and then cached, improving
# performance and reducing duplication.
#
# LOCALS VS VARIABLES:
# --------------------
# Variables:
# - User input (set via tfvars, CLI, environment variables)
# - Can have validation rules
# - Can have defaults
# - Cannot reference other variables in default values
#
# Locals:
# - Computed values (expressions, functions, concatenation)
# - Can reference variables, resources, data sources
# - Cannot be overridden externally
# - Evaluated during plan/apply
#
# WHEN TO USE LOCALS:
# -------------------
# ✓ Complex expressions used multiple times
# ✓ Combining multiple variables into one value
# ✓ Conditional logic that doesn't need to be a variable
# ✓ Standardized naming conventions
# ✓ Tag combinations and merging
# ✓ CIDR calculations and subnet sizing
# ✓ Resource naming patterns
#
# BEST PRACTICES:
# ---------------
# - Use locals for complex computed values
# - Document what each local represents
# - Keep locals simple and readable
# - Use descriptive names (name_prefix vs np)
# - Group related locals together
# - Don't overuse - simple values can stay inline
#
# ============================================================================

locals {
  # ----------------------------------------------------------------------------
  # NAMING CONVENTIONS AND RESOURCE PREFIXES
  # ----------------------------------------------------------------------------
  #
  # Standardized naming ensures:
  # - Resource names are consistent across infrastructure
  # - Easy to identify environment and project
  # - Prevents naming conflicts
  # - Simplifies resource discovery
  # - Supports automation and scripting
  #
  # NAMING PATTERN: {project}-{environment}-{resource-type}
  # Example: myapp-prod-vpc, myapp-staging-alb, myapp-dev-db
  #
  # WHY THIS PATTERN:
  # -----------------
  # - Alphabetical grouping in AWS Console
  # - Clear ownership and environment
  # - Easy filtering and searching
  # - AWS resource name requirements compliant
  # - Compatible with DNS naming (for services like RDS)
  #
  # AWS NAMING RESTRICTIONS:
  # ------------------------
  # - Most resources: 1-255 characters
  # - S3 buckets: 3-63 characters, lowercase, no underscores
  # - RDS identifiers: 1-63 characters, alphanumeric and hyphens
  # - Cannot start or end with hyphen
  # - Some resources require unique names within account/region
  #

  # Standard resource name prefix
  # Used consistently across all resources for standardization
  # Format: {project}-{environment}
  # Example: "myapp-prod", "analytics-staging", "backend-dev"
  name_prefix = "${var.project_name}-${var.environment}"

  # Full resource name pattern (includes resource type)
  # Use this function for creating resource names
  # Example: local.resource_name("vpc") => "myapp-prod-vpc"
  # resource_name = function(type) "${local.name_prefix}-${type}"

  # Region-specific name prefix (for multi-region deployments)
  # Include region in name to avoid conflicts
  # Example: "myapp-prod-us-east-1", "myapp-prod-eu-west-1"
  regional_name_prefix = "${local.name_prefix}-${data.aws_region.current.name}"

  # Account-specific name prefix (for globally unique resources like S3)
  # S3 buckets must be globally unique across all AWS accounts
  # Example: "myapp-prod-logs-123456789012"
  account_name_prefix = "${local.name_prefix}-${data.aws_caller_identity.current.account_id}"

  # Environment suffix for DNS (subdomain structure)
  # Example: prod.myapp.com, staging.myapp.com, dev.myapp.com
  # environment_subdomain = var.environment == "prod" ? "" : "${var.environment}."

  # ----------------------------------------------------------------------------
  # TAG MANAGEMENT AND COMBINATION
  # ----------------------------------------------------------------------------
  #
  # Tags are merged from multiple sources:
  # 1. Default tags (from provider configuration)
  # 2. Common tags (defined here in locals)
  # 3. Resource-specific tags (defined in resource blocks)
  # 4. User-provided tags (from variables)
  #
  # MERGE ORDER (later tags override earlier ones):
  # -----------------------------------------------
  # default_tags → common_tags → resource_tags → var.additional_tags
  #
  # TAG INHERITANCE:
  # ----------------
  # - Provider default_tags: Applied automatically to ALL resources
  # - Local common_tags: Merged into resources explicitly
  # - Resource tags: Specific to individual resources
  # - Additional tags: User-provided via variables
  #
  # TAGGING STRATEGY:
  # -----------------
  # Use default_tags for: Mandatory org-wide tags
  # Use common_tags for: Project/environment-specific tags
  # Use resource tags for: Resource-specific metadata
  # Use additional_tags for: Flexible user customization
  #

  # Common tags applied to most resources
  # Merged with default_tags from provider
  common_tags = {
    # Deployment Information
    DeploymentId      = formatdate("YYYYMMDDhhmmss", timestamp())
    DeployedBy        = "Terraform"
    
    # Infrastructure Context
    InfrastructureType = "Multi-Tier-Web-Application"
    Architecture      = "3-Tier-HA-Auto-Scaling"
    
    # High Availability Indicators
    HighAvailability  = "Enabled"
    MultiAZ           = "true"
    DisasterRecovery  = "Multi-AZ-Failover"
    
    # Network Architecture
    NetworkTier       = "3-Tier-Segmentation"
    NetworkSecurity   = "Zero-Trust-Architecture"
    
    # Monitoring and Operations
    MonitoringEnabled = "true"
    LoggingEnabled    = "true"
    BackupEnabled     = "true"
    
    # Compliance and Security
    EncryptionAtRest     = "KMS-AES256"
    EncryptionInTransit  = "TLS-1.2-Plus"
    SecurityPosture      = "Defense-in-Depth"
    ComplianceFrameworks = join(",", [
      "PCI-DSS",
      "HIPAA",
      "SOC-2",
      "ISO-27001",
      "GDPR"
    ])
  }

  # Resource-specific tag templates
  # Use these for specific resource types that need special tags
  
  # Tags for networking resources (VPC, Subnets, Route Tables)
  network_tags = merge(
    local.common_tags,
    {
      ResourceType = "Network"
      Layer        = "Infrastructure"
    }
  )

  # Tags for compute resources (EC2, ASG, ALB)
  compute_tags = merge(
    local.common_tags,
    {
      ResourceType = "Compute"
      Layer        = "Application"
    }
  )

  # Tags for security resources (Security Groups, NACLs)
  security_tags = merge(
    local.common_tags,
    {
      ResourceType = "Security"
      Layer        = "Protection"
    }
  )

  # Tags for data resources (RDS, ElastiCache, S3)
  data_tags = merge(
    local.common_tags,
    {
      ResourceType       = "Data"
      Layer              = "Persistence"
      DataClassification = "Confidential"
    }
  )

  # ----------------------------------------------------------------------------
  # ENVIRONMENT-SPECIFIC CONFIGURATIONS
  # ----------------------------------------------------------------------------
  #
  # Different settings based on environment (dev/staging/prod)
  # This promotes DRY (Don't Repeat Yourself) principle
  #

  # Environment configuration map
  # Lookup values based on var.environment
  env_config = {
    dev = {
      instance_type        = "t3.small"
      min_size            = 1
      max_size            = 3
      enable_monitoring   = false
      backup_retention    = 7
      multi_az            = false
      deletion_protection = false
    }
    staging = {
      instance_type        = "t3.medium"
      min_size            = 2
      max_size            = 6
      enable_monitoring   = true
      backup_retention    = 14
      multi_az            = true
      deletion_protection = false
    }
    prod = {
      instance_type        = "t3.large"
      min_size            = 3
      max_size            = 10
      enable_monitoring   = true
      backup_retention    = 30
      multi_az            = true
      deletion_protection = true
    }
  }

  # Current environment configuration (lookup from map)
  # Access with: local.current_env_config.instance_type
  current_env_config = local.env_config[var.environment]

  # Boolean flags for environment type
  # Simplifies conditional logic in resources
  is_production = var.environment == "prod" || var.environment == "production"
  is_staging    = var.environment == "staging" || var.environment == "stage"
  is_development = var.environment == "dev" || var.environment == "development"

  # ----------------------------------------------------------------------------
  # NETWORK CIDR CALCULATIONS
  # ----------------------------------------------------------------------------
  #
  # CIDR calculations for automatic subnet creation
  # Uses cidrsubnet() function for clean subnet allocation
  #

  # VPC CIDR block (from variable)
  vpc_cidr = var.vpc_cidr

  # Calculate subnet CIDRs automatically
  # This is a preview - actual calculations in network.tf
  # Using /20 subnets (4,096 IPs each) from /16 VPC (65,536 IPs)
  
  # Public subnets: 10.0.0.0/20, 10.0.16.0/20, 10.0.32.0/20
  # public_subnet_cidrs = [
  #   cidrsubnet(local.vpc_cidr, 4, 0),
  #   cidrsubnet(local.vpc_cidr, 4, 1),
  #   cidrsubnet(local.vpc_cidr, 4, 2),
  # ]

  # ----------------------------------------------------------------------------
  # INTEGRATION WITH OTHER TERRAFORM FILES
  # ----------------------------------------------------------------------------
  #
  # This main.tf provides foundation for:
  #
  # 1. network.tf:
  #    - Uses: local.name_prefix for resource naming
  #    - Uses: local.network_tags for VPC/subnet tagging
  #    - Uses: data.aws_availability_zones for multi-AZ deployment
  #
  # 2. security_groups.tf:
  #    - Uses: local.name_prefix for security group naming
  #    - Uses: local.security_tags for security resource tagging
  #    - Uses: data.aws_caller_identity for IAM policies
  #
  # 3. instances.tf:
  #    - Uses: local.name_prefix for instance naming
  #    - Uses: local.compute_tags for EC2/ASG tagging
  #    - Uses: data.aws_region for regional configurations
  #    - Uses: local.current_env_config for environment-specific settings
  #
  # 4. outputs.tf:
  #    - Uses: data.aws_caller_identity for account information
  #    - Uses: data.aws_region for region information
  #    - Uses: All resources created in other files
  #

  # ----------------------------------------------------------------------------
  # FEATURE FLAGS AND CONDITIONAL LOGIC
  # ----------------------------------------------------------------------------
  #
  # Feature flags control optional infrastructure components
  # Enable/disable features without removing code
  #

  # Enable advanced features for production
  enable_advanced_features = local.is_production

  # Enable enhanced monitoring (detailed CloudWatch metrics)
  enable_detailed_monitoring = local.is_production || local.is_staging

  # Enable deletion protection for critical resources
  enable_deletion_protection = local.is_production

  # Enable cross-region backup for DR
  # enable_cross_region_backup = local.is_production

  # Enable AWS Config for compliance monitoring
  # enable_aws_config = local.is_production || local.is_staging

  # Enable GuardDuty for threat detection
  # enable_guardduty = local.is_production

  # Enable Security Hub for security posture management
  # enable_security_hub = local.is_production

  # ----------------------------------------------------------------------------
  # HELPER FUNCTIONS AND UTILITIES
  # ----------------------------------------------------------------------------

  # Timestamp for resource naming (if needed)
  timestamp = formatdate("YYYYMMDDhhmmss", timestamp())

  # ISO 8601 timestamp for tags
  timestamp_iso = formatdate("YYYY-MM-DD'T'hh:mm:ssZZZ", timestamp())
}

# ============================================================================
# END OF MAIN.TF
# ============================================================================
#
# NEXT STEPS AFTER REVIEWING THIS FILE:
# --------------------------------------
# 
# 1. CUSTOMIZE VARIABLES:
#    - Edit terraform.tfvars with your actual values
#    - Set AWS region, project name, environment
#    - Configure instance sizes and counts
#
# 2. INITIALIZE TERRAFORM:
#    terraform init
#    - Downloads AWS provider
#    - Initializes backend (if configured)
#    - Prepares working directory
#
# 3. VALIDATE CONFIGURATION:
#    terraform validate
#    - Checks syntax and configuration
#    - Ensures all required variables are set
#    - Validates resource dependencies
#
# 4. PLAN DEPLOYMENT:
#    terraform plan -out=tfplan
#    - Shows what will be created/modified/destroyed
#    - Review carefully before applying
#    - Save plan to file for audit trail
#
# 5. APPLY INFRASTRUCTURE:
#    terraform apply tfplan
#    - Creates all resources in AWS
#    - Takes 10-15 minutes for full deployment
#    - Outputs important information (ALB DNS, etc.)
#
# 6. VERIFY DEPLOYMENT:
#    - Check AWS Console for resources
#    - Test ALB endpoint: http://<alb-dns-name>/health
#    - Review CloudWatch Logs
#    - Verify security groups and network config
#
# 7. DOCUMENT INFRASTRUCTURE:
#    terraform output -json > infrastructure-state.json
#    - Export all outputs for documentation
#    - Share with team members
#    - Keep in secure location
#
# 8. SET UP MONITORING:
#    - Configure CloudWatch alarms
#    - Set up SNS notifications
#    - Enable AWS Config (if not automated)
#    - Review VPC Flow Logs
#
# 9. CONFIGURE STATE BACKEND:
#    - Create S3 bucket and DynamoDB table
#    - Uncomment backend block in this file
#    - Run: terraform init -migrate-state
#    - Verify state in S3
#
# 10. ESTABLISH WORKFLOWS:
#     - Set up CI/CD pipeline
#     - Define change approval process
#     - Create disaster recovery runbooks
#     - Schedule regular security reviews
#
# MAINTENANCE CHECKLIST:
# ----------------------
# □ Weekly: Review CloudWatch alarms and logs
# □ Weekly: Check AWS Cost Explorer for cost anomalies
# □ Monthly: Review security groups and NACLs
# □ Monthly: Apply security patches (AMI updates)
# □ Quarterly: Review and update IAM policies
# □ Quarterly: Disaster recovery drill
# □ Annually: Full security audit
# □ Annually: Cost optimization review
#
# TROUBLESHOOTING COMMON ISSUES:
# -------------------------------
# 
# Issue: "Error: Insufficient capacity in AZ"
# Solution: Add/remove AZs in variables, retry deployment
#
# Issue: "Error: InvalidPermissions"
# Solution: Check IAM permissions, ensure Terraform has required access
#
# Issue: "Error: ResourceAlreadyExists"
# Solution: Resource name conflict, adjust name_prefix variable
#
# Issue: "Error: State lock acquisition failed"
# Solution: Wait for other Terraform operation to complete, or force-unlock
#
# Issue: "Plan shows unexpected changes"
# Solution: Check for manual changes in AWS Console, import or remove
#
# SECURITY REMINDERS:
# -------------------
# ⚠️  NEVER commit terraform.tfstate to Git
# ⚠️  NEVER commit terraform.tfvars with secrets to Git
# ⚠️  NEVER hardcode credentials in Terraform files
# ⚠️  ALWAYS use IAM roles instead of access keys
# ⚠️  ALWAYS enable MFA for AWS account access
# ⚠️  ALWAYS encrypt Terraform state (S3 + KMS)
# ⚠️  ALWAYS review terraform plan before apply
# ⚠️  ALWAYS test in dev/staging before production
#
# ============================================================================
# ARCHITECTURAL DECISION RECORDS (ADRs):
# ============================================================================
#
# ADR-001: Use Terraform for Infrastructure as Code
# Decision: All infrastructure managed via Terraform
# Rationale: Version control, repeatability, collaboration
# Alternatives Considered: CloudFormation, CDK, Pulumi, Manual
# Status: Accepted
#
# ADR-002: Multi-AZ Deployment for High Availability
# Decision: Deploy across 3 Availability Zones
# Rationale: 99.99% availability, fault tolerance, compliance
# Alternatives Considered: Single AZ, 2 AZs
# Status: Accepted
#
# ADR-003: Three-Tier Architecture (Web, App, Data)
# Decision: Separate security groups and subnets per tier
# Rationale: Security isolation, least privilege, compliance
# Alternatives Considered: Flat network, two-tier
# Status: Accepted
#
# ADR-004: NAT Gateway per AZ
# Decision: One NAT Gateway in each Availability Zone
# Rationale: High availability, no single point of failure
# Alternatives Considered: Single NAT Gateway, NAT Instance
# Cost Impact: +$64/month for additional 2 NAT Gateways
# Status: Accepted
#
# ADR-005: KMS-Encrypted EBS Volumes
# Decision: All EBS volumes encrypted with customer-managed KMS key
# Rationale: Compliance (HIPAA/PCI-DSS), data protection
# Alternatives Considered: AWS-managed encryption, no encryption
# Status: Accepted
#
# ADR-006: IMDSv2 Enforcement
# Decision: Require IMDSv2 for all EC2 instances
# Rationale: Prevents SSRF attacks, security best practice
# Alternatives Considered: Allow IMDSv1
# Status: Accepted
#
# ADR-007: Auto Scaling Based on CPU Utilization
# Decision: Target 70% CPU utilization with target tracking
# Rationale: Balance performance and cost, industry standard
# Alternatives Considered: Memory-based, request count-based
# Status: Accepted
#
# ============================================================================
# PROJECT METADATA AND CONTACT INFORMATION:
# ============================================================================
#
# Project Name: Enterprise AWS Infrastructure
# Version: 1.0.0
# Last Updated: 2026-02-24
# Maintained By: Platform Engineering Team
# Contact: devops@company.com
# Documentation: https://wiki.company.com/aws-infrastructure
# Repository: https://github.com/company/aws-terraform
# Support: #infrastructure-support (Slack)
# On-Call: PagerDuty - Infrastructure Team
#
# ============================================================================
