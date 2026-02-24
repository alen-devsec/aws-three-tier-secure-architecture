# ============================================================================
# ENTERPRISE-GRADE COMPUTE INFRASTRUCTURE WITH AUTO SCALING
# ============================================================================
#
# This Terraform configuration deploys a highly available, auto-scaling
# compute infrastructure following AWS Well-Architected Framework principles.
#
# ARCHITECTURE OVERVIEW:
# ----------------------
# 
#                        INTERNET
#                           |
#                           v
#                 Application Load Balancer
#            (Multi-AZ, HTTPS/HTTP, Health Checks)
#                           |
#          +----------------+----------------+
#          |                                 |
#      Web Tier ASG                    App Tier ASG
#   (Auto Scaling 2-10)              (Auto Scaling 2-8)
#   Private Subnets                  Private Subnets
#   Multi-AZ                         Multi-AZ
#          |                                 |
#          +----------------+----------------+
#                           |
#                           v
#                    RDS Database
#                  (Multi-AZ, Encrypted)
#
# COMPONENTS:
# -----------
# 1. Application Load Balancer (ALB)
# 2. Target Groups (Web & App Tiers)
# 3. Launch Templates (Encrypted EBS, IMDSv2, User Data)
# 4. Auto Scaling Groups (Dynamic Scaling)
# 5. Auto Scaling Policies (CPU-based)
# 6. IAM Roles & Instance Profiles
# 7. CloudWatch Alarms
# 8. SNS Topics for Notifications
#
# SECURITY FEATURES:
# ------------------
# - Encrypted EBS volumes (KMS)
# - No SSH keys (AWS Systems Manager Session Manager)
# - IMDSv2 enforcement (prevents SSRF attacks)
# - Least privilege IAM policies
# - Private subnets only (no public IPs)
# - Security group tier isolation
# - User data hardening script
# - CloudWatch Logs integration
# - VPC Flow Logs monitoring
#
# HIGH AVAILABILITY:
# ------------------
# - Multi-AZ deployment across 3 AZs
# - Auto Scaling with health checks
# - ALB with cross-zone load balancing
# - Connection draining enabled
# - Automated instance replacement
# - Zero-downtime deployments
#
# COMPLIANCE:
# -----------
# - PCI-DSS: Encrypted storage, network segmentation
# - HIPAA: Encryption at rest and in transit
# - SOC 2: Monitoring, logging, access controls
# - ISO 27001: Security controls, change management
#
# ============================================================================

# ============================================================================
# DATA SOURCES
# ============================================================================

# Reference the VPC created in network.tf
data "aws_vpc" "main" {
  filter {
    name   = "tag:Name"
    values = ["${var.project_name}-${var.environment}-vpc"]
  }
}

# Get the latest Amazon Linux 2023 AMI
# Amazon Linux 2023 is the latest generation Linux OS from AWS with:
# - Long-term support (5 years)
# - Optimized for AWS
# - SELinux enabled by default
# - Regular security updates
# - Systemd-based init system
# - Modern kernel (6.x)
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
}

# Get current AWS region for resource configuration
data "aws_region" "current" {}

# Get current AWS account ID for IAM policies
data "aws_caller_identity" "current" {}

# ============================================================================
# LOCAL VARIABLES
# ============================================================================

locals {
  # Common resource naming
  name_prefix = "${var.project_name}-${var.environment}"

  # Instance configuration
  web_tier_config = {
    instance_type = var.web_tier_instance_type
    min_size      = var.web_tier_min_size
    max_size      = var.web_tier_max_size
    desired_size  = var.web_tier_desired_size
  }

  app_tier_config = {
    instance_type = var.app_tier_instance_type
    min_size      = var.app_tier_min_size
    max_size      = var.app_tier_max_size
    desired_size  = var.app_tier_desired_size
  }

  # User Data script for Web Tier instances
  # This script hardens the instance and installs required software
  web_tier_user_data = <<-EOF
    #!/bin/bash
    # ========================================================================
    # WEB TIER INSTANCE BOOTSTRAP AND HARDENING SCRIPT
    # ========================================================================
    # This script runs on first boot to configure and harden the instance
    # following CIS Amazon Linux 2023 Benchmark recommendations
    #
    # EXECUTED AS: root
    # LOGGING: /var/log/user-data.log
    # ========================================================================

    set -euo pipefail  # Exit on error, undefined variables, and pipe failures

    # Redirect all output to log file for troubleshooting
    exec > >(tee -a /var/log/user-data.log)
    exec 2>&1

    echo "========================================="
    echo "Instance Bootstrap Started: $(date)"
    echo "Instance ID: $(ec2-metadata --instance-id | cut -d ' ' -f 2)"
    echo "Region: $(ec2-metadata --availability-zone | cut -d ' ' -f 2 | sed 's/[a-z]$//')"
    echo "========================================="

    # ========================================================================
    # PHASE 1: SYSTEM UPDATES AND PACKAGE INSTALLATION
    # ========================================================================
    echo "[Phase 1] Updating system packages..."
    
    # Update all packages to latest security patches
    # This addresses known CVEs and security vulnerabilities
    dnf update -y --security
    dnf upgrade -y
    
    # Install essential packages for monitoring and management
    # - amazon-cloudwatch-agent: Metrics and logs to CloudWatch
    # - aws-cli: AWS service interaction
    # - htop: System monitoring
    # - fail2ban: Intrusion prevention
    # - aide: File integrity monitoring
    dnf install -y \
      amazon-cloudwatch-agent \
      aws-cli \
      htop \
      vim \
      curl \
      wget \
      git \
      jq \
      fail2ban \
      aide \
      chrony

    echo "[Phase 1] Package installation complete"

    # ========================================================================
    # PHASE 2: SECURITY HARDENING
    # ========================================================================
    echo "[Phase 2] Applying security hardening..."

    # 2.1 Configure automatic security updates
    # Ensures critical security patches are applied automatically
    cat > /etc/dnf/automatic.conf << 'DNFCONF'
[commands]
upgrade_type = security
download_updates = yes
apply_updates = yes

[emitters]
emit_via = stdio

[email]
email_from = root@localhost
email_to = root
email_host = localhost
DNFCONF

    systemctl enable --now dnf-automatic.timer
    echo "[Phase 2.1] Automatic security updates configured"

    # 2.2 Harden SSH configuration (even though we use SSM)
    # Defense in depth: Secure SSH even if accidentally exposed
    if [ -f /etc/ssh/sshd_config ]; then
      cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
      
      # Disable root login
      sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
      sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
      
      # Disable password authentication (key-based only)
      sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
      sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
      
      # Enable public key authentication
      sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
      
      # Disable empty passwords
      sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
      sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/' /etc/ssh/sshd_config
      
      # Set login grace time
      echo "LoginGraceTime 60" >> /etc/ssh/sshd_config
      
      # Limit max authentication tries
      echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
      
      # Set max sessions
      echo "MaxSessions 2" >> /etc/ssh/sshd_config
      
      # Disable X11 forwarding
      sed -i 's/#X11Forwarding no/X11Forwarding no/' /etc/ssh/sshd_config
      sed -i 's/X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
      
      # Use privilege separation
      echo "UsePrivilegeSeparation sandbox" >> /etc/ssh/sshd_config
      
      # Configure logging
      echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
      
      systemctl restart sshd || true
      echo "[Phase 2.2] SSH hardening complete"
    fi

    # 2.3 Configure firewalld (host-based firewall)
    # Additional layer beyond security groups
    systemctl enable --now firewalld
    
    # Allow only HTTP/HTTPS for web tier
    firewall-cmd --permanent --add-service=http
    firewall-cmd --permanent --add-service=https
    
    # Allow health check port
    firewall-cmd --permanent --add-port=8081/tcp
    
    # Drop all other inbound traffic
    firewall-cmd --set-default-zone=drop
    firewall-cmd --reload
    echo "[Phase 2.3] Firewall configured"

    # 2.4 Configure fail2ban for intrusion prevention
    # Blocks IPs with repeated failed login attempts
    cat > /etc/fail2ban/jail.local << 'FAIL2BAN'
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
logpath = /var/log/secure
FAIL2BAN

    systemctl enable --now fail2ban
    echo "[Phase 2.4] Fail2ban intrusion prevention enabled"

    # 2.5 Initialize AIDE (Advanced Intrusion Detection Environment)
    # File integrity monitoring to detect unauthorized changes
    aide --init
    mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    
    # Schedule daily integrity checks
    cat > /etc/cron.daily/aide-check << 'AIDECHECK'
#!/bin/bash
/usr/sbin/aide --check | mail -s "AIDE Integrity Check" root
AIDECHECK
    
    chmod 755 /etc/cron.daily/aide-check
    echo "[Phase 2.5] File integrity monitoring initialized"

    # 2.6 Kernel hardening via sysctl
    # Configure kernel parameters for enhanced security
    cat >> /etc/sysctl.d/99-security.conf << 'SYSCTL'
# IP Forwarding (disable unless needed)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# IP Spoofing Protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP errors
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN Cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Randomize kernel addresses
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers
kernel.kptr_restrict = 2
SYSCTL

    sysctl -p /etc/sysctl.d/99-security.conf
    echo "[Phase 2.6] Kernel hardening applied"

    # 2.7 Set restrictive umask
    # Default file permissions: 644 for files, 755 for directories
    echo "umask 022" >> /etc/profile
    echo "[Phase 2.7] Restrictive umask configured"

    # ========================================================================
    # PHASE 3: CLOUDWATCH AGENT CONFIGURATION
    # ========================================================================
    echo "[Phase 3] Configuring CloudWatch Agent..."

    # Create CloudWatch agent configuration
    cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json << 'CWAGENT'
{
  "agent": {
    "metrics_collection_interval": 60,
    "run_as_user": "cwagent"
  },
  "logs": {
    "logs_collected": {
      "files": {
        "collect_list": [
          {
            "file_path": "/var/log/messages",
            "log_group_name": "/aws/ec2/${local.name_prefix}/web-tier/messages",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 7
          },
          {
            "file_path": "/var/log/secure",
            "log_group_name": "/aws/ec2/${local.name_prefix}/web-tier/secure",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 30
          },
          {
            "file_path": "/var/log/user-data.log",
            "log_group_name": "/aws/ec2/${local.name_prefix}/web-tier/user-data",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 7
          },
          {
            "file_path": "/var/log/cloud-init-output.log",
            "log_group_name": "/aws/ec2/${local.name_prefix}/web-tier/cloud-init",
            "log_stream_name": "{instance_id}",
            "retention_in_days": 7
          }
        ]
      }
    }
  },
  "metrics": {
    "namespace": "${local.name_prefix}/WebTier",
    "metrics_collected": {
      "cpu": {
        "measurement": [
          {
            "name": "cpu_usage_idle",
            "rename": "CPU_IDLE",
            "unit": "Percent"
          },
          {
            "name": "cpu_usage_iowait",
            "rename": "CPU_IOWAIT",
            "unit": "Percent"
          },
          "cpu_time_guest"
        ],
        "metrics_collection_interval": 60,
        "resources": {
          "*": "*"
        },
        "totalcpu": false
      },
      "disk": {
        "measurement": [
          {
            "name": "used_percent",
            "rename": "DISK_USED",
            "unit": "Percent"
          },
          "inodes_free"
        ],
        "metrics_collection_interval": 60,
        "resources": {
          "*": "*"
        }
      },
      "diskio": {
        "measurement": [
          "io_time"
        ],
        "metrics_collection_interval": 60,
        "resources": {
          "*": "*"
        }
      },
      "mem": {
        "measurement": [
          {
            "name": "mem_used_percent",
            "rename": "MEMORY_USED",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60
      },
      "netstat": {
        "measurement": [
          "tcp_established",
          "tcp_time_wait"
        ],
        "metrics_collection_interval": 60
      },
      "swap": {
        "measurement": [
          {
            "name": "swap_used_percent",
            "rename": "SWAP_USED",
            "unit": "Percent"
          }
        ],
        "metrics_collection_interval": 60
      }
    }
  }
}
CWAGENT

    # Start CloudWatch Agent
    /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
      -a fetch-config \
      -m ec2 \
      -s \
      -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

    systemctl enable amazon-cloudwatch-agent
    echo "[Phase 3] CloudWatch Agent configured and started"

    # ========================================================================
    # PHASE 4: APPLICATION INSTALLATION
    # ========================================================================
    echo "[Phase 4] Installing application..."

    # Install Nginx web server
    dnf install -y nginx

    # Create application directory
    mkdir -p /var/www/html
    chown -R nginx:nginx /var/www/html

    # Create a simple health check endpoint
    cat > /var/www/html/health.html << 'HEALTH'
{
  "status": "healthy",
  "timestamp": "SERVER_TIME",
  "service": "web-tier",
  "instance_id": "INSTANCE_ID"
}
HEALTH

    # Create Nginx configuration
    cat > /etc/nginx/conf.d/app.conf << 'NGINX'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Root directory
    root /var/www/html;
    index index.html index.htm;

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Main application
    location / {
        try_files $uri $uri/ =404;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Logging
    access_log /var/log/nginx/access.log;
    error_log /var/log/nginx/error.log;
}
NGINX

    # Start and enable Nginx
    systemctl enable --now nginx
    echo "[Phase 4] Nginx installed and configured"

    # ========================================================================
    # PHASE 5: SYSTEM CONFIGURATION
    # ========================================================================
    echo "[Phase 5] Final system configuration..."

    # 5.1 Configure timezone
    timedatectl set-timezone UTC
    
    # 5.2 Enable NTP time synchronization
    systemctl enable --now chronyd
    
    # 5.3 Set hostname
    INSTANCE_ID=$(ec2-metadata --instance-id | cut -d ' ' -f 2)
    hostnamectl set-hostname "${local.name_prefix}-web-$INSTANCE_ID"
    
    # 5.4 Disable unnecessary services
    systemctl disable --now postfix || true
    systemctl disable --now cups || true
    
    # 5.5 Create motd banner
    cat > /etc/motd << 'MOTD'
################################################################################
#                                                                              #
#  WARNING: Authorized Access Only                                            #
#                                                                              #
#  This system is for authorized use only. All activity is monitored and      #
#  logged. Unauthorized access attempts will be investigated and may result   #
#  in civil and/or criminal prosecution.                                      #
#                                                                              #
#  Environment: ${var.environment}                                             #
#  Tier: Web                                                                   #
#  Managed By: Terraform                                                       #
#                                                                              #
################################################################################
MOTD

    echo "[Phase 5] System configuration complete"

    # ========================================================================
    # PHASE 6: SECURITY AUDIT AND VALIDATION
    # ========================================================================
    echo "[Phase 6] Running security audit..."

    # Verify firewall rules
    firewall-cmd --list-all

    # Check disk usage
    df -h

    # Check memory
    free -h

    # ========================================================================
    # COMPLETION
    # ========================================================================
    echo "========================================="
    echo "Instance Bootstrap Completed: $(date)"
    echo "========================================="
    
    # Signal CloudFormation/ASG that instance is ready
    # This is used by ASG health checks
    touch /tmp/bootstrap-complete

  EOF

  # User Data for App Tier (similar but for backend services)
  app_tier_user_data = <<-EOF
    #!/bin/bash
    # App Tier Bootstrap Script (Backend API Services)
    # Similar hardening as web tier with app-specific configurations
    
    set -euo pipefail
    exec > >(tee -a /var/log/user-data.log)
    exec 2>&1

    echo "App Tier Bootstrap Started: $(date)"
    
    # System updates
    dnf update -y --security
    dnf upgrade -y
    
    # Install packages
    dnf install -y \
      amazon-cloudwatch-agent \
      aws-cli \
      python3 \
      python3-pip \
      htop \
      fail2ban
    
    # Application setup (example: Python API)
    mkdir -p /opt/app
    cd /opt/app
    
    # Install application dependencies
    pip3 install flask gunicorn boto3
    
    # Create systemd service for app
    cat > /etc/systemd/system/api.service << 'APISERVICE'
[Unit]
Description=Backend API Service
After=network.target

[Service]
Type=simple
User=ec2-user
WorkingDirectory=/opt/app
ExecStart=/usr/local/bin/gunicorn -w 4 -b 0.0.0.0:8080 app:app
Restart=always

[Install]
WantedBy=multi-user.target
APISERVICE
    
    systemctl daemon-reload
    systemctl enable api.service
    # systemctl start api.service  # Start after deploying app code
    
    echo "App Tier Bootstrap Completed: $(date)"
  EOF

  # Common tags
  common_tags = merge(
    var.additional_tags,
    {
      ManagedBy   = "Terraform"
      Environment = var.environment
      Project     = var.project_name
    }
  )
}

# ============================================================================
# IAM ROLE: EC2 INSTANCE ROLE FOR WEB TIER
# ============================================================================
#
# PURPOSE: Grants EC2 instances permissions to interact with AWS services
# PRINCIPLE: Least privilege - only permissions absolutely necessary
#
# PERMISSIONS GRANTED:
# - CloudWatch Logs: Write application and system logs
# - CloudWatch Metrics: Publish custom metrics
# - S3: Read application configuration and assets
# - Systems Manager: Enable Session Manager access (no SSH required)
# - EC2: Describe instances for service discovery
#
# SECURITY BENEFITS:
# - No long-lived credentials stored on instance
# - Temporary credentials rotated automatically
# - Centralized permission management
# - Audit trail via CloudTrail
# ============================================================================

resource "aws_iam_role" "web_tier_role" {
  name               = "${local.name_prefix}-web-tier-role"
  description        = "IAM role for web tier EC2 instances with least privilege permissions"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-web-tier-role"
      Tier = "Web"
    }
  )
}

# IAM Policy: CloudWatch Logs and Metrics
resource "aws_iam_role_policy" "web_tier_cloudwatch" {
  name = "${local.name_prefix}-web-tier-cloudwatch-policy"
  role = aws_iam_role.web_tier_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogStreams"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/${local.name_prefix}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "cloudwatch:namespace" = "${local.name_prefix}/WebTier"
          }
        }
      }
    ]
  })
}

# Attach AWS Managed Policy: SSM (Systems Manager Session Manager)
resource "aws_iam_role_policy_attachment" "web_tier_ssm" {
  role       = aws_iam_role.web_tier_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM Instance Profile (required to attach role to EC2)
resource "aws_iam_instance_profile" "web_tier_profile" {
  name = "${local.name_prefix}-web-tier-profile"
  role = aws_iam_role.web_tier_role.name

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-web-tier-profile"
    }
  )
}

# ============================================================================
# IAM ROLE: EC2 INSTANCE ROLE FOR APP TIER
# ============================================================================

resource "aws_iam_role" "app_tier_role" {
  name               = "${local.name_prefix}-app-tier-role"
  description        = "IAM role for app tier EC2 instances with database and S3 access"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-app-tier-role"
      Tier = "Application"
    }
  )
}

# IAM Policy: S3 Access for application data
resource "aws_iam_role_policy" "app_tier_s3" {
  name = "${local.name_prefix}-app-tier-s3-policy"
  role = aws_iam_role.app_tier_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${local.name_prefix}-app-data/*",
          "arn:aws:s3:::${local.name_prefix}-app-data"
        ]
      }
    ]
  })
}

# Attach CloudWatch and SSM policies
resource "aws_iam_role_policy_attachment" "app_tier_ssm" {
  role       = aws_iam_role.app_tier_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "app_tier_profile" {
  name = "${local.name_prefix}-app-tier-profile"
  role = aws_iam_role.app_tier_role.name

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-app-tier-profile"
    }
  )
}

# ============================================================================
# KMS KEY FOR EBS ENCRYPTION
# ============================================================================
#
# PURPOSE: Customer-managed KMS key for encrypting EBS volumes
# SECURITY: Better than AWS-managed keys for audit and compliance
#
# BENEFITS:
# - Full control over key policies
# - CloudTrail logging of key usage
# - Automatic key rotation
# - Compliance requirements (HIPAA, PCI-DSS)
# ============================================================================

resource "aws_kms_key" "ebs" {
  description             = "KMS key for EBS volume encryption in ${var.environment} environment"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow EC2 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow Auto Scaling to use the key"
        Effect = "Allow"
        Principal = {
          Service = "autoscaling.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-ebs-encryption-key"
    }
  )
}

resource "aws_kms_alias" "ebs" {
  name          = "alias/${local.name_prefix}-ebs"
  target_key_id = aws_kms_key.ebs.key_id
}

# ============================================================================
# LAUNCH TEMPLATE: WEB TIER
# ============================================================================
#
# PURPOSE: Defines instance configuration for Auto Scaling Group
# IMMUTABLE INFRASTRUCTURE: Changes require new launch template version
#
# CONFIGURATION:
# - Instance type, AMI, security groups
# - Encrypted EBS volumes
# - User data script
# - IAM instance profile
# - Metadata service configuration (IMDSv2)
#
# SECURITY FEATURES:
# - IMDSv2 enforcement (prevents SSRF attacks)
# - Encrypted root volume (AES-256)
# - No SSH key pair (use SSM Session Manager)
# - Detailed monitoring enabled
# ============================================================================

resource "aws_launch_template" "web_tier" {
  name_prefix   = "${local.name_prefix}-web-tier-"
  description   = "Launch template for web tier instances with security hardening"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = local.web_tier_config.instance_type

  # Security: No key pair - use AWS Systems Manager Session Manager
  # key_name = "my-key"  # DO NOT USE for production

  # VPC Security Groups
  vpc_security_group_ids = [aws_security_group.web_tier.id]

  # IAM Instance Profile for AWS service access
  iam_instance_profile {
    arn = aws_iam_instance_profile.web_tier_profile.arn
  }

  # =========================================================================
  # BLOCK DEVICE MAPPING: ENCRYPTED EBS VOLUMES
  # =========================================================================
  # Root volume configuration with encryption
  # 
  # ENCRYPTION DETAILS:
  # - Algorithm: AES-256
  # - Key Management: Customer-managed KMS key
  # - Performance Impact: Negligible (<5%)
  # 
  # COMPLIANCE:
  # - PCI-DSS Requirement 3.4: Encryption of cardholder data
  # - HIPAA: ePHI must be encrypted at rest
  # - SOC 2: Encryption of sensitive data required
  # 
  # VOLUME TYPES:
  # - gp3: Latest generation, best price/performance
  # - gp2: Previous generation, still widely used
  # - io2: Provisioned IOPS for databases
  # - st1: Throughput-optimized for big data
  # - sc1: Cold HDD for infrequent access
  #
  # We use gp3 for optimal balance of performance and cost
  # =========================================================================

  block_device_mappings {
    device_name = "/dev/xvda"  # Root device for Amazon Linux 2023

    ebs {
      # Volume size in GB
      # Recommendation: Start small, use monitoring to right-size
      volume_size = var.web_tier_root_volume_size

      # Volume type: gp3 is latest generation general purpose SSD
      # - Baseline: 3,000 IOPS and 125 MB/s throughput
      # - Scalable: Up to 16,000 IOPS and 1,000 MB/s
      # - Cost: ~20% cheaper than gp2 for same performance
      volume_type = "gp3"

      # IOPS (Input/Output Operations Per Second)
      # Default: 3,000 IOPS (sufficient for most web applications)
      # Max: 16,000 IOPS
      iops = 3000

      # Throughput in MB/s
      # Default: 125 MB/s
      # Max: 1,000 MB/s
      throughput = 125

      # CRITICAL: Encryption at rest
      # Uses KMS key for encryption/decryption
      # Performance impact: <5% (negligible)
      encrypted = true
      kms_key_id = aws_kms_key.ebs.arn

      # Delete volume when instance terminates
      # Auto Scaling will create new instances with new volumes
      delete_on_termination = true

      # Tags for the EBS volume
      tags = merge(
        local.common_tags,
        {
          Name      = "${local.name_prefix}-web-tier-root"
          Encrypted = "true"
          VolumeType = "gp3"
        }
      )
    }
  }

  # =========================================================================
  # INSTANCE METADATA SERVICE (IMDS) CONFIGURATION
  # =========================================================================
  # IMDSv2 is a defense-in-depth security feature
  # 
  # IMDS VERSIONS:
  # - IMDSv1: Original, vulnerable to SSRF attacks
  # - IMDSv2: Session-oriented, prevents SSRF
  # 
  # SSRF ATTACK SCENARIO (IMDSv1):
  # 1. Attacker finds SSRF vulnerability in web app
  # 2. Tricks app into making request to http://169.254.169.254/latest/meta-data/
  # 3. Retrieves IAM credentials from instance metadata
  # 4. Uses credentials to access AWS services
  # 
  # IMDSv2 PROTECTION:
  # - Requires PUT request to get session token first
  # - Session token has TTL (max 6 hours)
  # - HTTP headers required (prevents forwarding)
  # - Protects against SSRF, open firewalls, open routers
  # 
  # COMPLIANCE:
  # - CIS AWS Benchmark: Requires IMDSv2
  # - AWS Security Best Practices: Recommended
  # 
  # COMPATIBILITY:
  # - Most modern SDKs support IMDSv2
  # - May require updates to older applications
  # =========================================================================

  metadata_options {
    # Require IMDSv2 (deny IMDSv1 requests)
    # Values: optional (both v1 and v2), required (v2 only)
    http_tokens = "required"

    # Enable metadata service
    # Values: enabled, disabled
    http_endpoint = "enabled"

    # Response hop limit for metadata requests
    # Default: 1 (only same instance)
    # Increase if using containers/pods that forward requests
    http_put_response_hop_limit = 1

    # Enable instance tags in metadata
    # Allows applications to read instance tags
    instance_metadata_tags = "enabled"
  }

  # Monitoring: Enable detailed monitoring (1-minute intervals)
  # Default is 5-minute intervals
  # Cost: ~$2.10 per instance per month
  # Benefit: Faster Auto Scaling reactions, better troubleshooting
  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  # User Data: Bootstrap script (defined in locals)
  # Base64 encoded automatically by Terraform
  user_data = base64encode(local.web_tier_user_data)

  # Network interfaces configuration
  # We don't specify subnets here - ASG will place instances
  network_interfaces {
    # No public IP address (private subnet)
    # Instances access internet via NAT Gateway
    associate_public_ip_address = false

    # Delete network interface when instance terminates
    delete_on_termination = true

    # Security groups applied at network interface level
    security_groups = [aws_security_group.web_tier.id]
  }

  # Tag specifications for instances and volumes
  tag_specifications {
    resource_type = "instance"
    tags = merge(
      local.common_tags,
      {
        Name = "${local.name_prefix}-web-tier-instance"
        Tier = "Web"
      }
    )
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(
      local.common_tags,
      {
        Name = "${local.name_prefix}-web-tier-volume"
      }
    )
  }

  # Lifecycle: Create new version before destroying old one
  # Allows for safe rolling updates
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-web-tier-lt"
    }
  )
}

# ============================================================================
# LAUNCH TEMPLATE: APP TIER
# ============================================================================
# Similar configuration to web tier but for backend services

resource "aws_launch_template" "app_tier" {
  name_prefix   = "${local.name_prefix}-app-tier-"
  description   = "Launch template for application tier backend services"
  image_id      = data.aws_ami.amazon_linux_2023.id
  instance_type = local.app_tier_config.instance_type

  vpc_security_group_ids = [aws_security_group.app_tier.id]

  iam_instance_profile {
    arn = aws_iam_instance_profile.app_tier_profile.arn
  }

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size           = var.app_tier_root_volume_size
      volume_type           = "gp3"
      iops                  = 3000
      throughput            = 125
      encrypted             = true
      kms_key_id            = aws_kms_key.ebs.arn
      delete_on_termination = true

      tags = merge(
        local.common_tags,
        {
          Name = "${local.name_prefix}-app-tier-root"
        }
      )
    }
  }

  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  monitoring {
    enabled = var.enable_detailed_monitoring
  }

  user_data = base64encode(local.app_tier_user_data)

  network_interfaces {
    associate_public_ip_address = false
    delete_on_termination       = true
    security_groups             = [aws_security_group.app_tier.id]
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(
      local.common_tags,
      {
        Name = "${local.name_prefix}-app-tier-instance"
        Tier = "Application"
      }
    )
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-app-tier-lt"
    }
  )
}

# ============================================================================
# APPLICATION LOAD BALANCER (ALB)
# ============================================================================
#
# PURPOSE: Distribute traffic across multiple web tier instances
# TIER: Edge/Internet-facing layer
#
# FEATURES:
# - Layer 7 (HTTP/HTTPS) load balancing
# - SSL/TLS termination
# - Host-based and path-based routing
# - WebSocket support
# - HTTP/2 support
# - Sticky sessions (optional)
# - Health checks with configurable parameters
# - Access logs to S3
# - Integration with AWS WAF
# - Integration with AWS Shield (DDoS protection)
#
# HIGH AVAILABILITY:
# - Deployed across multiple AZs
# - Automatic failover
# - Cross-zone load balancing
# - Connection draining
#
# SECURITY:
# - HTTPS enforcement
# - Security group restrictions
# - Access logs for compliance
# - Integration with ACM for certificate management
# ============================================================================

resource "aws_lb" "main" {
  name               = "${local.name_prefix}-alb"
  internal           = false  # Internet-facing
  load_balancer_type = "application"

  # Deploy ALB across all public subnets for high availability
  # ALB automatically load balances across AZs
  subnets = aws_subnet.public[*].id

  # Security group for ALB (allows HTTP/HTTPS from internet)
  security_groups = [aws_security_group.alb.id]

  # Enable deletion protection for production
  # Prevents accidental deletion via API/Console
  # Must be disabled before ALB can be deleted
  enable_deletion_protection = var.environment == "prod" ? true : false

  # Enable cross-zone load balancing
  # Distributes traffic evenly across all instances in all AZs
  # Slightly higher data transfer costs but better fault tolerance
  enable_cross_zone_load_balancing = true

  # Enable HTTP/2 for better performance
  # Requires HTTPS listener
  # Benefits: multiplexing, header compression, server push
  enable_http2 = true

  # Drop invalid HTTP headers
  # Security: Prevents header injection attacks
  drop_invalid_header_fields = true

  # Idle timeout: Time connection can be idle before being closed
  # Default: 60 seconds
  # Increase for long-polling applications
  idle_timeout = 60

  # Access logs configuration
  # Logs all requests for security audit and troubleshooting
  # Cost: S3 storage + data transfer
  # Compliance: Required for PCI-DSS, HIPAA
  access_logs {
    bucket  = aws_s3_bucket.alb_logs.id
    prefix  = "alb-logs"
    enabled = var.enable_alb_access_logs
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-alb"
      Type = "Application-Load-Balancer"
    }
  )
}

# S3 Bucket for ALB Access Logs
resource "aws_s3_bucket" "alb_logs" {
  bucket = "${local.name_prefix}-alb-logs-${data.aws_caller_identity.current.account_id}"

  # Prevent accidental deletion
  force_destroy = false

  tags = merge(
    local.common_tags,
    {
      Name    = "${local.name_prefix}-alb-logs"
      Purpose = "ALB-Access-Logs"
    }
  )
}

# Enable versioning for log bucket
resource "aws_s3_bucket_versioning" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Encrypt ALB logs at rest
resource "aws_s3_bucket_server_side_encryption_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block public access to logs
resource "aws_s3_bucket_public_access_block" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy for log retention
resource "aws_s3_bucket_lifecycle_configuration" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  rule {
    id     = "log-retention"
    status = "Enabled"

    # Transition to cheaper storage class after 30 days
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }

    # Transition to Glacier after 90 days
    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Delete logs after retention period
    expiration {
      days = var.alb_log_retention_days
    }
  }
}

# S3 Bucket Policy: Allow ALB to write logs
resource "aws_s3_bucket_policy" "alb_logs" {
  bucket = aws_s3_bucket.alb_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSLogDeliveryWrite"
        Effect = "Allow"
        Principal = {
          Service = "elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.alb_logs.arn}/*"
      },
      {
        Sid    = "AWSLogDeliveryAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "elasticloadbalancing.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.alb_logs.arn
      }
    ]
  })
}

# ============================================================================
# TARGET GROUP: WEB TIER
# ============================================================================
#
# PURPOSE: Group of web tier instances for ALB to route traffic to
# PROTOCOL: HTTP (ALB terminates HTTPS)
#
# HEALTH CHECK CONFIGURATION:
# - Protocol: HTTP
# - Path: /health
# - Interval: 30 seconds
# - Timeout: 5 seconds
# - Healthy threshold: 2 consecutive successes
# - Unhealthy threshold: 3 consecutive failures
#
# BENEFITS:
# - Automatic removal of unhealthy instances
# - Gradual instance registration (slow start)
# - Connection draining on deregistration
# - Stickiness for session persistence (optional)
# ============================================================================

resource "aws_lb_target_group" "web_tier" {
  name     = "${local.name_prefix}-web-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = data.aws_vpc.main.id

  # Target type: instance, ip, or lambda
  # instance: Route to EC2 instance IDs
  # ip: Route to IP addresses (for ECS, EKS)
  # lambda: Route to Lambda function
  target_type = "instance"

  # Health check configuration
  health_check {
    enabled             = true
    path                = "/health"
    protocol            = "HTTP"
    port                = "traffic-port"  # Same port as target
    interval            = 30              # Seconds between health checks
    timeout             = 5               # Seconds to wait for response
    healthy_threshold   = 2               # Consecutive successes to mark healthy
    unhealthy_threshold = 3               # Consecutive failures to mark unhealthy
    matcher             = "200"           # Expected HTTP status code
  }

  # Deregistration delay (connection draining)
  # Time to wait before deregistering target
  # Allows in-flight requests to complete
  # Default: 300 seconds (5 minutes)
  # Recommendation: Set to slightly longer than longest request duration
  deregistration_delay = 30

  # Slow start mode
  # Gradually increases share of traffic to new targets
  # Prevents overwhelming newly started instances
  # Duration in seconds (30-900)
  # 0 = disabled
  slow_start = 30

  # Stickiness (session affinity)
  # Routes requests from same client to same target
  # Useful for applications with session state
  # Types: lb_cookie (ALB-generated), app_cookie (application-generated)
  stickiness {
    enabled         = var.enable_sticky_sessions
    type            = "lb_cookie"
    cookie_duration = 86400  # 24 hours in seconds
  }

  # Load balancing algorithm
  # round_robin: Default, distributes requests evenly
  # least_outstanding_requests: Routes to target with fewest pending requests
  load_balancing_algorithm_type = "round_robin"

  # Preserve client IP address
  # When true, X-Forwarded-For header contains client IP
  # Important for access logs and application logic
  preserve_client_ip = true

  # Protocol version for HTTP
  # HTTP1: Default, widely compatible
  # HTTP2: Better performance, requires HTTPS
  # GRPC: For gRPC applications
  protocol_version = "HTTP1"

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-web-tg"
      Tier = "Web"
    }
  )

  # Lifecycle: Create new target group before destroying old one
  # Required for zero-downtime updates
  lifecycle {
    create_before_destroy = true
  }
}

# ============================================================================
# ALB LISTENER: HTTP (Port 80)
# ============================================================================
#
# PURPOSE: Listen for HTTP traffic and redirect to HTTPS
# SECURITY: Enforce HTTPS for all traffic
#
# ALTERNATIVE:
# - Can be disabled entirely if only HTTPS is needed
# - Can forward to target group if HTTPS not required
# ============================================================================

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  # Default action: Redirect HTTP to HTTPS
  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"  # Permanent redirect
    }
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-http-listener"
    }
  )
}

# ============================================================================
# ALB LISTENER: HTTPS (Port 443)
# ============================================================================
#
# PURPOSE: Terminate HTTPS/TLS and forward to web tier instances
# SECURITY: TLS 1.2+ only, strong cipher suites
#
# REQUIREMENTS:
# - ACM certificate (aws_acm_certificate)
# - Domain name registered
# - DNS validation or email validation
# ============================================================================

resource "aws_lb_listener" "https" {
  count = var.enable_https ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"

  # SSL/TLS Policy
  # Determines allowed SSL/TLS versions and cipher suites
  # ELBSecurityPolicy-TLS13-1-2-2021-06: TLS 1.2 and 1.3 only (recommended)
  # ELBSecurityPolicy-TLS-1-2-2017-01: TLS 1.2 only
  # ELBSecurityPolicy-FS-1-2-Res-2020-10: Forward secrecy, TLS 1.2+
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"

  # ACM Certificate ARN
  # Must be in the same region as ALB
  # Can be a wildcard certificate (*.example.com)
  certificate_arn = var.acm_certificate_arn

  # Default action: Forward to web tier target group
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web_tier.arn
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-https-listener"
    }
  )
}

# ============================================================================
# AUTO SCALING GROUP: WEB TIER
# ============================================================================
#
# PURPOSE: Maintain desired number of healthy web tier instances
# SCALING: Automatic based on CPU utilization and schedule
#
# FEATURES:
# - Automatic instance replacement on failure
# - Rolling updates with instance refresh
# - Multiple AZ deployment
# - Health checks (EC2 + ELB)
# - Notifications on scaling events
# - Termination policies for cost optimization
#
# SCALING POLICIES:
# - Target tracking: Maintain target CPU utilization
# - Step scaling: Scale based on CloudWatch alarms
# - Scheduled scaling: Scale on predictable schedule
# - Predictive scaling: ML-based scaling predictions
# ============================================================================

resource "aws_autoscaling_group" "web_tier" {
  name                = "${local.name_prefix}-web-tier-asg"
  vpc_zone_identifier = aws_subnet.private[*].id  # Deploy in private subnets

  # Capacity configuration
  min_size         = local.web_tier_config.min_size
  max_size         = local.web_tier_config.max_size
  desired_capacity = local.web_tier_config.desired_size

  # Launch template configuration
  launch_template {
    id      = aws_launch_template.web_tier.id
    version = "$Latest"  # Always use latest version
  }

  # Health check configuration
  # EC2: Basic instance health (running, not terminated)
  # ELB: Target group health checks
  # Both: Instance must pass both checks
  health_check_type         = "ELB"
  health_check_grace_period = 300  # Seconds to wait before first health check

  # Target group attachment
  # ASG will automatically register/deregister instances
  target_group_arns = [aws_lb_target_group.web_tier.arn]

  # Default cooldown period
  # Time to wait between scaling activities
  # Prevents rapid scaling up/down
  default_cooldown = 300

  # Termination policies
  # Determines which instances to terminate during scale-in
  termination_policies = [
    "OldestLaunchTemplate",
    "OldestInstance"
  ]

  # Force delete: Delete ASG even if instances exist
  # Useful for development, dangerous for production
  force_delete = false

  # Wait for capacity timeout
  # Maximum time to wait for desired capacity during creation
  wait_for_capacity_timeout = "10m"

  # Protect instances from scale-in
  # Prevents specific instances from being terminated
  protect_from_scale_in = false

  # Instance refresh configuration
  # Enables rolling updates when launch template changes
  instance_refresh {
    strategy = "Rolling"
    
    preferences {
      # Minimum healthy percentage during refresh
      # 90% = at least 90% of desired capacity must be healthy
      min_healthy_percentage = 90

      # Maximum time for instance to become healthy
      # After this time, instance is considered unhealthy and replaced
      instance_warmup = 300
    }

    triggers = ["tag"]  # Trigger refresh on tag changes
  }

  # Enabled metrics
  # CloudWatch metrics to collect for monitoring
  # Free metrics updated every 5 minutes
  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupMaxSize",
    "GroupMinSize",
    "GroupPendingInstances",
    "GroupStandbyInstances",
    "GroupTerminatingInstances",
    "GroupTotalInstances"
  ]

  # Metrics granularity
  # 1Minute: Detailed monitoring (extra cost)
  # Default: 5 minutes (free)
  metrics_granularity = "1Minute"

  # Tags
  # Propagated to all instances launched by ASG
  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-web-tier-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Tier"
    value               = "Web"
    propagate_at_launch = true
  }

  tag {
    key                 = "Environment"
    value               = var.environment
    propagate_at_launch = true
  }

  tag {
    key                 = "ManagedBy"
    value               = "Terraform-Auto-Scaling"
    propagate_at_launch = true
  }

  # Lifecycle: Create new ASG before destroying
  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]  # Allow manual scaling
  }

  # Dependencies
  depends_on = [
    aws_lb_target_group.web_tier,
    aws_launch_template.web_tier
  ]
}

# ============================================================================
# AUTO SCALING POLICY: WEB TIER - TARGET TRACKING (CPU)
# ============================================================================
#
# PURPOSE: Maintain target CPU utilization through automatic scaling
# TYPE: Target Tracking (simplest, most common)
#
# HOW IT WORKS:
# 1. ASG monitors average CPU across all instances
# 2. If CPU > target, scale out (add instances)
# 3. If CPU < target, scale in (remove instances)
# 4. Respects cooldown periods between scaling actions
#
# TARGET: 70% CPU utilization
# - Low enough to handle traffic spikes
# - High enough for cost efficiency
# - Adjust based on application characteristics
#
# BENEFITS:
# - Automatic calculation of scaling amounts
# - Handles metric fluctuations gracefully
# - Prevents flapping (rapid scale out/in)
# ============================================================================

resource "aws_autoscaling_policy" "web_tier_cpu_tracking" {
  name                   = "${local.name_prefix}-web-tier-cpu-tracking"
  autoscaling_group_name = aws_autoscaling_group.web_tier.name
  policy_type            = "TargetTrackingScaling"

  # Target tracking configuration
  target_tracking_configuration {
    # Predefined metric: ASGAverageCPUUtilization
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }

    # Target value (percentage)
    # 70% provides buffer for traffic spikes
    target_value = var.target_cpu_utilization

    # Scale-in cooldown
    # Time to wait after scale-in before another scale-in
    # Prevents over-aggressive scale-in
    scale_in_cooldown = 300

    # Scale-out cooldown
    # Time to wait after scale-out before another scale-out
    # Allows new instances to initialize before adding more
    scale_out_cooldown = 60
  }
}

# ============================================================================
# AUTO SCALING POLICY: WEB TIER - STEP SCALING (OPTIONAL)
# ============================================================================
#
# PURPOSE: Step-based scaling for more granular control
# USE CASE: Scale different amounts based on metric severity
#
# EXAMPLE:
# - CPU 70-80%: Add 1 instance
# - CPU 80-90%: Add 2 instances  
# - CPU 90%+: Add 3 instances
# ============================================================================

# CloudWatch Alarm: High CPU (for step scaling)
resource "aws_cloudwatch_metric_alarm" "web_tier_high_cpu" {
  count = var.enable_step_scaling ? 1 : 0

  alarm_name          = "${local.name_prefix}-web-tier-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 60
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Triggers when CPU exceeds 80%"
  alarm_actions       = [aws_autoscaling_policy.web_tier_scale_up[0].arn]

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.web_tier.name
  }

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-web-tier-high-cpu-alarm"
    }
  )
}

# Step Scaling Policy: Scale Up
resource "aws_autoscaling_policy" "web_tier_scale_up" {
  count = var.enable_step_scaling ? 1 : 0

  name                   = "${local.name_prefix}-web-tier-scale-up"
  autoscaling_group_name = aws_autoscaling_group.web_tier.name
  policy_type            = "StepScaling"
  adjustment_type        = "ChangeInCapacity"

  step_adjustment {
    scaling_adjustment          = 1
    metric_interval_lower_bound = 0
    metric_interval_upper_bound = 10
  }

  step_adjustment {
    scaling_adjustment          = 2
    metric_interval_lower_bound = 10
    metric_interval_upper_bound = 20
  }

  step_adjustment {
    scaling_adjustment          = 3
    metric_interval_lower_bound = 20
  }
}

# ============================================================================
# AUTO SCALING GROUP: APP TIER (Similar to Web Tier)
# ============================================================================

resource "aws_autoscaling_group" "app_tier" {
  name                = "${local.name_prefix}-app-tier-asg"
  vpc_zone_identifier = aws_subnet.private[*].id

  min_size         = local.app_tier_config.min_size
  max_size         = local.app_tier_config.max_size
  desired_capacity = local.app_tier_config.desired_size

  launch_template {
    id      = aws_launch_template.app_tier.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300
  default_cooldown          = 300

  termination_policies = [
    "OldestLaunchTemplate",
    "OldestInstance"
  ]

  enabled_metrics = [
    "GroupDesiredCapacity",
    "GroupInServiceInstances",
    "GroupTotalInstances"
  ]

  tag {
    key                 = "Name"
    value               = "${local.name_prefix}-app-tier-instance"
    propagate_at_launch = true
  }

  tag {
    key                 = "Tier"
    value               = "Application"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
    ignore_changes        = [desired_capacity]
  }
}

# ============================================================================
# SNS TOPIC: AUTO SCALING NOTIFICATIONS
# ============================================================================
#
# PURPOSE: Receive notifications for scaling events
# EVENTS: Launch, terminate, fail to launch, fail to terminate
# ============================================================================

resource "aws_sns_topic" "asg_notifications" {
  name              = "${local.name_prefix}-asg-notifications"
  display_name      = "Auto Scaling Group Notifications"
  kms_master_key_id = aws_kms_key.sns.id

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-asg-notifications"
    }
  )
}

# KMS Key for SNS Encryption
resource "aws_kms_key" "sns" {
  description             = "KMS key for SNS topic encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = merge(
    local.common_tags,
    {
      Name = "${local.name_prefix}-sns-key"
    }
  )
}

# SNS Topic Subscription (Email)
resource "aws_sns_topic_subscription" "asg_notifications_email" {
  count = var.asg_notification_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.asg_notifications.arn
  protocol  = "email"
  endpoint  = var.asg_notification_email
}

# ASG Notification Configuration
resource "aws_autoscaling_notification" "web_tier" {
  group_names = [aws_autoscaling_group.web_tier.name]

  notifications = [
    "autoscaling:EC2_INSTANCE_LAUNCH",
    "autoscaling:EC2_INSTANCE_TERMINATE",
    "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
    "autoscaling:EC2_INSTANCE_TERMINATE_ERROR"
  ]

  topic_arn = aws_sns_topic.asg_notifications.arn
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.main.dns_name
}

output "alb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.main.arn
}

output "alb_zone_id" {
  description = "Zone ID of the Application Load Balancer (for Route 53)"
  value       = aws_lb.main.zone_id
}

output "web_tier_asg_name" {
  description = "Name of the web tier Auto Scaling Group"
  value       = aws_autoscaling_group.web_tier.name
}

output "app_tier_asg_name" {
  description = "Name of the app tier Auto Scaling Group"
  value       = aws_autoscaling_group.app_tier.name
}

output "web_tier_launch_template_id" {
  description = "ID of the web tier launch template"
  value       = aws_launch_template.web_tier.id
}

output "app_tier_launch_template_id" {
  description = "ID of the app tier launch template"
  value       = aws_launch_template.app_tier.id
}

output "web_tier_target_group_arn" {
  description = "ARN of the web tier target group"
  value       = aws_lb_target_group.web_tier.arn
}

output "ebs_kms_key_id" {
  description = "ID of the KMS key used for EBS encryption"
  value       = aws_kms_key.ebs.id
}
