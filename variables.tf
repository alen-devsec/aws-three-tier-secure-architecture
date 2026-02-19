variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-east-1"
}

variable "vpc_cidr" {
  description = "CIDR block for the main VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "project_tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {
    Project     = "Secure-Architecture"
    Environment = "Production"
    ManagedBy   = "Terraform"
  }
}
