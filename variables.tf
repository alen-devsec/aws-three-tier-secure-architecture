variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "project_tags" {
  type = map(string)
  default = {
    Project     = "Secure-Architecture"
    Environment = "Production"
    Owner       = "DevSecOps-Team"
    Compliance  = "PCI-DSS"
  }
}
