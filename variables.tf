# variables.tf
# Variables for the Registry Forensics Lab Terraform configuration

variable "aws_region" {
  description = "AWS region where the lab will be deployed"
  type        = string
  default     = "us-east-1"
}

variable "windows_ami_id" {
  description = "AMI ID for Windows 10 (varies by region)"
  type        = string
  default     = "ami-0be0a52ed3f231b45" # Windows 10 Enterprise AMI (update with appropriate AMI for your region)
}

variable "instance_type" {
  description = "EC2 instance type for the forensics workstation"
  type        = string
  default     = "t3.large" # 2 vCPU, 8 GiB memory recommended for lab performance
}

variable "key_name" {
  description = "Name of the key pair for SSH access"
  type        = string
  default     = "forensics-lab-key"
}

variable "s3_bucket_name" {
  description = "Name of the S3 bucket for storing lab files and evidence reports"
  type        = string
  default     = "globomantics-forensics-lab-storage"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the lab environment"
  type        = list(string)
  default     = ["0.0.0.0/0"] # WARNING: This allows access from anywhere (update with your specific IP range)
}

variable "student_count" {
  description = "Number of student workstations to provision"
  type        = number
  default     = 1
}

variable "lab_name" {
  description = "Name of the lab environment"
  type        = string
  default     = "Registry-Forensics-Lab"
}

variable "environment" {
  description = "Environment type (production, development, training)"
  type        = string
  default     = "training"
}

variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for instances"
  type        = bool
  default     = true
}

variable "enable_encryption" {
  description = "Enable encryption for EBS volumes and S3 bucket"
  type        = bool
  default     = true
}
