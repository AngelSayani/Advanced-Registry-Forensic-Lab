# outputs.tf
# Output values for the Registry Forensics Lab

output "forensics_workstation_public_ip" {
  description = "Public IP address of the forensics workstation"
  value       = aws_instance.forensics_workstation.public_ip
}

output "forensics_workstation_private_ip" {
  description = "Private IP address of the forensics workstation"
  value       = aws_instance.forensics_workstation.private_ip
}

output "forensics_workstation_id" {
  description = "Instance ID of the forensics workstation"
  value       = aws_instance.forensics_workstation.id
}

output "forensics_lab_bucket_name" {
  description = "Name of the S3 bucket for storing lab files and evidence reports"
  value       = aws_s3_bucket.forensics_lab_bucket.bucket
}

output "forensics_lab_vpc_id" {
  description = "ID of the VPC containing the lab environment"
  value       = aws_vpc.forensics_lab_vpc.id
}

output "rdp_connection_string" {
  description = "Connection string for RDP access to the workstation"
  value       = "mstsc.exe /v:${aws_instance.forensics_workstation.public_ip}"
}

output "lab_access_url" {
  description = "URL for accessing the lab environment"
  value       = "https://${aws_instance.forensics_workstation.public_dns}"
}

output "cloudwatch_log_group" {
  description = "CloudWatch Log Group for lab activities"
  value       = aws_cloudwatch_log_group.forensics_lab_logs.name
}

output "lab_security_group_id" {
  description = "ID of the security group protecting the lab environment"
  value       = aws_security_group.forensics_lab_sg.id
}

output "kms_key_id" {
  description = "ID of the KMS key used for encryption"
  value       = aws_kms_key.forensics_lab_kms_key.key_id
}
