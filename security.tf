# security.tf
# Security configuration for the Registry Forensics Lab

# Security group for the forensics workstation
resource "aws_security_group" "forensics_lab_sg" {
  name        = "forensics-lab-sg"
  description = "Security group for the Registry Forensics Lab"
  vpc_id      = aws_vpc.forensics_lab_vpc.id
  
  # Allow RDP access from specific IP ranges
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.allowed_cidr_blocks
    description = "RDP access for lab users"
  }
  
  # Allow HTTPS access for downloads and updates
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access for downloads and updates"
  }
  
  # Allow HTTP access for downloads and updates
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access for downloads and updates"
  }
  
  # Allow outbound traffic to all destinations
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }
  
  tags = {
    Name        = "forensics-lab-sg"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}

# IAM role for the forensics workstation
resource "aws_iam_role" "forensics_workstation_role" {
  name = "forensics-workstation-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Effect = "Allow",
        Sid    = ""
      }
    ]
  })
  
  tags = {
    Name        = "forensics-workstation-role"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}

# IAM policy for S3 access
resource "aws_iam_policy" "forensics_s3_access" {
  name        = "forensics-s3-access"
  description = "Policy for accessing the forensics lab S3 bucket"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ],
        Effect = "Allow",
        Resource = [
          "${aws_s3_bucket.forensics_lab_bucket.arn}",
          "${aws_s3_bucket.forensics_lab_bucket.arn}/*"
        ]
      }
    ]
  })
}

# IAM policy for CloudWatch Logs access
resource "aws_iam_policy" "forensics_cloudwatch_access" {
  name        = "forensics-cloudwatch-access"
  description = "Policy for writing to CloudWatch Logs"
  
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Effect = "Allow",
        Resource = "${aws_cloudwatch_log_group.forensics_lab_logs.arn}:*"
      }
    ]
  })
}

# Attach S3 access policy to the role
resource "aws_iam_role_policy_attachment" "s3_access_attachment" {
  role       = aws_iam_role.forensics_workstation_role.name
  policy_arn = aws_iam_policy.forensics_s3_access.arn
}

# Attach CloudWatch Logs access policy to the role
resource "aws_iam_role_policy_attachment" "cloudwatch_access_attachment" {
  role       = aws_iam_role.forensics_workstation_role.name
  policy_arn = aws_iam_policy.forensics_cloudwatch_access.arn
}

# Instance profile for the forensics workstation
resource "aws_iam_instance_profile" "forensics_workstation_profile" {
  name = "forensics-workstation-profile"
  role = aws_iam_role.forensics_workstation_role.name
}

# KMS key for encryption
resource "aws_kms_key" "forensics_lab_kms_key" {
  description             = "KMS key for forensics lab encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = {
    Name        = "forensics-lab-kms-key"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}

# KMS key alias
resource "aws_kms_alias" "forensics_lab_kms_alias" {
  name          = "alias/forensics-lab-key"
  target_key_id = aws_kms_key.forensics_lab_kms_key.key_id
}

# S3 bucket server-side encryption configuration
resource "aws_s3_bucket_server_side_encryption_configuration" "forensics_bucket_encryption" {
  bucket = aws_s3_bucket.forensics_lab_bucket.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.forensics_lab_kms_key.arn
      sse_algorithm     = "aws:kms"
    }
  }
}
