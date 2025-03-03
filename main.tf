# main.tf
# Terraform configuration for Registry Forensics Lab cloud deployment

provider "aws" {
  region = var.aws_region
}

# VPC for the lab environment
resource "aws_vpc" "forensics_lab_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = {
    Name        = "forensics-lab-vpc"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}

# Public subnet within the VPC
resource "aws_subnet" "forensics_lab_subnet" {
  vpc_id                  = aws_vpc.forensics_lab_vpc.id
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
  availability_zone       = "${var.aws_region}a"
  
  tags = {
    Name        = "forensics-lab-subnet"
    Environment = "training"
  }
}

# Internet Gateway for the VPC
resource "aws_internet_gateway" "forensics_lab_igw" {
  vpc_id = aws_vpc.forensics_lab_vpc.id
  
  tags = {
    Name        = "forensics-lab-igw"
    Environment = "training"
  }
}

# Route table with a route to the Internet Gateway
resource "aws_route_table" "forensics_lab_rtb" {
  vpc_id = aws_vpc.forensics_lab_vpc.id
  
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.forensics_lab_igw.id
  }
  
  tags = {
    Name        = "forensics-lab-rtb"
    Environment = "training"
  }
}

# Route table association with the subnet
resource "aws_route_table_association" "forensics_lab_rtb_assoc" {
  subnet_id      = aws_subnet.forensics_lab_subnet.id
  route_table_id = aws_route_table.forensics_lab_rtb.id
}

# EC2 Instance for the Windows 10 workstation
resource "aws_instance" "forensics_workstation" {
  ami                    = var.windows_ami_id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.forensics_lab_subnet.id
  vpc_security_group_ids = [aws_security_group.forensics_lab_sg.id]
  key_name               = var.key_name
  
  root_block_device {
    volume_size = 80
    volume_type = "gp2"
    encrypted   = true
  }
  
  user_data = <<-EOF
              <powershell>
              # Install required tools
              choco install -y git
              choco install -y vscode
              
              # Create lab directory
              New-Item -Path "C:\RegistryForensicsLab" -ItemType Directory -Force
              
              # Clone lab repository
              git clone https://github.com/example/registry-forensics-lab.git C:\RegistryForensicsLab
              
              # Set execution policy to allow PowerShell scripts
              Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope LocalMachine -Force
              
              # Create desktop shortcut
              $WshShell = New-Object -ComObject WScript.Shell
              $Shortcut = $WshShell.CreateShortcut("C:\Users\Administrator\Desktop\Registry Forensics Lab.lnk")
              $Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
              $Shortcut.Arguments = "-ExecutionPolicy Bypass -File C:\RegistryForensicsLab\start_lab.ps1"
              $Shortcut.WorkingDirectory = "C:\RegistryForensicsLab"
              $Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,23"
              $Shortcut.Save()
              </powershell>
              EOF
  
  tags = {
    Name        = "forensics-workstation"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}

# S3 bucket for storing lab files and evidence reports
resource "aws_s3_bucket" "forensics_lab_bucket" {
  bucket = var.s3_bucket_name
  
  tags = {
    Name        = "forensics-lab-bucket"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}

# S3 bucket access control
resource "aws_s3_bucket_ownership_controls" "forensics_lab_bucket_ownership" {
  bucket = aws_s3_bucket.forensics_lab_bucket.id
  
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

# S3 bucket public access block
resource "aws_s3_bucket_public_access_block" "forensics_lab_bucket_public_access" {
  bucket = aws_s3_bucket.forensics_lab_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CloudWatch Log Group for lab activities
resource "aws_cloudwatch_log_group" "forensics_lab_logs" {
  name              = "/forensics-lab/activity-logs"
  retention_in_days = 30
  
  tags = {
    Name        = "forensics-lab-logs"
    Environment = "training"
    Project     = "Dark-Kittens-Lab"
  }
}
