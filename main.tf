terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
    aws = {
      source = "hashicorp/aws"
    }
  }
}

# Variables

variable "gcp_region" {
  default = "europe-west1"
}

variable "gcp_zone" {
  default = "europe-west1-b"
}

variable "gcp_project" {
}

variable "aws_region" {
  default = "eu-west-1"
}

variable "aws_keypair" {
}

variable "aws_instance_type" {
  default = "t2.medium"
}

variable "name" {
  validation {
    condition     = can(regex("^[a-z]{6,30}$", var.name))
    error_message = "Name must be between 6 and 30 lowercase letters"
  }
}

# Providers

provider "google" {
  region = var.gcp_region
  zone   = var.gcp_zone
}

provider "aws" {
  region = var.aws_region
}

# Data

data "google_project" "sandbox" {
  project_id = var.gcp_project
}

data "aws_caller_identity" "current" {}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  owners = ["099720109477"] # Canonical
}

data "aws_key_pair" "me" {
  key_name           = var.aws_keypair
  include_public_key = true
}

# Resources

# Service account for workspaces
resource "google_service_account" "sa" {
  project      = data.google_project.sandbox.project_id
  account_id   = var.name
  display_name = var.name
}

# Service account for the Coder instance to use.
# This will be linked with the AWS instance role.
resource "google_service_account" "instance_sa" {
  project      = data.google_project.sandbox.project_id
  account_id   = "${var.name}-instance-sa"
  display_name = "${var.name}-instance-sa"
}

# Grant the workloadIdentityUser role to the instance service account
resource "google_project_iam_member" "instance_sa_workload_identity" {
  project = data.google_project.sandbox.project_id
  role    = "roles/iam.workloadIdentityUser"
  member  = "serviceAccount:${google_service_account.instance_sa.email}"
}

# Grant the compute.admin role to the instance service account
resource "google_project_iam_member" "instance_sa_compute_admin" {
  project = data.google_project.sandbox.project_id
  role    = "roles/compute.admin"
  member  = "serviceAccount:${google_service_account.instance_sa.email}"
}

# Grant the storage.admin role to the instance service account
resource "google_project_iam_member" "instance_sa_storage_admin" {
  project = data.google_project.sandbox.project_id
  role    = "roles/storage.admin"
  member  = "serviceAccount:${google_service_account.instance_sa.email}"
}

# Grant the service account user role to the instance service account
resource "google_project_iam_member" "instance_sa_service_account_user" {
  project = data.google_project.sandbox.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.instance_sa.email}"
}

# Allow the external AWS account to assume the instance service account
# See: https://cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds#allow_the_external_workload_to_impersonate_the_service_account
resource "google_service_account_iam_binding" "iam_binding_instance_sa" {
  service_account_id = google_service_account.instance_sa.name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/projects/${data.google_project.sandbox.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.pool.workload_identity_pool_id}/attribute.aws_role/${aws_iam_role.instance.name}"
  ]
}

# Create a workload identity pool and provider
resource "google_iam_workload_identity_pool" "pool" {
  project                   = data.google_project.sandbox.project_id
  workload_identity_pool_id = "${var.name}-pool" # 30 days deletion grace period
}

resource "google_iam_workload_identity_pool_provider" "provider" {
  display_name                       = var.name
  project                            = data.google_project.sandbox.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = var.name
  # From https://cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds#mappings-and-conditions
  attribute_mapping = {
    "google.subject"             = "assertion.arn"
    "attribute.aws_account"      = "assertion.account"
    "attribute.aws_role"         = "assertion.arn.extract('assumed-role/{role}/')"
    "attribute.aws_ec2_instance" = "assertion.arn.extract('assumed-role/{role_and_session}').extract('{session}')"
  }
  attribute_condition = "assertion.arn.startsWith('arn:aws:sts::${data.aws_caller_identity.current.account_id}:assumed-role/${aws_iam_role.instance.name}')"
  aws {
    account_id = data.aws_caller_identity.current.account_id
  }
}

# Reference the pre-existing AWS IAM policy document for the instance role
data "aws_iam_policy_document" "instance_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# Create an AWS IAM role for the instance referencing the above policy
# that allows it to be assumed by EC2 instances
resource "aws_iam_role" "instance" {
  name = "${var.name}-instance"
  inline_policy {
    name = var.name
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = ["ec2:Describe*"]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
  assume_role_policy = data.aws_iam_policy_document.instance_assume_role_policy.json
}

# Create an AWS IAM instance profile for the instance role
resource "aws_iam_instance_profile" "instance_profile" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.instance.name
}

# Create an AWS instance for Coder that uses the instance profile
resource "aws_instance" "coder" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.aws_instance_type
  associate_public_ip_address = true
  ebs_block_device {
    delete_on_termination = true
    device_name           = "/dev/sda1"
    volume_size           = 100
    volume_type           = "gp3"
  }
  tags = {
    "Name" = var.name
  }
  key_name             = data.aws_key_pair.me.key_name
  iam_instance_profile = aws_iam_instance_profile.instance_profile.name
  security_groups      = [aws_security_group.ssh.name]
}

# Create a firewall rule to allow SSH access. We're not going to worry about setting up HTTP access for this demo.
resource "aws_security_group" "ssh" {
  name = "${var.name}-ssh"
  ingress {
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

resource "local_file" "instructions" {
  filename = "${path.module}/instructions.txt"
  content  = <<EOF
# 1. To create a GCP credential config file, run:
gcloud iam workload-identity-pools create-cred-config ${google_iam_workload_identity_pool_provider.provider.name} \
  --service-account ${google_service_account.instance_sa.email} \
  --service-account-token-lifetime-seconds=3600 \
  --aws \
  --enable-imdsv2 \
  --output-file gcp-creds.json

# 2. Copy the config file to the instance:
scp gcp-creds.json ubuntu@${aws_instance.coder.public_ip}:gcp-creds.json

# 3. SSH into the Coder AWS instance:
ssh ubuntu@${aws_instance.coder.public_ip}

# 4. Install Coder using the script
#    Optionally, you can specify a version:
#    curl -fsSL https://coder.com/install.sh | sh -s -- --version x.y.z
curl -fsSL https://coder.com/install.sh | sh -s --

# 4. Move the config file to the correct location:
sudo mv gcp-creds.json /etc/coder.d/gcp-creds.json

# 5. Set the GOOGLE_APPLICATION_CREDENTIALS environment variable in /etc/coder.d/coder.env and in your shell:
echo "GOOGLE_APPLICATION_CREDENTIALS=/etc/coder.d/gcp-creds.json" | sudo tee -a /etc/coder.d/coder.env
echo "export GOOGLE_APPLICATION_CREDENTIALS=/etc/coder.d/gcp-creds.json" | tee -a ~/.bashrc
source ~/.bashrc

# 5. Install the gcloud cli on the instance:
sudo snap install google-cloud-sdk --classic

# 6. Login to GCP with the credential file:
gcloud auth login --cred-file=/etc/coder.d/gcp-creds.json

# 7. Validate that the credentials work. If the command completes successfully, the credentials are valid:
gcloud config set project ${data.google_project.sandbox.project_id}

# 9. Enable and start Coder:
sudo systemctl enable coder
sudo systemctl start coder

# 10. Perform the Coder first-time setup, and follow the prompts:
coder login http://localhost:3000

# 11. Create the sample GCP template:
coder templates init --id gcp-linux
cd gcp-linux
coder templates create --var project_id="${data.google_project.sandbox.project_id}"

# 12. Create a workspace using the template:
coder create --template gcp-linux my-workspace
  EOF
}

output "instance_ip" {
  value = aws_instance.coder.public_ip
}

output "instructions_txt" {
  value = "IMPORTANT: Read the instructions in ${local_file.instructions.filename}"
}
