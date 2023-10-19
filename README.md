# Coder AWS -> GCP workload identity demo

This repository contains Terraform configuration to set up a Coder instance running in AWS
configured to authenticate with GCP using workload identity federation:

The following resources are created:

- A Coder instance running in AWS
- An AWS IAM role for the Coder instance
- A GCP service account to be used by the Coder instance
- A GCP workload identity pool configured to allow the AWS role assumed by the Coder instance to
  authenticate as the GCP service account

## Prerequisites

- [Terraform](https://www.terraform.io/downloads.html)
- AWS account configured with AWS CLI
- GCP account and project configured with gcloud CLI
- AWS keypair (see [AWS documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/create-key-pairs.html))

## Usage

1. Run `terraform init` to initialize the Terraform configuration.

1. Edit the variables defined in `main.tf` as required.

1. Run `terraform apply` to apply the Terraform configuration.

    > Note: You must specify at least the variables `aws_keypair`, `gcp_project`, and `name`.

1. Follow the instructions in `instructions.txt` to complete the setup.

## Cleanup

> Note: before destroying the Terraform configuration, ensure you have deleted any Coder workspaces
> that were created using the Coder instance created by this Terraform configuration.
> These workspaces will not be deleted automatically when the Terraform configuration is destroyed.

1. Run `terraform destroy` to destroy all resources created by this Terraform configuration.
