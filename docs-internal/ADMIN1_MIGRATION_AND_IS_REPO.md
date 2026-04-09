# admin1 Migration to aws-compute + is_repo Flag

## Current State

admin1 (`i-0df6b0145d1285b42`) is a manually-created EC2 instance in the
`coreinfra_prod` VPC. Not managed by Terraform.

### Instance Details

| Attribute | Value |
|-----------|-------|
| Instance ID | `i-0df6b0145d1285b42` |
| Type | `t3.medium` |
| AMI | `ami-09222573bc99a7788` (Ubuntu 24.04 Noble) |
| VPC | `vpc-02b0c54b3523324a3` (core_infra_prod) |
| Subnet | `subnet-01b71718b84203467` (us-west-2a, **public route table**) |
| Key pair | `core_infra` |
| Security group | `sg-0cb029338def4a791` |
| IAM profile | `admin1-prod-instance-profile` |
| Root volume | 20GB gp3 (`/dev/sda1`) |
| Data volume | 40GB gp3 (`/dev/sdh`) |
| Public IP | None |
| Internet access | **None** (public subnet + no public IP = no egress) |

### Problems

1. No internet access — in public subnet without public IP, needs NAT
2. Not Terraform-managed — drift risk, no audit trail
3. No S3 permissions for bootstrap bucket — can't run `bodega`

## Plan

### 1. Add `is_repo` flag to aws-compute module

**File:** `platform/aws/modules/aws-compute/variables.tf`

```hcl
variable "is_repo" {
  description = "Treat this instance as a repo manager. Grants read/write to the bootstrap S3 bucket."
  type        = bool
  default     = false
}

variable "bootstrap_bucket_arn" {
  description = "ARN of the bootstrap S3 bucket. Required when is_repo is true."
  type        = string
  default     = null
}
```

**File:** `platform/aws/modules/aws-compute/main.tf` (IAM section)

When `is_repo = true`, attach an additional IAM policy granting full S3 access
to the bootstrap bucket:

```hcl
resource "aws_iam_role_policy" "bodega" {
  count = var.is_repo ? 1 : 0
  name  = "${var.name}-bodega"
  role  = aws_iam_role.this.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:CreateBucket",
        "s3:PutBucketVersioning",
        "s3:PutBucketEncryption",
        "s3:PutPublicAccessBlock",
        "s3:GetPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketEncryption",
      ]
      Resource = [
        var.bootstrap_bucket_arn,
        "${var.bootstrap_bucket_arn}/*",
      ]
    }]
  })
}
```

No duplicate resources — each instance with `is_repo = true` gets its own
policy attachment on its own IAM role. The bucket itself is NOT created by
this module.

### 2. Instantiate admin1 via aws-compute

**File:** `platform/aws/main.tf`

```hcl
module "admin1" {
  source = "./modules/aws-compute"

  providers = {
    aws = aws.coreinfra_usw2
  }

  name         = "admin1-prod"
  environment  = "prod"
  vpc_id       = module.aws_vpc.coreinfra_prod_usw2_vpc_id
  subnet_ids   = module.aws_vpc.coreinfra_prod_usw2_subnet_ids
  # ... other vpc/netbox context ...

  instance_type    = "t3.medium"
  key_name         = "core_infra"
  ami_id           = "ami-09222573bc99a7788"
  root_volume_size = 20

  is_repo              = true
  bootstrap_bucket_arn = module.bootstrap.bucket_arn
}
```

### 3. Import existing resources into Terraform state

```bash
terraform import 'module.admin1.aws_instance.this[0]' i-0df6b0145d1285b42
terraform import 'module.admin1.aws_iam_role.this' admin1-prod-instance-role
terraform import 'module.admin1.aws_iam_instance_profile.this' admin1-prod-instance-profile
```

After import, run `terraform plan` to see drift. Fix any differences (e.g.,
the subnet will change from the public subnet to a private one with NAT egress).

### 4. Fix networking

After the two-tier subnet migration, admin1's subnet
(`subnet-01b71718b84203467`) will use the default route table (NAT egress)
instead of the public route table. admin1 will then have internet access
without needing a public IP.

If the two-tier migration hasn't been applied yet, admin1 needs to be moved
to a different subnet (one that uses the default route table with NAT).
