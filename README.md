# Cloudtrail Security checking

Enables AWS Config and adds managed config rules with good defaults.
The following AWS Config Rules are supported:

* acm-certificate-expiration-check: Ensure ACM Certificates in your account are marked for expiration within the specified number of days.
* cloudtrail-enabled: Ensure CloudTrail is enabled.
* ec2-volume-inuse-check: Checks whether EBS volumes are attached to EC2 instances
* guardduty-enabled-centralized: Checks whether Amazon GuardDuty is enabled in your AWS account and region.
* instances-in-vpc: Ensure all EC2 instances run in a VPC.
* root-account-mfa-enabled: Ensure root AWS account has MFA enabled.
* rds-storage-encrypted: Checks whether storage encryption is enabled for your RDS DB instances.
* s3-bucket-public-write-prohibited: Checks that your S3 buckets do not allow public write access.

- Terraform `0.13.+`

And more...

## How to use

- The module has a lot of variables (needed) setting by default, see `variables.tf` for more information and custom configuration.

```hcl
module "security-checking" {
  source                 = "hendrixroa/config-security-check/aws"
  config_logs_bucket     = aws_s3_bucket.mybucket.bucket
  config_aggregator_name = "My Organization"
}
```
