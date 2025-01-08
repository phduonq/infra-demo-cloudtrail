provider "aws" {
  region = "ap-southeast-2"
}

# Tạo S3 bucket để lưu trữ log của CloudTrail
resource "aws_s3_bucket" "cloudtrail_bucket" {
  bucket        = "my-cloudtrail-logs-bucket-duongpham"
  force_destroy = true

  lifecycle {
    prevent_destroy = false
  }
}

resource "aws_s3_bucket_versioning" "bucket_versioning" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id

  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "bucket_policy" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.cloudtrail_bucket.arn]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.cloudtrail_bucket.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_s3_bucket_policy" "bucket_policy" {
  bucket = aws_s3_bucket.cloudtrail_bucket.id
  policy = data.aws_iam_policy_document.bucket_policy.json
}

# Tên S3 để CloudTrail lắng nghe sự kiện
data "aws_s3_bucket" "important_bucket" {
  bucket = "my-cloudtrail-important-bucket-duongpham"
}

# Tạo IAM role cho CloudTrail để gửi log tới CloudWatch Logs
resource "aws_iam_role_policy" "cloudtrail_policy" {
  name = "CloudTrailPolicy"
  role = aws_iam_role.cloudtrail_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ],
        Resource = "arn:aws:logs:*:*:*"
      },
    ]
  })
}

resource "aws_iam_role" "cloudtrail_role" {
  name = "CloudTrail-To-CloudWatch-Role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# Tạo Log Group cho CloudWatch Logs
resource "aws_cloudwatch_log_group" "cloudtrail_log_group" {
  name              = "/aws/cloudtrail/cloudtrail-logs"
  retention_in_days = 30
}

# Tạo CloudTrail và cấu hình để gửi log tới CloudWatch Logs
resource "aws_cloudtrail" "demo" {
  name                       = "DemoCloudTrail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail_bucket.bucket
  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail_log_group.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail_role.arn
  enable_logging             = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["${data.aws_s3_bucket.important_bucket.arn}/"]
    }
  }
}
