

module "labels" {
  source      = "https://github.com/slovink/terraform-aws-labels.git?ref=1.0.0"
  name        = var.name
  environment = var.environment
  managedby   = var.managedby
  label_order = var.label_order
  repository  = var.repository
}

#tfsec:ignore:aws-ec2-require-vpc-flow-logs-for-all-vpcs
resource "aws_vpc" "my_vpc" {
  cidr_block                           = var.cidr_block
  ipv4_ipam_pool_id                    = var.ipv4_ipam_pool_id
  ipv4_netmask_length                  = var.ipv4_netmask_length
  ipv6_cidr_block                      = var.ipv6_cidr_block
  ipv6_netmask_length                  = var.ipv4_netmask_length
  ipv6_ipam_pool_id                    = var.ipv6_ipam_pool_id
  ipv6_cidr_block_network_border_group = var.ipv6_cidr_block_network_border_group
  instance_tenancy                     = var.instance_tenancy
  enable_dns_support                   = var.enable_dns_support
  enable_network_address_usage_metrics = var.enable_network_address_usage_metrics
  enable_dns_hostnames                 = var.enabled_dns_hostnames
  assign_generated_ipv6_cidr_block     = var.assign_generated_ipv6_cidr_block
  tags                                 = module.labels.tags
}
resource "aws_vpc_ipv4_cidr_block_association" "default" {
  for_each   = toset(var.additional_cidr_block)
  vpc_id     = join("", aws_vpc.my_vpc[*].id)
  cidr_block = each.key
}
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.my_vpc.id

  tags = merge(
    module.labels.tags,
    {
      "Name" = format("%s-igw", module.labels.id)
    }
  )
}
resource "aws_egress_only_internet_gateway" "example" {
  count  = var.enable && var.enabled_ipv6_egress_only_internet_gateway ? 1 : 0
  vpc_id = join("", aws_vpc.my_vpc[*].id)
  tags   = module.labels.tags
}


resource "aws_default_security_group" "default" {
  vpc_id = join("", aws_vpc.my_vpc[*].id)
  dynamic "ingress" {
    for_each = var.default_security_group_ingress
    content {
      self             = lookup(ingress.value, "self", true)
      cidr_blocks      = compact(split(",", lookup(ingress.value, "cidr_blocks", "")))
      ipv6_cidr_blocks = compact(split(",", lookup(ingress.value, "ipv6_cidr_blocks", "")))
      prefix_list_ids  = compact(split(",", lookup(ingress.value, "prefix_list_ids", "")))
      security_groups  = compact(split(",", lookup(ingress.value, "security_groups", "")))
      description      = lookup(ingress.value, "description", null)
      from_port        = lookup(ingress.value, "from_port", 0)
      to_port          = lookup(ingress.value, "to_port", 0)
      protocol         = lookup(ingress.value, "protocol", "-1")
    }
  }
  dynamic "egress" {
    for_each = var.default_security_group_egress
    content {
      self             = lookup(egress.value, "self", true)
      cidr_blocks      = compact(split(",", lookup(egress.value, "cidr_blocks", "")))
      ipv6_cidr_blocks = compact(split(",", lookup(egress.value, "ipv6_cidr_blocks", "")))
      prefix_list_ids  = compact(split(",", lookup(egress.value, "prefix_list_ids", "")))
      security_groups  = compact(split(",", lookup(egress.value, "security_groups", "")))
      description      = lookup(egress.value, "description", null)
      from_port        = lookup(egress.value, "from_port", 0)
      to_port          = lookup(egress.value, "to_port", 0)
      protocol         = lookup(egress.value, "protocol", "-1")
    }
  }
  tags = merge(
    module.labels.tags,
    {
      "Name" = format("%s-vpc-default-sg", module.labels.id)
    }
  )
}
resource "aws_default_route_table" "default" {
  default_route_table_id = join("", aws_vpc.my_vpc[*].default_route_table_id)
  dynamic "route" {
    for_each = var.default_route_table_routes
    content {
      # One of the following destinations must be provided
      cidr_block                 = route.value.cidr_block
      ipv6_cidr_block            = lookup(route.value, "ipv6_cidr_block", null)
      destination_prefix_list_id = lookup(route.value, "destination_prefix_list_id", null)
      # One of the following targets must be provided
      egress_only_gateway_id    = lookup(route.value, "egress_only_gateway_id", null)
      gateway_id                = lookup(route.value, "gateway_id", null)
      instance_id               = lookup(route.value, "instance_id", null)
      nat_gateway_id            = lookup(route.value, "nat_gateway_id", null)
      network_interface_id      = lookup(route.value, "network_interface_id", null)
      transit_gateway_id        = lookup(route.value, "transit_gateway_id", null)
      vpc_endpoint_id           = lookup(route.value, "vpc_endpoint_id", null)
      vpc_peering_connection_id = lookup(route.value, "vpc_peering_connection_id", null)
    }
  }
  tags = merge(
    module.labels.tags,
    {
      "Name" = format("%s-default-rt", module.labels.id)
    }
  )
}
resource "aws_vpc_dhcp_options" "dns_resolver" {
  domain_name          = var.dhcp_options_domain_name
  domain_name_servers  = var.dhcp_options_domain_name_servers
  ntp_servers          = var.dhcp_options_ntp_servers
  netbios_name_servers = var.dhcp_options_netbios_name_servers
  netbios_node_type    = var.dhcp_options_netbios_node_type

  tags = merge(

    {
      Name = "foo-name"
    }
  )
}

resource "aws_vpc_dhcp_options_association" "dns_resolver" {
  vpc_id          = aws_vpc.my_vpc.id
  dhcp_options_id = join("", aws_vpc_dhcp_options.dns_resolver[*].id)
}
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

#tfsec:ignore:aws-kms-auto-rotate-keys
resource "aws_kms_key" "vvv" {
  deletion_window_in_days = var.kms_key_deletion_window

}
resource "aws_kms_key" "v" {
  deletion_window_in_days = var.kms_key_deletion_window
  enable_key_rotation     = var.enable_key_rotation
}

resource "aws_kms_alias" "vvv" {
  name          = format("alias/%s-flow-log-key", module.labels.id)
  target_key_id = join("", aws_kms_key.vvv[*].key_id)
}

resource "aws_kms_key_policy" "example" {
  key_id = join("", aws_kms_key.vvv[*].id)
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Id" : "key-default-1",
    "Statement" : [{
      "Sid" : "Enable IAM User Permissions",
      "Effect" : "Allow",
      "Principal" : {
        "AWS" : "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
      },
      "Action" : "kms:*",
      "Resource" : "*"
      },
      {
        "Effect" : "Allow",
        "Principal" : { "Service" : "logs.${data.aws_region.current.name}.amazonaws.com" },
        "Action" : [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ],
        "Resource" : "*"
      }
    ]
  })

}
#tfsec:ignore:aws-s3-block-public-acl
#tfsec:ignore:aws-s3-specify-public-access-block
#tfsec:ignore:aws-s3-enable-versioning
#tfsec:ignore:aws-s3-enable-bucket-logging
#tfsec:ignore:aws-kms-auto-rotate-keys
#tfsec:ignore: aws-s3-encryption-customer-key
#tfsec:ignore:aws-s3-no-public-buckets
#tfsec:ignore:aws-s3-ignore-public-acls
#tfsec:ignore:aws-s3-enable-bucket-encryption
#tfsec:ignore: aws-s3-block-public-acls
#tfsec:ignore:aws-s3-block-public-policy
#tfsec:ignore:aws-s3-encryption-customer-key
#tfsec:ignore:aws-s3-block-public-policy
#tfsec:ignore:aws-s3-block-public-acls
resource "aws_s3_bucket" "example" {
  bucket = var.flow_logs_bucket_name

}
resource "aws_s3_bucket_ownership_controls" "example" {
  bucket = join("", aws_s3_bucket.example[*].id)

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "example" {
  depends_on = [aws_s3_bucket_ownership_controls.example]

  bucket = join("", aws_s3_bucket.example[*].id)
  acl    = "private"
}
resource "aws_s3_bucket_public_access_block" "example" {
  bucket                  = join("", aws_s3_bucket.example[*].id)
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = join("", aws_s3_bucket.example[*].id)

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = join("", aws_kms_key.vvv[*].id)
      sse_algorithm     = var.s3_sse_algorithm //"aws:kms"
    }
  }
}
resource "aws_s3_bucket_policy" "block-http" {
  bucket = join("", aws_s3_bucket.example[*].id)

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "Blockhttp"
    Statement = [
      {
        "Sid" : "AllowSSLRequestsOnly",
        "Effect" : "Deny",
        "Principal" : "*",
        "Action" : "s3:*",
        "Resource" : [
          join("", aws_s3_bucket.example[*].arn),
          "${join("", aws_s3_bucket.example[*].arn)}/*",
        ],
        "Condition" : {
          "Bool" : {
            "aws:SecureTransport" : "false"
          }
        }
      },
    ]
  })
}
resource "aws_cloudwatch_log_group" "flow_log" {
  name              = format("%s-vpc-flow-log-cloudwatch_log_group", module.labels.id)
  retention_in_days = var.flow_log_cloudwatch_log_group_retention_in_days
  kms_key_id        = join("", aws_kms_key.vvv[*].arn)
  tags              = module.labels.tags
}
resource "aws_iam_role" "vpc_flow_log_cloudwatch" {
  name                 = format("%s-vpc-flow-log-role", module.labels.id)
  assume_role_policy   = join("", data.aws_iam_policy_document.flow_log_cloudwatch_assume_role[*].json)
  permissions_boundary = var.vpc_flow_log_permissions_boundary
  tags                 = module.labels.tags
}

data "aws_iam_policy_document" "flow_log_cloudwatch_assume_role" {
  statement {
    sid = "AWSVPCFlowLogsAssumeRole"
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
  }
}
resource "aws_iam_role_policy_attachment" "vpc_flow_log_cloudwatch" {
  role       = join("", aws_iam_role.vpc_flow_log_cloudwatch[*].name)
  policy_arn = join("", aws_iam_policy.vpc_flow_log_cloudwatch[*].arn)

}


resource "aws_iam_policy" "vpc_flow_log_cloudwatch" {
  name   = format("%s-vpc-flow-log-to-cloudwatch", module.labels.id)
  policy = join("", data.aws_iam_policy_document.vpc_flow_log_cloudwatch[*].json)
  tags   = module.labels.tags
}
#tfsec:ignore:aws-iam-no-policy-wildcards
#tfsec:ignore:aws-iam-no-policy-wildcards
data "aws_iam_policy_document" "vpc_flow_log_cloudwatch" {
  count = var.enable && var.enable_flow_log && var.flow_log_destination_arn == null && var.flow_log_destination_type == "cloud-watch-logs" && var.create_flow_log_cloudwatch_iam_role ? 1 : 0
  statement {
    sid    = "AWSVPCFlowLogsPushToCloudWatch"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogGroups",
      "logs:DescribeLogStreams",
    ]
    resources = ["*"]
  }
}
resource "aws_flow_log" "vpc_flow_log" {
  count                    = var.enable && var.enable_flow_log == true ? 1 : 0
  log_destination_type     = var.flow_log_destination_type
  log_destination          = var.flow_log_destination_arn == null ? (var.flow_log_destination_type == "s3" ? join("", aws_s3_bucket.example[*].arn) : join("", aws_cloudwatch_log_group.flow_log[*].arn)) : var.flow_log_destination_arn
  log_format               = var.flow_log_log_format
  iam_role_arn             = var.create_flow_log_cloudwatch_iam_role ? join("", aws_iam_role.vpc_flow_log_cloudwatch[*].arn) : var.flow_log_iam_role_arn
  traffic_type             = var.flow_log_traffic_type
  vpc_id                   = join("", aws_vpc.my_vpc[*].id)
  max_aggregation_interval = var.flow_log_max_aggregation_interval
  dynamic "destination_options" {
    for_each = var.flow_log_destination_type == "s3" ? [true] : []

    content {
      file_format                = var.flow_log_file_format
      hive_compatible_partitions = var.flow_log_hive_compatible_partitions
      per_hour_partition         = var.flow_log_per_hour_partition
    }
  }
  tags = module.labels.tags
}
resource "aws_default_network_acl" "default" {
  count                  = var.enable && var.aws_default_network_acl ? 1 : 0
  default_network_acl_id = join("", aws_vpc.my_vpc[*].default_network_acl_id)
  dynamic "ingress" {
    for_each = var.default_network_acl_ingress
    content {
      action          = ingress.value.action
      cidr_block      = lookup(ingress.value, "cidr_block", null)
      from_port       = ingress.value.from_port
      icmp_code       = lookup(ingress.value, "icmp_code", null)
      icmp_type       = lookup(ingress.value, "icmp_type", null)
      ipv6_cidr_block = lookup(ingress.value, "ipv6_cidr_block", null)
      protocol        = ingress.value.protocol
      rule_no         = ingress.value.rule_no
      to_port         = ingress.value.to_port
    }
  }
  dynamic "egress" {
    for_each = var.default_network_acl_egress
    content {
      action          = egress.value.action
      cidr_block      = lookup(egress.value, "cidr_block", null)
      from_port       = egress.value.from_port
      icmp_code       = lookup(egress.value, "icmp_code", null)
      icmp_type       = lookup(egress.value, "icmp_type", null)
      ipv6_cidr_block = lookup(egress.value, "ipv6_cidr_block", null)
      protocol        = egress.value.protocol
      rule_no         = egress.value.rule_no
      to_port         = egress.value.to_port
    }
  }
  tags = merge(
    module.labels.tags,
    {
      "Name" = format("%s-nacl", module.labels.id)
    }
  )
}
