
output "id" {
  value       = join("", aws_vpc.my_vpc[*].id)
  description = "The ID of the VPC."
}
output "vpc_arn" {
  value       = join("", aws_vpc.my_vpc[*].arn)
  description = "The ARN of the VPC"
}

output "vpc_cidr_block" {
  value       = join("", aws_vpc.my_vpc[*].cidr_block)
  description = "The CIDR block of the VPC."
}

output "ipv6_cidr_block" {
  value       = join("", aws_vpc.my_vpc[*].ipv6_cidr_block)
  description = "The IPv6 CIDR block."
}

output "vpc_ipv6_association_id" {
  value       = join("", aws_vpc.my_vpc[*].ipv6_association_id)
  description = "The association ID for the IPv6 CIDR block."
}

output "ipv6_cidr_block_network_border_group" {
  value       = join("", aws_vpc.my_vpc[*].ipv6_cidr_block_network_border_group)
  description = "The IPv6 Network Border Group Zone name"
}

output "vpc_main_route_table_id" {
  value       = join("", aws_vpc.my_vpc[*].main_route_table_id)
  description = "The ID of the main route table associated with this VPC."
}

output "vpc_default_network_acl_id" {
  value       = join("", aws_vpc.my_vpc[*].default_network_acl_id)
  description = "The ID of the network ACL created by default on VPC creation."
}

output "vpc_default_security_group_id" {
  value       = join("", aws_vpc.my_vpc[*].default_security_group_id)
  description = "The ID of the security group created by default on VPC creation."
}

output "vpc_default_route_table_id" {
  value       = join("", aws_vpc.my_vpc[*].default_route_table_id)
  description = "The ID of the route table created by default on VPC creation."
}

output "tags" {
  value       = module.labels.tags
  description = "A mapping of tags to assign to the resource."
}

output "igw_id" {
  value       = join("", aws_internet_gateway.gw[*].id)
  description = "The ID of the Internet Gateway."
}

output "ipv6_egress_only_igw_id" {
  value       = join("", aws_egress_only_internet_gateway.example[*].id)
  description = "The ID of the egress-only Internet Gateway"
}

output "arn" {
  value       = join("", aws_flow_log.vpc_flow_log[*].arn)
  description = "Amazon Resource Name (ARN) of VPC"
}

