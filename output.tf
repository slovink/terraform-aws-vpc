output "vpc_id" {
  value = "${aws_vpc.coe-vpc.id}"
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = aws_subnet.public-subnet.*.id
}

output "private_subnets" {
  description = "List of IDs of public subnets"
  value       = aws_subnet.private-subnet.*.id
}