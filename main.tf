/**********************************************
 This will deploy one vpc
   - public subnet/private subnets based on variables
   - igw
   - nat-gateway
   - associated route tables
**********************************************/
resource "aws_vpc" "coe-vpc" {
   cidr_block           = "${var.vpc_cidr}"
   enable_dns_hostnames = "${var.enable_dns_hostnames}"
   tags = {
        Name        = "${var.vpc_name}"
        environment = "${var.environment}"
        Stack       = "COE-Applications"
   }
}

/* Internet-Gateways */
resource "aws_internet_gateway" "igw" {
   vpc_id = "${aws_vpc.coe-vpc.id}"
   tags = {
        Name         = "igw-pub-sub"
        environment  = "${var.environment}"
   }
}

/***** Routing information public subnet ***************/
resource "aws_route_table" "pub_rtb" {
   vpc_id = "${aws_vpc.coe-vpc.id}"
   route {
     cidr_block = "0.0.0.0/0"
     gateway_id ="${aws_internet_gateway.igw.id}"
   }
   tags = {
     Name        = "Public-RTB"
     environment = "${var.environment}"
   }
}
/**************** Public-subnet **********/
resource "aws_subnet" "public-subnet" {
   count             = "${length(var.public_subnet_cidrs)}"
   availability_zone = "${element(var.azs,count.index)}"
   cidr_block        = "${var.public_subnet_cidrs[count.index]}"
   vpc_id            = "${aws_vpc.coe-vpc.id}"
   tags = {
        Name        = "Public_Subnet-${count.index}"
        environment = "${var.environment}"
   }
}

resource "aws_route_table_association" "a-pub-sub" {
   count          = "${length(var.public_subnet_cidrs)}"
   subnet_id      = "${element(aws_subnet.public-subnet.*.id,count.index)}"
   route_table_id = "${element(aws_route_table.pub_rtb.*.id,count.index)}"
}

/********************Nat-Gateway **********************/
resource "aws_eip" "nat"{
   count         =  "${length(var.public_subnet_cidrs)}"
   vpc = true
}

resource "aws_nat_gateway" "ngw" {
    count         =  "${length(var.public_subnet_cidrs)}"
    allocation_id = "${element(aws_eip.nat.*.id,count.index)}"
    subnet_id     = "${element(aws_subnet.public-subnet.*.id,count.index)}"
    depends_on    = ["aws_internet_gateway.igw","aws_subnet.public-subnet"]
}

resource "aws_subnet" "private-subnet" {
   count             = "${length(var.private_subnet_cidrs)}"
   availability_zone = "${element(var.azs,count.index)}"
   cidr_block        = "${var.private_subnet_cidrs[count.index]}"
   vpc_id            = "${aws_vpc.coe-vpc.id}"
   tags = {
        Name        = "Private_Subnet-${count.index}"
        environment = "${var.environment}"
   }
   depends_on = ["aws_nat_gateway.ngw"]
}

resource "aws_subnet" "db-private-subnet" {
   count             = "${length(var.database_subnet_cidrs)}"
   availability_zone = "${element(var.azs,count.index)}"
   cidr_block        = "${var.database_subnet_cidrs[count.index]}"
   vpc_id            = "${aws_vpc.coe-vpc.id}"
   tags = {
        Name        = "Database_Subnet-${count.index}"
        environment = "${var.environment}"
   }
   depends_on = ["aws_nat_gateway.ngw"]
}
resource "aws_route_table" "pri_rtb" {
   count          =  "${length(var.public_subnet_cidrs)}"
   vpc_id = "${aws_vpc.coe-vpc.id}"
   route {
     cidr_block = "0.0.0.0/0"
     gateway_id = "${element(aws_nat_gateway.ngw.*.id,count.index)}"
   }
   tags = {
     Name        = "Private-RTB"
     environment = "${var.environment}"
   }
}
resource "aws_route_table_association" "a-priv-sub" {
   count          = "${length(var.private_subnet_cidrs)}"
   subnet_id      =  "${element(aws_subnet.private-subnet.*.id,count.index)}"
   route_table_id = "${element(aws_route_table.pri_rtb.*.id,count.index)}"
}


