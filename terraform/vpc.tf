# VPC dedicada para isolamento do ambiente de laboratório do Honeypot
resource "aws_vpc" "honeypot_vpc" {
  cidr_block           = "10.0.0.0/24"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

# Internet Gateway para acesso público da subnet
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.honeypot_vpc.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

# Subnet pública
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.honeypot_vpc.id
  cidr_block              = "10.0.0.0/26"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet"
  }
}

# Tabela de roteamento pública
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.honeypot_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

# Associação da subnet com a tabela de rotas pública
resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}
