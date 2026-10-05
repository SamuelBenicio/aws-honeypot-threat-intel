variable "aws_region" {
  description = "Região da AWS para deploy dos recursos"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Ambiente (dev, lab, prod)"
  type        = string
  default     = "lab"
}

variable "project_name" {
  description = "Prefixo para nomear recursos do projeto"
  type        = string
  default     = "cowrie-threat-intel"
}

variable "admin_my_ip" {
  description = "Seu IP público com /32 para acesso SSH de administração (ex: '203.0.113.25/32')"
  type        = string
  default     = "0.0.0.0/0" # Recomenda-se trocar pelo IP público real no terraform.tfvars
}

variable "admin_ssh_port" {
  description = "Porta de administração SSH real do host (não padrão para evitar escaneamento)"
  type        = number
  default     = 22022
}

variable "honeypot_ssh_port" {
  description = "Porta onde o Honeypot Cowrie aceita conexões públicas"
  type        = number
  default     = 22
}

variable "instance_type" {
  description = "Tipo de instância EC2 (elegível ao Free Tier)"
  type        = string
  default     = "t3.micro"
}

variable "enable_ec2_instance" {
  description = "Defina true para criar a instância EC2 automaticamente com o Terraform"
  type        = bool
  default     = true
}

variable "ssh_key_name" {
  description = "Nome de uma Key Pair existente na AWS para acesso SSH (opcional se usar AWS SSM Session Manager)"
  type        = string
  default     = ""
}

variable "root_volume_size" {
  description = "Tamanho do disco EBS raiz em GB"
  type        = number
  default     = 8
}
