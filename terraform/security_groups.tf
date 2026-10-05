# Security Group para o Honeypot Host (EC2)
resource "aws_security_group" "honeypot_sg" {
  name        = "${var.project_name}-sg"
  description = "Security Group com regras restritas para o Honeypot Cowrie"
  vpc_id      = aws_vpc.honeypot_vpc.id

  # --- INGRESS RULES ---

  # 1. Porta pública de engodo (Honeypot Cowrie)
  ingress {
    description = "Honeypot SSH aberto para a Internet capturar ataques"
    from_port   = var.honeypot_ssh_port
    to_port     = var.honeypot_ssh_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 2. Porta de administração real (apenas para o IP do administrador)
  ingress {
    description = "SSH de Gestao restrito ao IP do Administrador"
    from_port   = var.admin_ssh_port
    to_port     = var.admin_ssh_port
    protocol    = "tcp"
    cidr_blocks = [var.admin_my_ip]
  }

  # --- EGRESS RULES (CRÍTICO: Menor privilégio para evitar uso como Botnet/Pivô) ---

  # 1. HTTPS (443): Necessário para APIs AWS (S3, SSM), Docker Registry e APIs de Threat Intel
  egress {
    description = "Permite HTTPS para APIs AWS e servicos externos legitimos"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 2. HTTP (80): Necessário para repositórios apt do Ubuntu e pacotes
  egress {
    description = "Permite HTTP para updates de pacotes do sistema operacional"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # 3. DNS (53 TCP/UDP): Resolução de nomes
  egress {
    description = "Permite DNS UDP para resolucao de nomes"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Permite DNS TCP para resolucao de nomes"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # NENHUMA OUTRA SAÍDA É PERMITIDA (ex: SSH de saída, porta 25 SMTP de spam, etc. estão bloqueadas por padrão)

  tags = {
    Name = "${var.project_name}-sg"
  }
}
