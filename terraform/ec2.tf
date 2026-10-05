# Busca a AMI oficial mais recente do Ubuntu 24.04 LTS (Noble Numbat)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Instância EC2 t3.micro para rodar o Cowrie Honeypot
resource "aws_instance" "honeypot_host" {
  count = var.enable_ec2_instance ? 1 : 0

  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.honeypot_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.honeypot_instance_profile.name
  key_name               = var.ssh_key_name != "" ? var.ssh_key_name : null

  associate_public_ip_address = true

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_size
    delete_on_termination = true
    encrypted             = true

    tags = {
      Name = "${var.project_name}-ebs"
    }
  }

  # User Data básico para preparar o host com Docker e reconfigurar SSH administrativo
  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Atualização e utilitários
              apt-get update -y
              apt-get install -y ca-certificates curl gnupg lsb-release unzip

              # Instala AWS CLI v2
              curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
              unzip awscliv2.zip
              ./aws/install
              rm -rf aws awscliv2.zip

              # Instala Docker
              install -m 0755 -d /etc/apt/keyrings
              curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
              chmod a+r /etc/apt/keyrings/docker.asc
              echo \
                "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
                $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
                tee /etc/apt/sources.list.d/docker.list > /dev/null
              apt-get update -y
              apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

              systemctl enable docker
              systemctl start docker
              usermod -aG docker ubuntu

              # Mudar a porta do SSH real do host para a porta administrativa (ex: 22022)
              # Liberando a porta 22 para o Cowrie
              systemctl stop ssh.socket 2>/dev/null || true
              systemctl disable ssh.socket 2>/dev/null || true
              sed -i 's/^[#]*Port .*/Port ${var.admin_ssh_port}/' /etc/ssh/sshd_config
              systemctl enable --now ssh.service
              systemctl restart ssh.service

              echo "Host preparado com sucesso para receber o Cowrie!" > /var/log/honeypot-init.log
              EOF

  tags = {
    Name = "${var.project_name}-ec2"
  }
}
