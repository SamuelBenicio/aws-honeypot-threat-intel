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

  # User Data com Zero-Touch Bootstrap: instala Docker, configura Cowrie, inicia o container na porta 22 e agenda o S3 sync
  user_data = <<-EOF
              #!/bin/bash
              set -e

              # Atualização e utilitários
              apt-get update -y
              apt-get install -y ca-certificates curl gnupg lsb-release unzip

              # Instala AWS CLI v2
              curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
              unzip -q awscliv2.zip
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

              # Estrutura de pastas do Cowrie
              COWRIE_DIR="/home/ubuntu/cowrie"
              mkdir -p "$COWRIE_DIR/var/log/cowrie"
              mkdir -p "$COWRIE_DIR/var/lib/cowrie/downloads"
              mkdir -p "$COWRIE_DIR/var/lib/cowrie/tty"

              # cowrie.cfg
              cat <<'CFG_EOF' > "$COWRIE_DIR/cowrie.cfg"
              [honeypot]
              hostname = srv-prod-app01
              log_path = var/log/cowrie
              download_path = var/lib/cowrie/downloads
              tty_path = var/lib/cowrie/tty
              fake_addr = 192.168.1.150

              [ssh]
              enabled = true
              listen_endpoints = tcp:2222:interface=0.0.0.0
              version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.7

              [telnet]
              enabled = false

              [output_jsonlog]
              enabled = true
              logfile = var/log/cowrie/cowrie.json
              epoch_timestamp = false
              CFG_EOF

              # userdb.txt
              cat <<'USER_EOF' > "$COWRIE_DIR/userdb.txt"
              root:x:123456
              root:x:password
              root:x:admin
              root:x:root
              admin:x:admin123
              admin:x:admin
              ubuntu:x:ubuntu
              support:x:support
              USER_EOF

              # docker-compose.yml
              cat <<'COMPOSE_EOF' > "$COWRIE_DIR/docker-compose.yml"
              services:
                cowrie:
                  image: cowrie/cowrie:latest
                  container_name: cowrie-honeypot
                  restart: unless-stopped
                  ports:
                    - "22:2222"
                  volumes:
                    - ./cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
                    - ./userdb.txt:/cowrie/cowrie-git/etc/userdb.txt:ro
                    - ./var/log/cowrie:/cowrie/cowrie-git/var/log/cowrie
                    - ./var/lib/cowrie/downloads:/cowrie/cowrie-git/var/lib/cowrie/downloads
                    - ./var/lib/cowrie/tty:/cowrie/cowrie-git/var/lib/cowrie/tty
                  environment:
                    - COWRIE_HONEYPOT_NAME=srv-prod-app01
                  cap_drop:
                    - ALL
                  security_opt:
                    - no-new-privileges:true
              COMPOSE_EOF

              # sync_logs_to_s3.sh
              cat <<SYNC_EOF > "$COWRIE_DIR/sync_logs_to_s3.sh"
              #!/usr/bin/env bash
              set -euo pipefail

              BUCKET_NAME="${aws_s3_bucket.honeypot_logs.id}"
              LOG_FILE="/home/ubuntu/cowrie/var/log/cowrie/cowrie.json"
              STATE_FILE="/home/ubuntu/cowrie/.sync_last_position"

              if [ ! -f "\$LOG_FILE" ]; then
                  exit 0
              fi

              DATE_PATH=\$(date -u +"year=%Y/month=%m/day=%d")
              TIMESTAMP=\$(date -u +"%Y%m%d_%H%M%S")
              TEMP_CHUNK="/tmp/cowrie_chunk_\$${TIMESTAMP}.json"

              LAST_POS=0
              if [ -f "\$STATE_FILE" ]; then
                  LAST_POS=\$(cat "\$STATE_FILE" 2>/dev/null || echo 0)
              fi

              TOTAL_LINES=\$(wc -l < "\$LOG_FILE")

              if [ "\$TOTAL_LINES" -lt "\$LAST_POS" ]; then
                  LAST_POS=0
              fi

              if [ "\$TOTAL_LINES" -gt "\$LAST_POS" ]; then
                  TAIL_COUNT=\$((TOTAL_LINES - LAST_POS))
                  tail -n "\$TAIL_COUNT" "\$LOG_FILE" > "\$TEMP_CHUNK"
                  
                  TARGET_S3="s3://\$${BUCKET_NAME}/cowrie-logs/\$${DATE_PATH}/cowrie_\$${TIMESTAMP}.json"
                  aws s3 cp "\$TEMP_CHUNK" "\$TARGET_S3" --only-show-errors
                  
                  echo "\$TOTAL_LINES" > "\$STATE_FILE"
                  rm -f "\$TEMP_CHUNK"
              fi
              SYNC_EOF

              chmod +x "$COWRIE_DIR/sync_logs_to_s3.sh"
              chown -R ubuntu:ubuntu "$COWRIE_DIR"
              chmod -R 777 "$COWRIE_DIR/var"

              # Iniciar o Cowrie via Docker Compose
              cd "$COWRIE_DIR"
              docker compose up -d

              # Agendar sincronização periódica a cada 5 minutos no cron da conta ubuntu
              (crontab -l -u ubuntu 2>/dev/null || true; echo "*/5 * * * * /home/ubuntu/cowrie/sync_logs_to_s3.sh >> /home/ubuntu/cowrie/cowrie-s3-sync.log 2>&1") | crontab -u ubuntu -

              echo "Honeypot Cowrie e Sincronização S3 iniciados com sucesso!" > /var/log/honeypot-init.log
              EOF

  tags = {
    Name = "${var.project_name}-ec2"
  }
}
