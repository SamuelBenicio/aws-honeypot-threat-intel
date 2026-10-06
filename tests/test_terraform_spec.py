#!/usr/bin/env python3
"""
Testes estáticos de conformidade, segurança e boas práticas para Terraform:
- terraform/iam.tf (Princípio do Menor Privilégio - Least Privilege)
- terraform/security_groups.tf (Controle de Acesso de Rede e Egress)
- terraform/s3.tf (Bloqueio Público e Ciclo de Vida de Custos)
- terraform/ec2.tf (Criptografia de Disco e Parâmetros)
- .gitignore (Garantia de que nenhum estado ou segredo seja exposto)
"""

import os
import re
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TF_DIR = ROOT_DIR / "terraform"


class TestTerraformSecuritySpecs(unittest.TestCase):
    def setUp(self):
        self.iam_file = TF_DIR / "iam.tf"
        self.sg_file = TF_DIR / "security_groups.tf"
        self.s3_file = TF_DIR / "s3.tf"
        self.ec2_file = TF_DIR / "ec2.tf"
        self.variables_file = TF_DIR / "variables.tf"
        self.tfvars_example = TF_DIR / "terraform.tfvars.example"
        self.gitignore = ROOT_DIR / ".gitignore"

    def test_iam_least_privilege(self):
        """Valida que a IAM policy não concede permissões administrativas abusivas ('*' ou s3:*)."""
        content = self.iam_file.read_text(encoding="utf-8")

        # Não pode ter Action = "*"
        self.assertNotIn('"*"', content, "A IAM policy não deve conceder '*' irrestrito")
        self.assertNotIn('"s3:*"', content, "A IAM policy não deve conceder 's3:*'")

        # Deve conter apenas as ações estritamente necessárias para upload de logs
        self.assertIn("s3:PutObject", content)
        self.assertIn("s3:AbortMultipartUpload", content)
        self.assertIn("cowrie-logs/*", content, "O bucket ARN deve restringir o prefixo de escrita")

    def test_security_group_admin_port_isolation(self):
        """Garante que a porta de administração SSH usa variável dedicada e não 0.0.0.0/0 hardcoded."""
        content = self.sg_file.read_text(encoding="utf-8")

        # Verifica se o bloco de admin usa as variáveis corretas
        self.assertIn("var.admin_ssh_port", content)
        self.assertIn("var.admin_my_ip", content)

        # Garante regras restritas de EGRESS (sem 0.0.0.0/0 em ALL protocols)
        self.assertNotIn('protocol    = "-1"', content, "Egress não deve permitir todos os protocolos (-1)")
        self.assertIn("443", content, "Egress deve permitir HTTPS 443")
        self.assertIn("80", content, "Egress deve permitir HTTP 80")
        self.assertIn("53", content, "Egress deve permitir DNS 53")

    def test_variables_specification(self):
        """Valida que as variáveis de segurança padrão estão declaradas no variables.tf."""
        content = self.variables_file.read_text(encoding="utf-8")

        self.assertIn('variable "admin_ssh_port"', content)
        self.assertIn('default     = 22022', content)
        self.assertIn('variable "honeypot_ssh_port"', content)
        self.assertIn('default     = 22', content)

    def test_s3_bucket_public_access_block(self):
        """Garante que o S3 possui bloqueio total de acessos públicos habilitado."""
        content = self.s3_file.read_text(encoding="utf-8")

        self.assertIn("aws_s3_bucket_public_access_block", content)
        self.assertIn("block_public_acls       = true", content)
        self.assertIn("block_public_policy     = true", content)
        self.assertIn("ignore_public_acls      = true", content)
        self.assertIn("restrict_public_buckets = true", content)

    def test_s3_bucket_lifecycle_rules(self):
        """Garante que regras de ciclo de vida existem para prevenir custos no AWS Free Tier."""
        content = self.s3_file.read_text(encoding="utf-8")

        self.assertIn("aws_s3_bucket_lifecycle_configuration", content)
        self.assertIn("expiration", content)
        self.assertIn("days = 30", content, "Os logs devem expirar em 30 dias para respeitar o limite de 5 GB do S3")

    def test_ec2_root_volume_encrypted(self):
        """Garante que o volume EBS da instância EC2 é provisionado com criptografia em repouso ativada."""
        content = self.ec2_file.read_text(encoding="utf-8")

        self.assertIn("root_block_device", content)
        self.assertIn("encrypted             = true", content, "O disco EBS deve ser criptografado em repouso")

    def test_gitignore_protects_sensitive_files(self):
        """Valida que o .gitignore contém regras explícitas para chaves, tfstate e tfvars."""
        content = self.gitignore.read_text(encoding="utf-8")

        self.assertIn("*.pem", content)
        self.assertIn("*.tfvars", content)
        self.assertIn("*.tfstate", content)
        self.assertIn("honeypot-key.pem", content)

    def test_example_tfvars_sanitized(self):
        """Valida que terraform.tfvars.example existe como template seguro e documentado."""
        content = self.tfvars_example.read_text(encoding="utf-8")

        self.assertIn("admin_my_ip", content)
        self.assertIn("admin_ssh_port", content)
        self.assertIn("honeypot_ssh_port", content)

    def test_ec2_user_data_zero_touch_bootstrap(self):
        """Garante que o user_data da EC2 inicializa o Cowrie na porta 22 e agenda a sincronização S3."""
        content = self.ec2_file.read_text(encoding="utf-8")

        self.assertIn("docker compose up -d", content, "O user_data deve iniciar o container do Cowrie automaticamente")
        self.assertIn("sync_logs_to_s3.sh", content, "O user_data deve configurar o script de sincronização S3")
        self.assertIn("crontab", content, "O user_data deve configurar o agendamento no crontab")
        self.assertIn("cowrie.cfg", content, "O user_data deve criar o arquivo cowrie.cfg")
        self.assertIn("userdb.txt", content, "O user_data deve criar o arquivo userdb.txt")
        self.assertIn('"22:2222"', content, "O user_data deve expor a porta 22 para a porta interna 2222 do Cowrie")


if __name__ == "__main__":
    unittest.main()
