"""
Testes Estáticos Estendidos para a Infraestrutura como Código (Terraform)
Valida conformidade de FinOps, segurança, IAM e arquitetura analítica:
- terraform/athena.tf
- terraform/grafana_iam.tf
- terraform/lambda.tf
- terraform/outputs.tf
"""

import os
import unittest
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
TF_DIR = ROOT_DIR / "terraform"


class TestTerraformExtendedSpecs(unittest.TestCase):
    def setUp(self):
        self.athena_tf = TF_DIR / "athena.tf"
        self.grafana_iam_tf = TF_DIR / "grafana_iam.tf"
        self.lambda_tf = TF_DIR / "lambda.tf"
        self.outputs_tf = TF_DIR / "outputs.tf"

    def test_athena_database_and_workgroup_specs(self):
        """Valida que o Athena possui database dedicada e WorkGroup com travas severas de FinOps"""
        content = self.athena_tf.read_text(encoding="utf-8")

        # Database
        self.assertIn('resource "aws_glue_catalog_database" "athena_db"', content)
        self.assertIn('"cowrie_threat_intel"', content)

        # WorkGroup
        self.assertIn('resource "aws_athena_workgroup" "analytics"', content)
        self.assertIn('name        = "cowrie_analytics"', content)
        self.assertIn('enforce_workgroup_configuration    = true', content)
        self.assertIn('bytes_scanned_cutoff_per_query = 104857600', content, "Trava de 100MB por query obrigatória")

        # Glue Table e SerDe
        self.assertIn('resource "aws_glue_catalog_table" "enriched_attacks"', content)
        self.assertIn('"org.openx.data.jsonserde.JsonSerDe"', content)
        self.assertIn('EXTERNAL_TABLE', content)
        self.assertIn('location      = "s3://${aws_s3_bucket.honeypot_logs.id}/enriched-telemetry/"', content)

    def test_athena_table_column_schema(self):
        """Valida que o esquema da tabela externa do Glue possui todas as colunas necessárias para o Grafana"""
        content = self.athena_tf.read_text(encoding="utf-8")

        expected_columns = [
            "ip_address",
            "timestamp",
            "first_seen",
            "country_code",
            "country_name",
            "city",
            "latitude",
            "longitude",
            "isp",
            "abuse_score",
            "total_reports",
            "sessions_count",
            "login_attempts",
            "successful_logins",
            "usernames",
            "passwords",
            "commands",
            "downloads_count",
        ]

        for col in expected_columns:
            self.assertIn(f'name = "{col}"', content, f"Coluna '{col}' deve estar definida na tabela Glue")

    def test_grafana_iam_least_privilege_policy(self):
        """Garante que a política IAM do Grafana não concede permissões administrativas abusivas"""
        content = self.grafana_iam_tf.read_text(encoding="utf-8")

        # Criação do usuário e access key
        self.assertIn('resource "aws_iam_user" "grafana_reader"', content)
        self.assertIn('resource "aws_iam_access_key" "grafana_reader_key"', content)

        # Ações estritamente analíticas
        self.assertIn('"athena:GetWorkGroup"', content)
        self.assertIn('"athena:StartQueryExecution"', content)
        self.assertIn('"athena:GetQueryExecution"', content)
        self.assertIn('"athena:GetQueryResults"', content)
        self.assertIn('"glue:GetTable"', content)
        self.assertIn('"glue:GetDatabase"', content)

        # Bloqueio de wildcard perigoso
        self.assertNotIn('"*"', [line.strip() for line in content.splitlines() if 'Action' in line])
        self.assertNotIn('"s3:*"', content)
        self.assertNotIn('"athena:*"', content)
        self.assertNotIn('"glue:*"', content)

    def test_lambda_provisioning_and_s3_event_trigger(self):
        """Valida configuração de runtime, memória, timeout e gatilho S3 da Lambda"""
        content = self.lambda_tf.read_text(encoding="utf-8")

        # Runtime e sizing
        self.assertIn('"python3.12"', content)
        self.assertIn('timeout          = 120', content)
        self.assertIn('memory_size      = 128', content)
        self.assertIn('handler          = "handler.lambda_handler"', content)

        # Gatilho de evento no S3
        self.assertIn('resource "aws_s3_bucket_notification" "bucket_notification"', content)
        self.assertIn('events              = ["s3:ObjectCreated:*"]', content)
        self.assertIn('filter_prefix       = "cowrie-logs/"', content)

        # Permissão de invocação concedida ao bucket
        self.assertIn('resource "aws_lambda_permission" "allow_s3_invocation"', content)
        self.assertIn('action        = "lambda:InvokeFunction"', content)
        self.assertIn('principal     = "s3.amazonaws.com"', content)

    def test_outputs_specifications(self):
        """Valida que outputs essenciais estão mapeados no Terraform"""
        content = self.outputs_tf.read_text(encoding="utf-8")
        grafana_tf_content = self.grafana_iam_tf.read_text(encoding="utf-8")

        self.assertIn('output "athena_workgroup_name"', content)
        self.assertIn('output "athena_database_name"', content)
        self.assertIn('output "athena_table_name"', content)
        self.assertIn('output "grafana_aws_access_key_id"', grafana_tf_content)
        self.assertIn('output "grafana_aws_secret_access_key"', grafana_tf_content)
        self.assertIn('sensitive   = true', grafana_tf_content, "Chave secreta do Grafana deve ser marcada como sensível")


if __name__ == "__main__":
    unittest.main()
