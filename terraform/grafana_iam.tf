# ==============================================================================
# IAM User & Políticas de Leitura para o Grafana Cloud
# Princípio do menor privilégio: Apenas executa queries no Athena e lê resultados no S3
# ==============================================================================

resource "aws_iam_user" "grafana_reader" {
  name = "${var.project_name}-grafana-reader"

  tags = {
    Name        = "${var.project_name}-grafana-reader"
    Purpose     = "Grafana Cloud Athena Reader"
    Environment = var.environment
  }
}

resource "aws_iam_access_key" "grafana_reader_key" {
  user = aws_iam_user.grafana_reader.name
}

resource "aws_iam_policy" "grafana_athena_policy" {
  name        = "${var.project_name}-grafana-athena-policy"
  description = "Permite ao Grafana Cloud consultar o Athena e ler os dados no S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # 1. Permissões de Execução e Listagem no Athena
      {
        Sid    = "AthenaQueryPermissions"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
          "athena:GetWorkGroup",
          "athena:ListWorkGroups",
          "athena:GetDataCatalog",
          "athena:ListDataCatalogs",
          "athena:GetDatabase",
          "athena:ListDatabases",
          "athena:GetTableMetadata",
          "athena:ListTableMetadata"
        ]
        Resource = "*"
      },
      # 2. Permissões de Leitura no AWS Glue Data Catalog
      {
        Sid    = "GlueCatalogReadPermissions"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetPartition",
          "glue:GetPartitions",
          "glue:BatchGetPartition"
        ]
        Resource = "*"
      },
      # 3. Permissões no S3 para Leitura de Dados e Gravação dos Resultados do Athena
      {
        Sid    = "S3AthenaDataAndResults"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.honeypot_logs.arn,
          "${aws_s3_bucket.honeypot_logs.arn}/*"
        ]
      },
      {
        Sid    = "S3AthenaPutQueryResults"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.honeypot_logs.arn}/athena-query-results/*"
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_grafana_policy" {
  user       = aws_iam_user.grafana_reader.name
  policy_arn = aws_iam_policy.grafana_athena_policy.arn
}

# Outputs com as credenciais que serão inseridas no Grafana Cloud
output "grafana_aws_access_key_id" {
  description = "Access Key ID para configurar a Data Source no Grafana Cloud"
  value       = aws_iam_access_key.grafana_reader_key.id
}

output "grafana_aws_secret_access_key" {
  description = "Secret Access Key para configurar a Data Source no Grafana Cloud"
  value       = aws_iam_access_key.grafana_reader_key.secret
  sensitive   = true
}
