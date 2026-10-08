# ==============================================================================
# AWS Lambda: Motor Serverless de Threat Intelligence e Enriquecimento
# Disparado automaticamente pelo S3 na chegada de novos logs brutos do Cowrie
# ==============================================================================

# 1. Empacotamento do código Python em arquivo ZIP
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/handler.py"
  output_path = "${path.module}/lambda_payload.zip"
}

# 2. IAM Role de menor privilégio para a execução da Lambda
resource "aws_iam_role" "lambda_exec_role" {
  name = "${var.project_name}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# 3. IAM Policy restritiva para a Lambda
resource "aws_iam_policy" "lambda_policy" {
  name        = "${var.project_name}-lambda-policy"
  description = "Permite leitura de logs brutos e escrita de telemetria enriquecida no S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Leitura restrita de logs brutos
      {
        Sid    = "AllowReadCowrieRawLogs"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.honeypot_logs.arn}/cowrie-logs/*"
      },
      # Escrita restrita de logs enriquecidos para o Athena
      {
        Sid    = "AllowWriteEnrichedTelemetry"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.honeypot_logs.arn}/enriched-telemetry/*"
      },
      # Permissões padrão para logs no CloudWatch
      {
        Sid    = "AllowCloudWatchLogging"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "attach_lambda_policy" {
  role       = aws_iam_role.lambda_exec_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

# 4. Função Lambda Python 3.12 (Memória mínima 128 MB = Menor custo do Free Tier)
resource "aws_lambda_function" "threat_intel_processor" {
  function_name    = "${var.project_name}-enricher"
  description      = "Processa logs do Cowrie, enriquece com GeoIP e AbuseIPDB e salva para o Athena"
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  role             = aws_iam_role.lambda_exec_role.arn
  timeout          = 60
  memory_size      = 128

  environment {
    variables = {
      ENRICHED_S3_PREFIX  = "enriched-telemetry/"
      ABUSEIPDB_API_KEY   = var.abuseipdb_api_key
      DISCORD_WEBHOOK_URL = var.discord_webhook_url
    }
  }

  tags = {
    Name        = "${var.project_name}-enricher"
    Environment = var.environment
  }
}

# 5. Permissão para o Amazon S3 invocar a função Lambda
resource "aws_lambda_permission" "allow_s3_invocation" {
  statement_id  = "AllowExecutionFromS3Bucket"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_intel_processor.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.honeypot_logs.arn
}

# 6. S3 Event Notification Trigger (Gatilho automático)
# CRÍTICO: Dispara APENAS para o prefixo 'cowrie-logs/' para evitar loops recursivos!
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.honeypot_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.threat_intel_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "cowrie-logs/"
    filter_suffix       = ".json"
  }

  depends_on = [aws_lambda_permission.allow_s3_invocation]
}
