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
      # Leitura restrita de logs brutos e amostras de malware
      {
        Sid    = "AllowReadCowrieRawLogsAndMalware"
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = [
          "${aws_s3_bucket.honeypot_logs.arn}/cowrie-logs/*",
          "${aws_s3_bucket.honeypot_logs.arn}/malware-samples/*"
        ]
      },
      # Escrita restrita de logs e malwares enriquecidos para o Athena
      {
        Sid    = "AllowWriteEnrichedTelemetryAndMalware"
        Effect = "Allow"
        Action = [
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.honeypot_logs.arn}/enriched-telemetry/*",
          "${aws_s3_bucket.honeypot_logs.arn}/enriched-malware/*"
        ]
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
  timeout          = 120
  memory_size      = 128

  environment {
    variables = {
      ENRICHED_S3_PREFIX         = "enriched-telemetry/"
      ENRICHED_MALWARE_S3_PREFIX = "enriched-malware/"
      MALWARE_S3_PREFIX          = "malware-samples/"
      ABUSEIPDB_API_KEY          = var.abuseipdb_api_key
      VIRUSTOTAL_API_KEY         = var.virustotal_api_key
      DISCORD_WEBHOOK_URL        = var.discord_webhook_url
      TTL_DAYS                   = tostring(var.enriched_logs_retention_days)
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
# Dispara para logs brutos (cowrie-logs/) e para amostras binárias (malware-samples/)
resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.honeypot_logs.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.threat_intel_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "cowrie-logs/"
    filter_suffix       = ".json"
  }

  lambda_function {
    lambda_function_arn = aws_lambda_function.threat_intel_processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "malware-samples/"
  }

  depends_on = [aws_lambda_permission.allow_s3_invocation]
}
