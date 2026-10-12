# S3 Bucket para armazenamento de logs brutos do Honeypot (cowrie.json)
resource "aws_s3_bucket" "honeypot_logs" {
  bucket        = "${var.project_name}-logs-${random_id.suffix.hex}"
  force_destroy = true # Facilita limpeza no encerramento do lab

  tags = {
    Name = "${var.project_name}-logs"
  }
}

# Bloqueio estrito de acesso público (Block Public Access)
resource "aws_s3_bucket_public_access_block" "honeypot_logs_pab" {
  bucket = aws_s3_bucket.honeypot_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Habilitação de Criptografia padrão (SSE-S3 / AES256 - sem custo adicional)
resource "aws_s3_bucket_server_side_encryption_configuration" "honeypot_logs_encryption" {
  bucket = aws_s3_bucket.honeypot_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Regras de Ciclo de Vida: Gestão de Retenção, Proteção de FinOps e Limpeza de Temporários
resource "aws_s3_bucket_lifecycle_configuration" "honeypot_logs_lifecycle" {
  bucket = aws_s3_bucket.honeypot_logs.id

  # 1. Retenção de logs brutos do Honeypot (cowrie-logs/)
  rule {
    id     = "expire-raw-logs"
    status = "Enabled"

    filter {
      prefix = "cowrie-logs/"
    }

    expiration {
      days = var.raw_logs_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }

  # 2. Retenção de telemetria analítica enriquecida (enriched-telemetry/)
  # Previne que o volume acumulado ultrapasse a trava de 100 MB do Athena
  rule {
    id     = "expire-enriched-telemetry"
    status = "Enabled"

    filter {
      prefix = "enriched-telemetry/"
    }

    expiration {
      days = var.enriched_logs_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }

  # 3. Purga de resultados temporários de consultas do Athena (athena-query-results/)
  # Evita acúmulo de dezenas de milhares de arquivos CSV órfãos gerados pelo Grafana
  rule {
    id     = "expire-athena-query-results"
    status = "Enabled"

    filter {
      prefix = "athena-query-results/"
    }

    expiration {
      days = var.athena_results_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }

  # 4. Retenção de binários e scripts maliciosos reais (malware-samples/)
  rule {
    id     = "expire-malware-samples"
    status = "Enabled"

    filter {
      prefix = "malware-samples/"
    }

    expiration {
      days = var.raw_logs_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }

  # 5. Retenção da telemetria forense enriquecida de malwares (enriched-malware/)
  rule {
    id     = "expire-enriched-malware"
    status = "Enabled"

    filter {
      prefix = "enriched-malware/"
    }

    expiration {
      days = var.enriched_logs_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }
}


