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

# Regra de Ciclo de Vida: expiração após 30 dias para não gerar custos de armazenamento
resource "aws_s3_bucket_lifecycle_configuration" "honeypot_logs_lifecycle" {
  bucket = aws_s3_bucket.honeypot_logs.id

  rule {
    id     = "expire-logs-30-days"
    status = "Enabled"

    filter {
      prefix = "cowrie-logs/"
    }

    expiration {
      days = 30
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }
}
