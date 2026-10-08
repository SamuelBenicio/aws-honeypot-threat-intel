# ==============================================================================
# Amazon Athena & AWS Glue Data Catalog para Threat Intelligence Analytics
# Camada Serverless de Consultas SQL para o Grafana Cloud
# ==============================================================================

# 1. Banco de Dados no AWS Glue / Athena
resource "aws_glue_catalog_database" "athena_db" {
  name        = "cowrie_threat_intel"
  description = "Banco de dados analítico para eventos enriquecidos do Cowrie Honeypot"
}

# 2. Athena Workgroup com Trava Financeira de FinOps
resource "aws_athena_workgroup" "analytics" {
  name        = "cowrie_analytics"
  description = "Workgroup exclusivo com limites rígidos de escaneamento de dados"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    # TRAVA FINANCEIRA FINOPS:
    # Aborta qualquer consulta que tente escanear mais de 100 MB de dados.
    # Como nossos logs têm poucos MBs, isso garante custo mensal abaixo de US$ 0,01
    # e impede qualquer surpresa caso uma query seja mal formulada.
    bytes_scanned_cutoff_per_query = 104857600 # 100 MB em bytes

    result_configuration {
      output_location = "s3://${aws_s3_bucket.honeypot_logs.id}/athena-query-results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = {
    Name        = "${var.project_name}-athena-workgroup"
    Environment = var.environment
  }
}

# 3. Tabela Externa no Glue Catalog mapeando os Logs Enriquecidos no S3
resource "aws_glue_catalog_table" "enriched_attacks" {
  database_name = aws_glue_catalog_database.athena_db.name
  name          = "enriched_attacks"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL              = "TRUE"
    "classification"      = "json"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.honeypot_logs.id}/enriched-telemetry/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "ignore.malformed.json" = "TRUE"
        "dots.in.keys"          = "FALSE"
        "case.insensitive"      = "TRUE"
      }
    }

    # Colunas analíticas consumidas pelo Grafana
    columns {
      name = "ip_address"
      type = "string"
    }

    columns {
      name = "timestamp"
      type = "string"
    }

    columns {
      name = "first_seen"
      type = "string"
    }

    columns {
      name = "country_code"
      type = "string"
    }

    columns {
      name = "country_name"
      type = "string"
    }

    columns {
      name = "city"
      type = "string"
    }

    columns {
      name = "latitude"
      type = "double"
    }

    columns {
      name = "longitude"
      type = "double"
    }

    columns {
      name = "isp"
      type = "string"
    }

    columns {
      name = "abuse_score"
      type = "int"
    }

    columns {
      name = "total_reports"
      type = "int"
    }

    columns {
      name = "sessions_count"
      type = "int"
    }

    columns {
      name = "login_attempts"
      type = "int"
    }

    columns {
      name = "successful_logins"
      type = "int"
    }

    columns {
      name = "usernames"
      type = "array<string>"
    }

    columns {
      name = "passwords"
      type = "array<string>"
    }

    columns {
      name = "commands"
      type = "array<string>"
    }

    columns {
      name = "downloads_count"
      type = "int"
    }
  }
}
