# IAM Role para a instância EC2 do Honeypot
resource "aws_iam_role" "honeypot_ec2_role" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# Política restritiva de menor privilégio para gravação de logs no S3
resource "aws_iam_policy" "s3_upload_logs_policy" {
  name        = "${var.project_name}-s3-upload-policy"
  description = "Permite apenas envio de logs do Honeypot para o prefixo específico do S3"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowPutCowrieLogsOnly"
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:AbortMultipartUpload"
        ]
        Resource = "${aws_s3_bucket.honeypot_logs.arn}/cowrie-logs/*"
      }
    ]
  })
}

# Anexo da política de upload à Role
resource "aws_iam_role_policy_attachment" "attach_s3_upload" {
  role       = aws_iam_role.honeypot_ec2_role.name
  policy_arn = aws_iam_policy.s3_upload_logs_policy.arn
}

# Anexo da política SSM para permitir gerência via AWS Systems Manager Session Manager
# Vantagem: Dispensa abertura de portas de admin e chaves SSH fixas na máquina
resource "aws_iam_role_policy_attachment" "attach_ssm_core" {
  role       = aws_iam_role.honeypot_ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Instance Profile associado à EC2
resource "aws_iam_instance_profile" "honeypot_instance_profile" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.honeypot_ec2_role.name
}
