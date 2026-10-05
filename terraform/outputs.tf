output "s3_bucket_name" {
  description = "Nome do bucket S3 criado para os logs do Honeypot"
  value       = aws_s3_bucket.honeypot_logs.id
}

output "s3_bucket_arn" {
  description = "ARN do bucket S3"
  value       = aws_s3_bucket.honeypot_logs.arn
}

output "ec2_public_ip" {
  description = "IP público da instância Honeypot EC2"
  value       = length(aws_instance.honeypot_host) > 0 ? aws_instance.honeypot_host[0].public_ip : "N/A"
}

output "admin_ssh_command" {
  description = "Comando para conectar via SSH de administração"
  value       = length(aws_instance.honeypot_host) > 0 ? "ssh -p ${var.admin_ssh_port} ubuntu@${aws_instance.honeypot_host[0].public_ip}" : "N/A"
}

output "iam_role_name" {
  description = "Nome da Role IAM associada à EC2"
  value       = aws_iam_role.honeypot_ec2_role.name
}

output "security_group_id" {
  description = "ID do Security Group aplicado"
  value       = aws_security_group.honeypot_sg.id
}
