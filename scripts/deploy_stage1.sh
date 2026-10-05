#!/usr/bin/env bash
# ==============================================================================
# Script de Deploy Alternativo via AWS CLI (Etapa 1)
# Pode ser executado localmente ou diretamente no AWS CloudShell
# ==============================================================================
set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
PROJECT_NAME="cowrie-threat-intel"
ADMIN_PORT=22022
HONEYPOT_PORT=22

echo "[+] Iniciando provisionamento da Etapa 1 na regiao ${REGION}..."

# 1. Gerar sufixo único
SUFFIX=$(openssl rand -hex 4 2>/dev/null || date +%s | tail -c 8)
BUCKET_NAME="${PROJECT_NAME}-logs-${SUFFIX}"

# 2. Criar S3 Bucket
echo "[+] Criando S3 Bucket: ${BUCKET_NAME}..."
if [ "${REGION}" == "us-east-1" ]; then
    aws s3api create-bucket --bucket "${BUCKET_NAME}" --region "${REGION}"
else
    aws s3api create-bucket --bucket "${BUCKET_NAME}" --region "${REGION}" \
        --create-bucket-configuration LocationConstraint="${REGION}"
fi

# Bloquear Acesso Público 100%
aws s3api put-public-access-block --bucket "${BUCKET_NAME}" \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Criptografia SSE-S3 AES256
aws s3api put-bucket-encryption --bucket "${BUCKET_NAME}" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

# Regra de Ciclo de Vida (Exclusão após 30 dias para Free Tier)
aws s3api put-bucket-lifecycle-configuration --bucket "${BUCKET_NAME}" \
    --lifecycle-configuration '{
        "Rules": [
            {
                "ID": "ExpireLogs30Days",
                "Status": "Enabled",
                "Filter": {"Prefix": "cowrie-logs/"},
                "Expiration": {"Days": 30}
            }
        ]
    }'

# 3. Criar IAM Role e Policy de menor privilégio
ROLE_NAME="${PROJECT_NAME}-ec2-role"
POLICY_NAME="${PROJECT_NAME}-s3-upload-policy"
INSTANCE_PROFILE_NAME="${PROJECT_NAME}-instance-profile"

echo "[+] Configurando IAM Role e Permissões com menor privilégio..."
TRUST_POLICY='{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}'

aws iam create-role --role-name "${ROLE_NAME}" --assume-role-policy-document "${TRUST_POLICY}" 2>/dev/null || true

# Anexa AWS Systems Manager (SSM)
aws iam attach-role-policy --role-name "${ROLE_NAME}" \
    --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"

# Cria e anexa política de menor privilégio para PutObject
UPLOAD_POLICY=$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowPutCowrieLogsOnly",
      "Effect": "Allow",
      "Action": ["s3:PutObject", "s3:AbortMultipartUpload"],
      "Resource": "arn:aws:s3:::${BUCKET_NAME}/cowrie-logs/*"
    }
  ]
}
EOF
)

POLICY_ARN=$(aws iam create-policy --policy-name "${POLICY_NAME}" --policy-document "${UPLOAD_POLICY}" --query 'Policy.Arn' --output text 2>/dev/null || \
  aws iam list-policies --query "Policies[?PolicyName=='${POLICY_NAME}'].Arn" --output text)

aws iam attach-role-policy --role-name "${ROLE_NAME}" --policy-arn "${POLICY_ARN}"

aws iam create-instance-profile --instance-profile-name "${INSTANCE_PROFILE_NAME}" 2>/dev/null || true
aws iam add-role-to-instance-profile --instance-profile-name "${INSTANCE_PROFILE_NAME}" --role-name "${ROLE_NAME}" 2>/dev/null || true

# 4. Criar VPC e Subnet
echo "[+] Criando VPC e Subnet..."
VPC_ID=$(aws ec2 create-vpc --cidr-block "10.0.0.0/24" --query 'Vpc.VpcId' --output text --region "${REGION}")
aws ec2 create-tags --resources "${VPC_ID}" --tags Key=Name,Value="${PROJECT_NAME}-vpc" --region "${REGION}"

IGW_ID=$(aws ec2 create-internet-gateway --query 'InternetGateway.InternetGatewayId' --output text --region "${REGION}")
aws ec2 attach-internet-gateway --vpc-id "${VPC_ID}" --internet-gateway-id "${IGW_ID}" --region "${REGION}"

SUBNET_ID=$(aws ec2 create-subnet --vpc-id "${VPC_ID}" --cidr-block "10.0.0.0/26" --query 'Subnet.SubnetId' --output text --region "${REGION}")
aws ec2 modify-subnet-attribute --subnet-id "${SUBNET_ID}" --map-public-ip-on-launch --region "${REGION}"

RTB_ID=$(aws ec2 create-route-table --vpc-id "${VPC_ID}" --query 'RouteTable.RouteTableId' --output text --region "${REGION}")
aws ec2 create-route --route-table-id "${RTB_ID}" --destination-cidr-block "0.0.0.0/0" --gateway-id "${IGW_ID}" --region "${REGION}"
aws ec2 associate-route-table --subnet-id "${SUBNET_ID}" --route-table-id "${RTB_ID}" --region "${REGION}"

# 5. Criar Security Group Restritivo
echo "[+] Criando Security Group com regras de menor privilégio..."
SG_ID=$(aws ec2 create-security-group \
    --group-name "${PROJECT_NAME}-sg" \
    --description "Security Group restrito para Cowrie Honeypot" \
    --vpc-id "${VPC_ID}" \
    --query 'GroupId' --output text --region "${REGION}")

# Ingress
# Porta 22 aberta para internet (Honeypot)
aws ec2 authorize-security-group-ingress --group-id "${SG_ID}" \
    --protocol tcp --port "${HONEYPOT_PORT}" --cidr "0.0.0.0/0" --region "${REGION}"

# Porta admin 22022
aws ec2 authorize-security-group-ingress --group-id "${SG_ID}" \
    --protocol tcp --port "${ADMIN_PORT}" --cidr "0.0.0.0/0" --region "${REGION}"

# Egress: Revogar padrão (0.0.0.0/0 all) e limitar a HTTPS (443), HTTP (80) e DNS (53)
aws ec2 revoke-security-group-egress --group-id "${SG_ID}" \
    --protocol "-1" --cidr "0.0.0.0/0" --region "${REGION}" 2>/dev/null || true

aws ec2 authorize-security-group-egress --group-id "${SG_ID}" \
    --protocol tcp --port 443 --cidr "0.0.0.0/0" --region "${REGION}"
aws ec2 authorize-security-group-egress --group-id "${SG_ID}" \
    --protocol tcp --port 80 --cidr "0.0.0.0/0" --region "${REGION}"
aws ec2 authorize-security-group-egress --group-id "${SG_ID}" \
    --protocol udp --port 53 --cidr "0.0.0.0/0" --region "${REGION}"
aws ec2 authorize-security-group-egress --group-id "${SG_ID}" \
    --protocol tcp --port 53 --cidr "0.0.0.0/0" --region "${REGION}"

echo "================================================================="
echo "Provisionamento da Etapa 1 Concluído com Sucesso!"
echo "S3 Bucket:         ${BUCKET_NAME}"
echo "VPC ID:            ${VPC_ID}"
echo "Subnet ID:         ${SUBNET_ID}"
echo "Security Group ID: ${SG_ID}"
echo "Instance Profile:  ${INSTANCE_PROFILE_NAME}"
echo "================================================================="
