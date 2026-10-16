#!/usr/bin/env python3
"""
Utilitario de Diagnostico e Verificacao de Saude do Pipeline Honeypot (AWS)
Verifica o status de todas as camadas: EC2, SSM, S3, Lambda e Athena.
Suporta configuracao dinamica via argumentos CLI e variaveis de ambiente.
"""

import argparse
import os
import sys
import time
import boto3

DEFAULT_REGION = os.getenv("AWS_DEFAULT_REGION", os.getenv("AWS_REGION", "us-east-1"))
DEFAULT_INSTANCE_ID = os.getenv("HONEYPOT_INSTANCE_ID", "i-0cbc1920d1c90e101")
DEFAULT_BUCKET_NAME = os.getenv("HONEYPOT_BUCKET_NAME", "cowrie-threat-intel-logs-9628d6d2")
DEFAULT_LAMBDA_NAME = os.getenv("HONEYPOT_LAMBDA_NAME", "cowrie-threat-intel-enricher")
DEFAULT_ATHENA_WORKGROUP = os.getenv("HONEYPOT_ATHENA_WORKGROUP", "cowrie_analytics")
DEFAULT_ATHENA_DB = os.getenv("HONEYPOT_ATHENA_DB", "cowrie_threat_intel")


def parse_args(args=None):
    parser = argparse.ArgumentParser(
        description="Utilitario de Diagnostico e Verificacao de Saude do Pipeline Honeypot (AWS)"
    )
    parser.add_argument(
        "--region",
        default=DEFAULT_REGION,
        help="Regiao AWS (padrao: variavel AWS_REGION ou us-east-1)",
    )
    parser.add_argument(
        "--instance-id",
        default=DEFAULT_INSTANCE_ID,
        help="ID da instancia EC2 do Cowrie (padrao: HONEYPOT_INSTANCE_ID)",
    )
    parser.add_argument(
        "--bucket",
        default=DEFAULT_BUCKET_NAME,
        help="Nome do bucket S3 de telemetria (padrao: HONEYPOT_BUCKET_NAME)",
    )
    parser.add_argument(
        "--lambda-name",
        default=DEFAULT_LAMBDA_NAME,
        help="Nome da funcao AWS Lambda de enriquecimento (padrao: HONEYPOT_LAMBDA_NAME)",
    )
    parser.add_argument(
        "--workgroup",
        default=DEFAULT_ATHENA_WORKGROUP,
        help="Nome do workgroup FinOps do Amazon Athena (padrao: HONEYPOT_ATHENA_WORKGROUP)",
    )
    parser.add_argument(
        "--database",
        default=DEFAULT_ATHENA_DB,
        help="Nome do banco de dados no Glue/Athena (padrao: HONEYPOT_ATHENA_DB)",
    )
    parser.add_argument(
        "--ssm-wait-secs",
        type=int,
        default=3,
        help="Tempo base de espera entre checagens do SSM em segundos (padrao: 3)",
    )
    parser.add_argument(
        "--ssm-max-attempts",
        type=int,
        default=5,
        help="Numero maximo de tentativas de polling do SSM (padrao: 5)",
    )
    return parser.parse_args(args)


def check_pipeline_health(
    region: str = DEFAULT_REGION,
    instance_id: str = DEFAULT_INSTANCE_ID,
    bucket_name: str = DEFAULT_BUCKET_NAME,
    lambda_name: str = DEFAULT_LAMBDA_NAME,
    athena_workgroup: str = DEFAULT_ATHENA_WORKGROUP,
    athena_db: str = DEFAULT_ATHENA_DB,
    ssm_wait_secs: int = 3,
    ssm_max_attempts: int = 5,
):
    print("=" * 70)
    print("[*] DIAGNOSTICO DE SAUDE DO PIPELINE COWRIE THREAT INTEL")
    print("=" * 70)

    results = {}

    # 1. AWS Credentials
    try:
        sts = boto3.client("sts", region_name=region)
        caller = sts.get_caller_identity()
        print(f"[OK] AWS STS: Conectado como conta {caller['Account']} ({caller['Arn']})")
        results["sts"] = True
    except Exception as e:
        print(f"[FALHA] AWS STS: Erro de credenciais: {e}")
        results["sts"] = False
        return results

    # 2. Amazon S3
    try:
        s3 = boto3.client("s3", region_name=region)
        s3.head_bucket(Bucket=bucket_name)
        resp = s3.list_objects_v2(Bucket=bucket_name, Prefix="cowrie-logs/", MaxKeys=5)
        raw_count = resp.get("KeyCount", 0)
        resp_enr = s3.list_objects_v2(Bucket=bucket_name, Prefix="enriched-telemetry/", MaxKeys=5)
        enr_count = resp_enr.get("KeyCount", 0)
        print(f"[OK] Amazon S3: Bucket {bucket_name} acessivel (Objetos encontrados: raw={raw_count}, enriched={enr_count})")
        results["s3"] = True
    except Exception as e:
        print(f"[FALHA] Amazon S3: Erro no bucket {bucket_name}: {e}")
        results["s3"] = False

    # 3. AWS Lambda
    try:
        lmb = boto3.client("lambda", region_name=region)
        fn = lmb.get_function(FunctionName=lambda_name)
        conf = fn["Configuration"]
        print(f"[OK] AWS Lambda: {lambda_name} ativo (Runtime: {conf['Runtime']}, Memoria: {conf['MemorySize']} MB, Timeout: {conf['Timeout']}s)")
        results["lambda"] = True
    except Exception as e:
        print(f"[FALHA] AWS Lambda: Erro na funcao {lambda_name}: {e}")
        results["lambda"] = False

    # 4. Amazon Athena & Glue
    try:
        athena = boto3.client("athena", region_name=region)
        wg = athena.get_work_group(WorkGroup=athena_workgroup)
        state = wg["WorkGroup"]["State"]
        cutoff = wg["WorkGroup"]["Configuration"].get("BytesScannedCutoffPerQuery", "N/A")
        print(f"[OK] Amazon Athena: Workgroup {athena_workgroup} em estado {state} (Trava FinOps: {cutoff} bytes)")
        results["athena"] = True
    except Exception as e:
        print(f"[FALHA] Amazon Athena: Erro no workgroup {athena_workgroup}: {e}")
        results["athena"] = False

    # 5. EC2 & SSM Status
    try:
        ec2 = boto3.client("ec2", region_name=region)
        inst_resp = ec2.describe_instances(InstanceIds=[instance_id])
        state = inst_resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        ip = inst_resp["Reservations"][0]["Instances"][0].get("PublicIpAddress", "N/A")
        print(f"[OK] Amazon EC2: Instancia {instance_id} em estado {state} (IP Publico: {ip})")
        results["ec2"] = True

        ssm = boto3.client("ssm", region_name=region)
        conn = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
        )
        if conn.get("InstanceInformationList"):
            ping = conn["InstanceInformationList"][0]["PingStatus"]
            print(f"[OK] AWS SSM Agent: Conectado e respondendo (PingStatus: {ping})")
            results["ssm"] = True

            cmd = ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={
                    "commands": [
                        "docker inspect -f 'Running={{.State.Running}}' cowrie-honeypot 2>/dev/null || echo 'Running=false'",
                        "echo \"STATE_POS=$(cat /home/ubuntu/cowrie/.sync_last_position 2>/dev/null || echo 0)\"",
                        "echo \"INODE=$(cat /home/ubuntu/cowrie/.sync_last_inode 2>/dev/null || echo 0)\"",
                        "echo \"TOTAL_LINES=$(wc -l < /home/ubuntu/cowrie/var/log/cowrie/cowrie.json 2>/dev/null || echo 0)\""
                    ]
                }
            )
            cmd_id = cmd["Command"]["CommandId"]

            inv = None
            for attempt in range(1, ssm_max_attempts + 1):
                time.sleep(ssm_wait_secs)
                try:
                    inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=instance_id)
                    inv_status = inv.get("Status", "Pending")
                    if inv_status in ["Success", "Failed", "Cancelled", "TimedOut"]:
                        break
                except Exception as ssm_poll_err:
                    if attempt == ssm_max_attempts:
                        raise ssm_poll_err

            if inv and inv.get("Status") == "Success":
                stdout = inv.get("StandardOutputContent", "").strip()
                print("\n--- Telemetria da Instancia EC2 (via SSM) ---")
                for line in stdout.splitlines():
                    print(f"  {line}")
            elif inv:
                inv_status = inv.get("Status")
                stderr = inv.get("StandardErrorContent", "").strip()
                print(f"[FALHA] AWS SSM: Comando encerrou com status '{inv_status}'. Detalhes: {stderr}")
                results["ssm"] = False
            else:
                print("[FALHA] AWS SSM: Tempo limite esgotado ao aguardar conclusao do comando.")
                results["ssm"] = False
        else:
            print("[AVISO] AWS SSM: Instancia nao listada no SSM no momento.")
            results["ssm"] = False
    except Exception as e:
        print(f"[FALHA] EC2 / SSM: Erro ao consultar instancia {instance_id}: {e}")
        results["ec2"] = False

    print("=" * 70)
    all_ok = bool(results) and all(results.values())
    status_summary = "[OK] Verificacao de saude concluida com sucesso." if all_ok else "[FALHA] Verificacao de saude identificou inconsistencias."
    print(status_summary)
    print("=" * 70)
    return results


def main(cli_args=None):
    args = parse_args(cli_args)
    results = check_pipeline_health(
        region=args.region,
        instance_id=args.instance_id,
        bucket_name=args.bucket,
        lambda_name=args.lambda_name,
        athena_workgroup=args.workgroup,
        athena_db=args.database,
        ssm_wait_secs=args.ssm_wait_secs,
        ssm_max_attempts=args.ssm_max_attempts,
    )
    success = bool(results) and all(results.values())
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
