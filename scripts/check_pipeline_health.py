#!/usr/bin/env python3
"""
Utilitario de Diagnostico e Verificacao de Saude do Pipeline Honeypot (AWS)
Verifica o status de todas as camadas: EC2, SSM, S3, Lambda e Athena.
"""

import sys
import time
import boto3

REGION = "us-east-1"
INSTANCE_ID = "i-0cbc1920d1c90e101"
BUCKET_NAME = "cowrie-threat-intel-logs-9628d6d2"
LAMBDA_NAME = "cowrie-threat-intel-enricher"
ATHENA_WORKGROUP = "cowrie_analytics"
ATHENA_DB = "cowrie_threat_intel"


def check_pipeline_health(ssm_wait_secs: int = 3):
    print("=" * 70)
    print("[*] DIAGNOSTICO DE SAUDE DO PIPELINE COWRIE THREAT INTEL")
    print("=" * 70)

    results = {}

    # 1. AWS Credentials
    try:
        sts = boto3.client("sts", region_name=REGION)
        caller = sts.get_caller_identity()
        print(f"[OK] AWS STS: Conectado como conta {caller['Account']} ({caller['Arn']})")
        results["sts"] = True
    except Exception as e:
        print(f"[FALHA] AWS STS: Erro de credenciais: {e}")
        results["sts"] = False
        return results

    # 2. Amazon S3
    try:
        s3 = boto3.client("s3", region_name=REGION)
        s3.head_bucket(Bucket=BUCKET_NAME)
        resp = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix="cowrie-logs/", MaxKeys=5)
        raw_count = resp.get("KeyCount", 0)
        resp_enr = s3.list_objects_v2(Bucket=BUCKET_NAME, Prefix="enriched-telemetry/", MaxKeys=5)
        enr_count = resp_enr.get("KeyCount", 0)
        print(f"[OK] Amazon S3: Bucket {BUCKET_NAME} acessivel (Objetos encontrados: raw={raw_count}, enriched={enr_count})")
        results["s3"] = True
    except Exception as e:
        print(f"[FALHA] Amazon S3: Erro no bucket {BUCKET_NAME}: {e}")
        results["s3"] = False

    # 3. AWS Lambda
    try:
        lmb = boto3.client("lambda", region_name=REGION)
        fn = lmb.get_function(FunctionName=LAMBDA_NAME)
        conf = fn["Configuration"]
        print(f"[OK] AWS Lambda: {LAMBDA_NAME} ativo (Runtime: {conf['Runtime']}, Memoria: {conf['MemorySize']} MB, Timeout: {conf['Timeout']}s)")
        results["lambda"] = True
    except Exception as e:
        print(f"[FALHA] AWS Lambda: Erro na funcao {LAMBDA_NAME}: {e}")
        results["lambda"] = False

    # 4. Amazon Athena & Glue
    try:
        athena = boto3.client("athena", region_name=REGION)
        wg = athena.get_work_group(WorkGroup=ATHENA_WORKGROUP)
        state = wg["WorkGroup"]["State"]
        cutoff = wg["WorkGroup"]["Configuration"].get("BytesScannedCutoffPerQuery", "N/A")
        print(f"[OK] Amazon Athena: Workgroup {ATHENA_WORKGROUP} em estado {state} (Trava FinOps: {cutoff} bytes)")
        results["athena"] = True
    except Exception as e:
        print(f"[FALHA] Amazon Athena: Erro no workgroup {ATHENA_WORKGROUP}: {e}")
        results["athena"] = False

    # 5. EC2 & SSM Status
    try:
        ec2 = boto3.client("ec2", region_name=REGION)
        inst_resp = ec2.describe_instances(InstanceIds=[INSTANCE_ID])
        state = inst_resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        ip = inst_resp["Reservations"][0]["Instances"][0].get("PublicIpAddress", "N/A")
        print(f"[OK] Amazon EC2: Instancia {INSTANCE_ID} em estado {state} (IP Publico: {ip})")
        results["ec2"] = True

        ssm = boto3.client("ssm", region_name=REGION)
        conn = ssm.describe_instance_information(
            Filters=[{"Key": "InstanceIds", "Values": [INSTANCE_ID]}]
        )
        if conn.get("InstanceInformationList"):
            ping = conn["InstanceInformationList"][0]["PingStatus"]
            print(f"[OK] AWS SSM Agent: Conectado e respondendo (PingStatus: {ping})")
            results["ssm"] = True

            cmd = ssm.send_command(
                InstanceIds=[INSTANCE_ID],
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
            time.sleep(ssm_wait_secs)
            inv = ssm.get_command_invocation(CommandId=cmd_id, InstanceId=INSTANCE_ID)
            stdout = inv.get("StandardOutputContent", "").strip()
            print("\n--- Telemetria da Instancia EC2 (via SSM) ---")
            for line in stdout.splitlines():
                print(f"  {line}")
        else:
            print("[AVISO] AWS SSM: Instancia nao listada no SSM no momento.")
            results["ssm"] = False
    except Exception as e:
        print(f"[FALHA] EC2 / SSM: Erro ao consultar instancia {INSTANCE_ID}: {e}")
        results["ec2"] = False

    print("=" * 70)
    print("[OK] Verificacao de saude concluida.")
    print("=" * 70)
    return results


if __name__ == "__main__":
    check_pipeline_health()
