"""
Script de Mineração e Carga Inicial (Backfill) de Threat Intelligence
Lê o histórico de logs brutos locais, enriquece com GeoIP e carrega na pasta do Athena no S3
"""

import sys
import os
import json
from pathlib import Path
import boto3

# Adiciona o diretório da Lambda para reutilizar a lógica de enriquecimento
sys.path.insert(0, str(Path(__file__).parent.parent / "lambda"))
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

import handler

BUCKET_NAME = "cowrie-threat-intel-logs-9628d6d2"
S3_OUTPUT_KEY = "enriched-telemetry/enriched_historical_backfill.json"

def run_mining():
    print("=" * 65)
    print("[*] INICIANDO MINERACAO E ENRIQUECIMENTO DOS DADOS HISTORICOS")
    print("=" * 65)

    base_dir = Path(__file__).parent.parent / "logs_salvos"
    json_files = list(base_dir.glob("**/*.json"))

    if not json_files:
        print("[!] Nenhum arquivo de log bruto encontrado para mineração.")
        return

    print(f"[+] Total de arquivos de log brutos encontrados: {len(json_files)}")

    all_raw_lines = []
    for f in json_files:
        with open(f, "r", encoding="utf-8", errors="ignore") as fp:
            for line in fp:
                line = line.strip()
                if line:
                    all_raw_lines.append(line)

    print(f"[+] Total de eventos brutos extraídos: {len(all_raw_lines)}")
    print("[+] Agrupando eventos por atacante e extraindo telemetria...")
    aggregated_attacks = handler.parse_cowrie_records(all_raw_lines)
    print(f"[+] Total de IPs atacantes distintos identificados: {len(aggregated_attacks)}")

    print("[+] Minerando coordenadas geográficas (GeoIP) e operadoras (ISPs)...")
    enriched_records = []
    countries_found = set()

    for idx, atk in enumerate(aggregated_attacks, 1):
        ip = atk["ip"]
        geo = handler.get_geoip_info(ip)
        abuse = handler.get_abuseipdb_score(ip)

        countries_found.add(geo["country_name"])

        item = {
            "ip_address": ip,
            "timestamp": atk["timestamp"],
            "first_seen": atk["first_seen"],
            "country_code": geo["country_code"],
            "country_name": geo["country_name"],
            "city": geo["city"],
            "latitude": float(geo["latitude"]),
            "longitude": float(geo["longitude"]),
            "isp": geo.get("isp", "Desconhecido"),
            "abuse_score": abuse["abuse_score"],
            "total_reports": abuse["total_reports"],
            "sessions_count": atk["sessions_count"],
            "login_attempts": atk["login_attempts"],
            "successful_logins": atk["successful_logins"],
            "usernames": atk["usernames"],
            "passwords": atk["passwords"],
            "commands": atk["commands"],
            "downloads_count": atk["downloads_count"],
        }
        enriched_records.append(item)

        if idx % 15 == 0 or idx == len(aggregated_attacks):
            print(f"    -> Minerados {idx}/{len(aggregated_attacks)} atacantes...")

    print(f"\n[+] Países de origem minerados ({len(countries_found)}):")
    print(f"    {', '.join(sorted(list(countries_found)))}")

    # Gera payload JSON Lines para o Athena (OpenX JsonSerDe)
    jsonl_content = "\n".join(json.dumps(rec, ensure_ascii=False) for rec in enriched_records) + "\n"

    print(f"\n[+] Fazendo upload dos dados minerados para o Amazon S3...")
    print(f"    Bucket: {BUCKET_NAME}")
    print(f"    Caminho: {S3_OUTPUT_KEY}")

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=S3_OUTPUT_KEY,
        Body=jsonl_content.encode("utf-8"),
        ContentType="application/json",
        ServerSideEncryption="AES256",
    )

    print("=" * 65)
    print("[OK] MINERACAO E CARGA CONCLUIDAS COM SUCESSO NO S3!")
    print(f"   -> Pasta de destino: s3://{BUCKET_NAME}/enriched-telemetry/")
    print(f"   -> Registros estruturados prontos para o Athena: {len(enriched_records)}")
    print("=" * 65)

if __name__ == "__main__":
    run_mining()
