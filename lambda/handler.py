"""
AWS Lambda Handler: Threat Intelligence & Enrichment Engine
Processa logs do Cowrie (S3), enriquece com GeoIP e AbuseIPDB, e persiste no DynamoDB.
Runtime: Python 3.12 (Zero dependências externas pesadas - usa bibliotecas padrão urllib e boto3)
"""

import os
import json
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone, timedelta
from decimal import Decimal
from collections import defaultdict
import boto3

# Inicialização de clientes AWS
s3_client = boto3.client("s3")

# Variáveis de ambiente configuráveis
ENRICHED_S3_PREFIX = os.environ.get("ENRICHED_S3_PREFIX", "enriched-telemetry/")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
TTL_DAYS = int(os.environ.get("TTL_DAYS", "30"))

# Cache em memória durante o ciclo de vida do container Lambda
GEOIP_CACHE = {}
ABUSE_CACHE = {}


def get_geoip_info(ip_address: str) -> dict:
    """
    Obtém metadados geográficos (País, Cidade, Latitude, Longitude) via serviço público rápido.
    Possui cache em memória para evitar chamadas redundantes para o mesmo IP.
    """
    if ip_address in GEOIP_CACHE:
        return GEOIP_CACHE[ip_address]

    # IPs privados/locais
    if ip_address.startswith(("10.", "172.16.", "192.168.", "127.")):
        return {
            "country_code": "LOCAL",
            "country_name": "Rede Interna",
            "city": "Localhost",
            "latitude": Decimal("0.0"),
            "longitude": Decimal("0.0"),
        }

    url = f"https://ipwho.is/{ip_address}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Cowrie-Threat-Intel/2.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if data.get("success", False):
                res = {
                    "country_code": data.get("country_code", "XX"),
                    "country_name": data.get("country", "Desconhecido"),
                    "city": data.get("city", "Desconhecido"),
                    "latitude": Decimal(str(round(data.get("latitude", 0.0), 4))),
                    "longitude": Decimal(str(round(data.get("longitude", 0.0), 4))),
                    "isp": data.get("connection", {}).get("isp", "Desconhecido"),
                }
                GEOIP_CACHE[ip_address] = res
                return res
    except Exception as e:
        print(f"[!] Falha na resolução GeoIP para {ip_address}: {e}")

    # Fallback seguro
    fallback = {
        "country_code": "XX",
        "country_name": "Desconhecido",
        "city": "Desconhecido",
        "latitude": Decimal("0.0"),
        "longitude": Decimal("0.0"),
        "isp": "Desconhecido",
    }
    GEOIP_CACHE[ip_address] = fallback
    return fallback


def get_abuseipdb_score(ip_address: str) -> dict:
    """
    Consulta o score de reputação e histórico de abuso no AbuseIPDB.
    Se a chave de API não estiver definida, retorna valores neutros de forma graciosa.
    """
    if not ABUSEIPDB_API_KEY:
        return {
            "abuse_score": 0,
            "total_reports": 0,
            "is_whitelisted": False,
            "abuse_checked": False,
        }

    if ip_address in ABUSE_CACHE:
        return ABUSE_CACHE[ip_address]

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip_address)}&maxAgeInDays=90"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
        "User-Agent": "Cowrie-Threat-Intel/2.0",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=4) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            data = body.get("data", {})
            res = {
                "abuse_score": int(data.get("abuseConfidenceScore", 0)),
                "total_reports": int(data.get("totalReports", 0)),
                "is_whitelisted": bool(data.get("isWhitelisted", False)),
                "abuse_checked": True,
            }
            ABUSE_CACHE[ip_address] = res
            return res
    except urllib.error.HTTPError as e:
        print(f"[!] Erro HTTP AbuseIPDB para {ip_address}: {e.code} - {e.reason}")
    except Exception as e:
        print(f"[!] Falha na consulta AbuseIPDB para {ip_address}: {e}")

    fallback = {
        "abuse_score": 0,
        "total_reports": 0,
        "is_whitelisted": False,
        "abuse_checked": False,
    }
    ABUSE_CACHE[ip_address] = fallback
    return fallback


def parse_cowrie_records(lines: list[str]) -> list[dict]:
    """
    Lê o log bruto JSON do Cowrie e agrega os eventos por sessão e por IP.
    """
    # Agregação por IP atacante
    attacks = defaultdict(lambda: {
        "first_seen": None,
        "last_seen": None,
        "sessions": set(),
        "login_attempts": 0,
        "successful_logins": 0,
        "usernames": set(),
        "passwords": set(),
        "commands": [],
        "downloads": [],
    })

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue

        ip = evt.get("src_ip")
        if not ip:
            continue

        ts = evt.get("timestamp")
        eid = evt.get("eventid", "")
        sid = evt.get("session")

        rec = attacks[ip]
        if sid:
            rec["sessions"].add(sid)

        # Atualiza limites temporais
        if ts:
            if not rec["first_seen"] or ts < rec["first_seen"]:
                rec["first_seen"] = ts
            if not rec["last_seen"] or ts > rec["last_seen"]:
                rec["last_seen"] = ts

        # Classificação do evento
        if eid in ("cowrie.login.success", "cowrie.login.failed"):
            rec["login_attempts"] += 1
            user = evt.get("username")
            pwd = evt.get("password")
            if user:
                rec["usernames"].add(user)
            if pwd:
                rec["passwords"].add(pwd)
            if eid == "cowrie.login.success":
                rec["successful_logins"] += 1

        elif eid == "cowrie.command.input":
            cmd = evt.get("input")
            if cmd and cmd not in rec["commands"]:
                rec["commands"].append(cmd)

        elif eid == "cowrie.session.file_download":
            shasum = evt.get("shasum")
            dest = evt.get("destfile")
            if shasum:
                rec["downloads"].append({"sha256": shasum, "path": dest})

    # Converte para formato estruturado
    results = []
    now = datetime.now(timezone.utc)
    ttl_epoch = int((now + timedelta(days=TTL_DAYS)).timestamp())

    for ip, data in attacks.items():
        results.append({
            "ip": ip,
            "timestamp": data["last_seen"] or now.isoformat(),
            "first_seen": data["first_seen"] or now.isoformat(),
            "sessions_count": len(data["sessions"]),
            "login_attempts": data["login_attempts"],
            "successful_logins": data["successful_logins"],
            "usernames": sorted(list(data["usernames"]))[:20],
            "passwords": sorted(list(data["passwords"]))[:20],
            "commands": data["commands"][:30],
            "downloads_count": len(data["downloads"]),
            "downloads": data["downloads"][:10],
            "ttl_timestamp": ttl_epoch,
        })

    return results


def send_discord_notification(enriched_event: dict):
    """Envia alerta imediato no Discord quando um ataque crítico ocorre (login bem sucedido ou malware)"""
    if not DISCORD_WEBHOOK_URL:
        return

    # Só notifica se houve login aceito ou comandos executados
    if enriched_event["successful_logins"] == 0 and not enriched_event["commands"]:
        return

    ip = enriched_event["ip_address"]
    country = enriched_event.get("country_name", "Desconhecido")
    score = enriched_event.get("abuse_score", 0)
    cmds = enriched_event.get("commands", [])
    cmds_str = "\n".join(cmds[:5]) if cmds else "Nenhum comando digitado"

    embed = {
        "title": "🚨 Honeypot Comprometido (Ataque Confirmado)",
        "color": 15158332 if score >= 80 else 16753920,
        "fields": [
            {"name": "IP Atacante", "value": f"`{ip}` ({country})", "inline": True},
            {"name": "Abuse Score", "value": f"**{score}%**", "inline": True},
            {"name": "Logins com Sucesso", "value": str(enriched_event["successful_logins"]), "inline": True},
            {"name": "Comandos Digitados (Top 5)", "value": f"```bash\n{cmds_str}\n```", "inline": False},
        ],
        "footer": {"text": "Cowrie Threat Intel Pipeline | AWS Serverless"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    try:
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=json.dumps({"embeds": [embed]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "Cowrie-Discord-Notifier"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            pass
    except Exception as e:
        print(f"[!] Falha ao enviar notificação Discord: {e}")


def lambda_handler(event, context):
    """
    Handler principal acionado pelo S3 (s3:ObjectCreated:*).
    """
    print(f"[+] Iniciando processamento de evento S3: {json.dumps(event)}")

    records = event.get("Records", [])
    total_processed = 0

    for record in records:
        s3_info = record.get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name")
        key = urllib.parse.unquote_plus(s3_info.get("object", {}).get("key", ""))

        if not bucket or not key:
            continue

        print(f"[+] Baixando arquivo s3://{bucket}/{key}...")
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
            content = response["Body"].read().decode("utf-8")
            lines = content.splitlines()
        except Exception as e:
            print(f"[!] Erro ao ler objeto do S3 ({key}): {e}")
            continue

        aggregated_events = parse_cowrie_records(lines)
        print(f"[+] Encontrados {len(aggregated_events)} atacantes distintos no arquivo {key}")

        enriched_items = []
        for atk in aggregated_events:
            ip = atk["ip"]
            # 1. Enriquecimento GeoIP
            geo = get_geoip_info(ip)

            # 2. Enriquecimento AbuseIPDB
            abuse = get_abuseipdb_score(ip)

            # 3. Montagem do item final estruturado para o Athena
            item = {
                "ip_address": ip,
                "timestamp": atk["timestamp"],
                "first_seen": atk["first_seen"],
                "country_code": geo["country_code"],
                "country_name": geo["country_name"],
                "city": geo["city"],
                "latitude": float(geo["latitude"]),
                "longitude": float(geo["longitude"]),
                "isp": geo.get("isp", abuse.get("isp", "Desconhecido")),
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
            enriched_items.append(item)
            total_processed += 1
            # Notifica Discord em caso de logins/malware
            send_discord_notification(item)

        # 4. Grava o lote enriquecido em JSON Lines no S3 para o Athena
        if enriched_items:
            # Mantém formato compatível com o OpenX JsonSerDe (um objeto JSON por linha)
            jsonl_payload = "\n".join(json.dumps(it, ensure_ascii=False) for it in enriched_items) + "\n"
            base_filename = os.path.basename(key)
            output_key = f"{ENRICHED_S3_PREFIX.rstrip('/')}/enriched_{base_filename}"

            try:
                print(f"[+] Gravando telemetria enriquecida em s3://{bucket}/{output_key}...")
                s3_client.put_object(
                    Bucket=bucket,
                    Key=output_key,
                    Body=jsonl_payload.encode("utf-8"),
                    ContentType="application/json",
                    ServerSideEncryption="AES256",
                )
                print(f"[OK] {len(enriched_items)} registros gravados com sucesso para o Athena.")
            except Exception as e:
                print(f"[!] Erro ao salvar arquivo enriquecido no S3 ({output_key}): {e}")

    print(f"[OK] Processamento concluído com sucesso. Total de eventos enriquecidos: {total_processed}")
    return {"statusCode": 200, "total_processed": total_processed}
