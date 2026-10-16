"""
AWS Lambda Handler: Threat Intelligence & Automated Malware Forensics Engine
Processa logs do Cowrie (S3), enriquece com GeoIP e AbuseIPDB, e analisa malwares e botnets capturados (VirusTotal + Análise Estática ELF/Script).
Runtime: Python 3.12 (Zero dependências externas pesadas - usa bibliotecas padrão hashlib, re, urllib e boto3)
"""

import os
import json
import hashlib
import re
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
ENRICHED_MALWARE_S3_PREFIX = os.environ.get("ENRICHED_MALWARE_S3_PREFIX", "enriched-malware/")
MALWARE_S3_PREFIX = os.environ.get("MALWARE_S3_PREFIX", "malware-samples/")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
DISCORD_WEBHOOK_URL = os.environ.get("DISCORD_WEBHOOK_URL", "")
TTL_DAYS = int(os.environ.get("TTL_DAYS", "60"))

# Cache em memória durante o ciclo de vida do container Lambda
GEOIP_CACHE = {}
ABUSE_CACHE = {}
VT_CACHE = {}


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


def get_virustotal_report(sha256_hash: str) -> dict:
    """
    Consulta a API pública gratuita v3 do VirusTotal para coletar taxa de detecção e classificação oficial.
    Se a chave de API não estiver configurada, executa fallback neutro gracioso.
    """
    if not VIRUSTOTAL_API_KEY:
        return {
            "vt_checked": False,
            "vt_positives": 0,
            "vt_total": 0,
            "malware_family": "Desconhecido (Sem API Key)",
            "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
        }

    if sha256_hash in VT_CACHE:
        return VT_CACHE[sha256_hash]

    url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY,
        "Accept": "application/json",
        "User-Agent": "Cowrie-Threat-Intel/2.0",
    }

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            data = body.get("data", {})
            attr = data.get("attributes", {})
            stats = attr.get("last_analysis_stats", {})
            positives = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values()) if stats else 0

            # Extrai classificação de família sugerida
            pop_class = attr.get("popular_threat_classification", {})
            family = pop_class.get("suggested_threat_label") or attr.get("meaningful_name") or "Malware"

            res = {
                "vt_checked": True,
                "vt_positives": positives,
                "vt_total": total,
                "malware_family": str(family),
                "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
            }
            VT_CACHE[sha256_hash] = res
            return res
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Amostra inédita ou zero-day não catalogada no VirusTotal
            res = {
                "vt_checked": True,
                "vt_positives": 0,
                "vt_total": 0,
                "malware_family": "Inédito / Zero-Day (Não Catalogado)",
                "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
            }
            VT_CACHE[sha256_hash] = res
            return res
        print(f"[!] Erro HTTP VirusTotal ({sha256_hash}): {e.code} - {e.reason}")
    except Exception as e:
        print(f"[!] Falha na consulta VirusTotal ({sha256_hash}): {e}")

    fallback = {
        "vt_checked": False,
        "vt_positives": 0,
        "vt_total": 0,
        "malware_family": "Desconhecido",
        "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256_hash}",
    }
    VT_CACHE[sha256_hash] = fallback
    return fallback


def inspect_binary_static(binary_data: bytes, sha256_hash: str) -> dict:
    """
    Executa análise estática autônoma no binário:
    - Verificação de Magic Header (ELF Linux, Script Shell, PE Windows)
    - Extração de strings e mineração de IoCs (IPs de C2 e URLs secundárias)
    - Classificação heurística de botnets (Mirai, Gafgyt, XMRig)
    """
    md5_hash = hashlib.md5(binary_data).hexdigest()
    file_size = len(binary_data)

    # 1. Identificação do formato do executável
    magic_type = "Arquivo Binário Genérico"
    if binary_data.startswith(b"\x7fELF"):
        arch_desc = "Linux"
        if len(binary_data) >= 20:
            e_machine = binary_data[18] | (binary_data[19] << 8)
            arch_map = {
                3: "x86 (i386)",
                62: "x86_64 (AMD64)",
                40: "ARM 32-bit",
                183: "AArch64 (ARM 64-bit)",
                8: "MIPS",
                10: "MIPS-II",
                20: "PowerPC",
                21: "PowerPC 64",
            }
            arch_desc = arch_map.get(e_machine, f"Machine {e_machine}")
        magic_type = f"ELF Binary ({arch_desc})"
    elif binary_data.startswith(b"MZ"):
        magic_type = "Windows PE Executable"
    elif binary_data.startswith(b"#!/") or b"bin/sh" in binary_data[:128] or b"bin/bash" in binary_data[:128]:
        magic_type = "Linux Shell Script"

    # 2. Extração de strings imprimíveis (ASCII >= 4 caracteres, limitado a 2 MB para proteção de RAM)
    raw_strings = re.findall(rb"[\x20-\x7e]{4,}", binary_data[:2097152])
    decoded_strings = [s.decode("utf-8", errors="ignore") for s in raw_strings]
    full_text = " ".join(decoded_strings).lower()

    # 3. Mineração de IPs de Command & Control (C2)
    ip_pattern = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    found_ips = ip_pattern.findall(" ".join(decoded_strings))
    c2_ips = []
    for ip in found_ips:
        if not ip.startswith(("127.", "10.", "192.168.", "172.16.", "0.0.", "255.255.")) and ip not in ("1.1.1.1", "8.8.8.8"):
            if ip not in c2_ips:
                c2_ips.append(ip)

    # 4. Mineração de URLs embutidas
    url_pattern = re.compile(r"https?://[^\s<>\"']+|ftp://[^\s<>\"']+")
    found_urls = url_pattern.findall(" ".join(decoded_strings))
    unique_urls = list(dict.fromkeys(found_urls))

    # 5. Classificação por assinaturas de botnet conhecidas
    yara_tags = []
    heuristic_family = "Desconhecido"

    if any(k in full_text for k in ["mirai", "busybox", "dvrhelper", "killer_kill", "post /cdn-cgi/"]):
        yara_tags.append("mirai_variant")
        heuristic_family = "Mirai Botnet"
    if any(k in full_text for k in ["gafgyt", "bashlite", "lizkebab", "qbot"]):
        yara_tags.append("gafgyt_variant")
        if heuristic_family == "Desconhecido":
            heuristic_family = "Gafgyt (Bashlite)"
    if any(k in full_text for k in ["stratum+tcp", "xmr", "monero", "xmrig", "cryptonight"]):
        yara_tags.append("cryptominer")
        heuristic_family = "Coinminer (XMRig)"
    if any(k in full_text for k in ["wget -q", "curl -o", "chmod 777", "chmod +x"]):
        yara_tags.append("payload_dropper")
        if heuristic_family == "Desconhecido":
            heuristic_family = "Malware Dropper"

    return {
        "sha256": sha256_hash,
        "md5": md5_hash,
        "file_size_bytes": file_size,
        "magic_type": magic_type,
        "extracted_ips": c2_ips[:15],
        "extracted_urls": unique_urls[:15],
        "yara_tags": yara_tags,
        "heuristic_family": heuristic_family,
    }


def send_discord_malware_alert(malware_item: dict):
    """Envia alerta prioritário no Discord com evidências do binário malicioso e link do VirusTotal"""
    if not DISCORD_WEBHOOK_URL:
        return

    sha = malware_item.get("sha256", "N/A")
    family = malware_item.get("malware_family", "Desconhecido")
    magic = malware_item.get("magic_type", "Desconhecido")
    vt_pos = malware_item.get("vt_positives", 0)
    vt_tot = malware_item.get("vt_total", 0)
    permalink = malware_item.get("vt_permalink", f"https://www.virustotal.com/gui/file/{sha}")
    size_kb = round(malware_item.get("file_size_bytes", 0) / 1024, 2)

    c2_list = malware_item.get("extracted_ips", [])
    c2_str = "\n".join(c2_list[:5]) if c2_list else "Nenhum IP embutido extraído"

    embed = {
        "title": "[ALERTA] Malware Interceptado e Analisado no Honeypot",
        "color": 10038562,  # Vermelho escuro (crítico)
        "fields": [
            {"name": "Família Identificada", "value": f"**{family}**", "inline": True},
            {"name": "Tipo / Arquitetura", "value": f"`{magic}`", "inline": True},
            {"name": "Detecções VirusTotal", "value": f"**{vt_pos}/{vt_tot}** motores", "inline": True},
            {"name": "Tamanho", "value": f"{size_kb} KB", "inline": True},
            {"name": "SHA256", "value": f"[`{sha[:16]}...`]({permalink})", "inline": False},
            {"name": "IoCs / C2s Detectados (Top 5)", "value": f"```text\n{c2_str}\n```", "inline": False},
        ],
        "footer": {"text": "Cowrie Malware Forensics Engine | AWS Serverless"},
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
        print(f"[!] Falha ao enviar notificação de malware no Discord: {e}")


def parse_cowrie_records(lines: list[str]) -> list[dict]:
    """
    Lê o log bruto JSON do Cowrie e agrega os eventos por sessão e por IP.
    """
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

        if ts:
            if not rec["first_seen"] or ts < rec["first_seen"]:
                rec["first_seen"] = ts
            if not rec["last_seen"] or ts > rec["last_seen"]:
                rec["last_seen"] = ts

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

    if enriched_event["successful_logins"] == 0 and not enriched_event["commands"]:
        return

    ip = enriched_event["ip_address"]
    country = enriched_event.get("country_name", "Desconhecido")
    score = enriched_event.get("abuse_score", 0)
    cmds = enriched_event.get("commands", [])
    cmds_str = "\n".join(cmds[:5]) if cmds else "Nenhum comando digitado"

    embed = {
        "title": "[ALERTA] Honeypot Comprometido (Ataque Confirmado)",
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


def process_malware_sample(bucket: str, key: str) -> dict:
    """
    Processa amostra binária de malware enviada para o prefixo malware-samples/
    Executa análise estática + VirusTotal e salva em enriched-malware/ para o Athena.
    """
    print(f"[+] Iniciando análise forense do malware s3://{bucket}/{key}...")
    response = s3_client.get_object(Bucket=bucket, Key=key)
    binary_data = response["Body"].read()

    file_hash = os.path.basename(key)
    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Análise estática local (ELF, strings, IoCs, heurística)
    static_info = inspect_binary_static(binary_data, file_hash)

    # 2. Consulta à API pública do VirusTotal
    vt_info = get_virustotal_report(file_hash)

    # 3. Consolidação da família da ameaça (VT prevalece sobre heurística se disponível)
    family = vt_info["malware_family"]
    if family in ("Desconhecido (Sem API Key)", "Desconhecido") and static_info["heuristic_family"] != "Desconhecido":
        family = static_info["heuristic_family"]

    malware_item = {
        "sha256": file_hash,
        "md5": static_info["md5"],
        "timestamp": now_iso,
        "file_name": file_hash,
        "file_size_bytes": static_info["file_size_bytes"],
        "magic_type": static_info["magic_type"],
        "malware_family": family,
        "vt_positives": vt_info["vt_positives"],
        "vt_total": vt_info["vt_total"],
        "vt_permalink": vt_info["vt_permalink"],
        "extracted_ips": static_info["extracted_ips"],
        "extracted_urls": static_info["extracted_urls"],
        "yara_tags": static_info["yara_tags"],
    }

    # 4. Grava registro JSON Lines no S3 para o Athena
    output_key = f"{ENRICHED_MALWARE_S3_PREFIX.rstrip('/')}/enriched_malware_{file_hash}.json"
    payload = json.dumps(malware_item, ensure_ascii=False) + "\n"

    try:
        s3_client.put_object(
            Bucket=bucket,
            Key=output_key,
            Body=payload.encode("utf-8"),
            ContentType="application/json",
            ServerSideEncryption="AES256",
        )
        print(f"[OK] Telemetria de malware gravada com sucesso em s3://{bucket}/{output_key}")
    except Exception as e:
        print(f"[!] Erro ao gravar telemetria forense de malware no S3 ({output_key}): {e}")

    # 5. Notificação imediata no Discord
    send_discord_malware_alert(malware_item)

    return malware_item


def lambda_handler(event, context):
    """
    Handler principal acionado pelo S3 (s3:ObjectCreated:*).
    Roteia automaticamente entre logs brutos e amostras de malware.
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

        # Rota A: Amostra binária de malware (malware-samples/)
        if key.startswith(MALWARE_S3_PREFIX.rstrip("/") + "/"):
            try:
                process_malware_sample(bucket, key)
                total_processed += 1
            except Exception as e:
                print(f"[!] Falha ao processar amostra de malware ({key}): {e}")
            continue

        # Rota B: Logs de texto do Honeypot (cowrie-logs/)
        if not key.startswith("cowrie-logs/"):
            print(f"[!] Objeto ignorado (fora dos prefixos suportados): {key}")
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
            geo = get_geoip_info(ip)
            abuse = get_abuseipdb_score(ip)

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
            send_discord_notification(item)

        if enriched_items:
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
