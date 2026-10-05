#!/usr/bin/env python3
"""
Gerador de Relatório Consolidado de Threat Intelligence
Analisa todos os logs reais capturados pelo Honeypot e gera métricas detalhadas.
"""

import glob
import json
import urllib.request
from collections import Counter
from datetime import datetime

def generate_report():
    files = glob.glob('logs_salvos/year=2026/month=10/day=01/*.json')
    all_events = []
    for f in files:
        with open(f, 'r', encoding='utf-8') as fp:
            for line in fp:
                if line.strip():
                    try:
                        all_events.append(json.loads(line))
                    except:
                        pass

    ips = [e.get('src_ip') for e in all_events if e.get('src_ip')]
    unique_ips = Counter(ips)
    
    logins = [(e.get('username'), e.get('password')) for e in all_events if e.get('eventid') in ('cowrie.login.success', 'cowrie.login.failed')]
    commands = [e.get('input') for e in all_events if e.get('eventid') == 'cowrie.command.input']
    
    # Geolocation dos top 10 IPs
    top_ips = unique_ips.most_common(10)
    geo_info = {}
    print("[+] Consultando geolocalização dos IPs atacantes...")
    for ip, count in top_ips:
        try:
            req = urllib.request.Request(f"http://ip-api.com/json/{ip}", headers={"User-Agent": "ThreatIntel/1.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                geo_info[ip] = {
                    "country": data.get("country", "Desconhecido"),
                    "city": data.get("city", ""),
                    "org": data.get("org", data.get("isp", "Desconhecido"))
                }
        except Exception:
            geo_info[ip] = {"country": "Desconhecido", "city": "", "org": "N/A"}

    # Gera Relatório Markdown
    report_path = "logs_salvos/RELATORIO_THREAT_INTEL_REAL.md"
    with open(report_path, "w", encoding="utf-8") as out:
        out.write("# 🚨 Relatório de Threat Intelligence: Invasores Reais Capturados\n\n")
        out.write(f"**Data da Coleta:** 01/10/2026  \n")
        out.write(f"**Período de Monitoramento:** ~20 horas contínuas na AWS  \n")
        out.write(f"**Status do Honeypot:** 100% Operacional e Ativo  \n\n")
        out.write("---\n\n")

        out.write("## 📊 Resumo Executivo das Ameaças\n\n")
        out.write(f"- **Total de Eventos Registrados:** `{len(all_events):,}`\n")
        out.write(f"- **Endereços IP Únicos de Atacantes:** `{len(unique_ips)}`\n")
        out.write(f"- **Tentativas de Autenticação Forçada (Brute-Force):** `{len(logins)}`\n")
        out.write(f"- **Comandos Maliciosos Injetados na Shell:** `{len(commands)}`\n\n")
        out.write("---\n\n")

        out.write("## 🌍 Top 10 IPs Atacantes e Origem Geográfica\n\n")
        out.write("| Endereço IP | Eventos | País / Cidade | Provedor / ASN |\n")
        out.write("| :--- | :--- | :--- | :--- |\n")
        for ip, count in top_ips:
            info = geo_info.get(ip, {})
            loc = f"{info.get('country', '')} ({info.get('city', '')})" if info.get('city') else info.get('country', '')
            out.write(f"| `{ip}` | **{count}** | {loc} | {info.get('org', '')} |\n")
        out.write("\n---\n\n")

        out.write("## 🔑 Principais Credenciais Testadas pelos Bots (Dicionário de Força Bruta)\n\n")
        out.write("| Usuário Alvo | Senha Testada | Frequência |\n")
        out.write("| :--- | :--- | :--- |\n")
        for cred, count in Counter(logins).most_common(15):
            out.write(f"| `{cred[0]}` | `{cred[1]}` | {count}x |\n")
        out.write("\n---\n\n")

        out.write("## 💻 Comandos Mais Injetados pelos Invasores na Máquina\n\n")
        out.write("Estes são os scripts reais que os invasores dispararam assim que o Honeypot aceitou a conexão:\n\n")
        for cmd, count in Counter(commands).most_common(8):
            out.write(f"### ⚙️ Executado {count}x:\n")
            out.write(f"```bash\n{cmd}\n```\n\n")

        out.write("---\n\n")
        out.write("## 🔎 Análise Tática dos Ataques Capturados\n\n")
        out.write("1. **Reconhecimento de Hardware & OS:** Os comandos `uname -s -v -n -r -m` e `cat /proc/cpuinfo` servem para os robôs identificarem o número de núcleos de CPU e a arquitetura para baixar o binário correto de malware (ARM, x86 ou x64).\n")
        out.write("2. **Caça a Mineradores Concorrentes:** O comando `ps -ef | grep '[Mm]iner'` é clássico de campanhas de **Crypto-Jacking**. O bot procura se outro invasor já estava usando o servidor para minerar criptomoeda para 'matar' o processo rival e colocar o dele.\n")
        out.write("3. **Procura por MikroTik RouterOS:** O comando `/ip cloud print` tenta descobrir se o servidor é um roteador de borda MikroTik vulnerável.\n")
        out.write("4. **Teste de Shell Dropper:** O comando `printf \"#!/bin/bash\\necho \\\"xxxxxx\\\"\\n\" > filter && chmod +x filter` testa se o diretório local permite execução de scripts antes de baixar o payload principal.\n")

    print(f"[+] Relatório gerado com sucesso em: {report_path}")

if __name__ == "__main__":
    generate_report()
