#!/usr/bin/env python3
"""
Utilitário de Conversão e Formatação de Telemetria do Cowrie
Converte arquivos brutos JSON Lines (.json) em relatórios humanos legíveis (.md e .txt)
"""

import sys
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

def parse_cowrie_file(json_file_path):
    sessions = defaultdict(lambda: {
        "start_time": "",
        "end_time": "",
        "ip": "",
        "port": "",
        "client_version": "",
        "hassh": "",
        "logins": [],
        "commands": [],
        "files_downloaded": [],
        "duration_ms": 0,
        "events": []
    })

    with open(json_file_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line)
            sid = data.get("session", "unknown")
            eid = data.get("eventid", "")
            ts = data.get("timestamp", "")
            msg = data.get("message", "")

            sess = sessions[sid]
            sess["events"].append(data)

            if eid == "cowrie.session.connect":
                sess["start_time"] = ts
                sess["ip"] = data.get("src_ip", "")
                sess["port"] = data.get("src_port", "")
            elif eid == "cowrie.client.version":
                sess["client_version"] = data.get("version", "")
            elif eid == "cowrie.client.kex":
                sess["hassh"] = data.get("hassh", "")
            elif eid in ("cowrie.login.success", "cowrie.login.failed"):
                sess["logins"].append({
                    "user": data.get("username", ""),
                    "password": data.get("password", ""),
                    "status": "SUCESSO" if "success" in eid else "FALHA",
                    "time": ts
                })
            elif eid == "cowrie.command.input":
                sess["commands"].append({
                    "cmd": data.get("input", ""),
                    "time": ts
                })
            elif eid == "cowrie.session.file_download":
                sess["files_downloaded"].append({
                    "sha256": data.get("shasum", msg.split("SHA-256 ")[-1].split(" ")[0] if "SHA-256 " in msg else "N/A"),
                    "url": data.get("url", "Entrada via terminal/redirecionamento")
                })
            elif eid == "cowrie.session.closed":
                sess["end_time"] = ts
                sess["duration_ms"] = data.get("duration_ms", 0)

    return sessions


def generate_markdown_report(sessions, input_file, output_file):
    with open(output_file, "w", encoding="utf-8") as out:
        out.write(f"# 🛡️ Relatório de Telemetria de Cibersegurança (Cowrie Honeypot)\n\n")
        out.write(f"**Arquivo Fonte:** `{Path(input_file).name}`  \n")
        out.write(f"**Total de Sessões Registradas:** `{len(sessions)}`  \n")
        out.write(f"**Data de Geração:** `{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}`\n\n")
        out.write("---\n\n")

        for idx, (sid, sess) in enumerate(sessions.items(), 1):
            ip = sess["ip"] or "Desconhecido"
            port = sess["port"] or "N/A"
            client = sess["client_version"] or "Não informado"
            start = sess["start_time"]
            duration = f"{sess['duration_ms'] / 1000:.2f}s" if sess["duration_ms"] else "N/A"
            
            out.write(f"## 📍 Sessão #{idx}: `{sid}`\n\n")
            out.write(f"| Atributo | Detalhe |\n")
            out.write(f"| :--- | :--- |\n")
            out.write(f"| **IP de Origem** | `{ip}` (Porta `{port}`) |\n")
            out.write(f"| **Horário UTC** | `{start}` (Duração: `{duration}`) |\n")
            out.write(f"| **Software do Atacante (SSH)** | `{client}` |\n")
            if sess["hassh"]:
                out.write(f"| **Fingerprint Criptográfico (HASSH)** | `{sess['hassh']}` |\n")
            out.write("\n")

            # Credenciais testadas
            if sess["logins"]:
                out.write("### 🔑 Credenciais Testadas (Força Bruta / Dicionário)\n")
                out.write("| Horário | Usuário | Senha | Resultado |\n")
                out.write("| :--- | :--- | :--- | :--- |\n")
                for log in sess["logins"]:
                    tag = "🟢 **ACEITA** (Engodo)" if log["status"] == "SUCESSO" else "🔴 RECUSADA"
                    out.write(f"| `{log['time']}` | `{log['user']}` | `{log['password']}` | {tag} |\n")
                out.write("\n")

            # Comandos digitados
            if sess["commands"]:
                out.write("### 💻 Linha do Tempo de Comandos Digitados pelo Invasor\n")
                out.write("```bash\n")
                for cmd in sess["commands"]:
                    out.write(f"[{cmd['time']}] # {cmd['cmd']}\n")
                out.write("```\n\n")

            # Arquivos capturados
            if sess["files_downloaded"]:
                out.write("### 🚨 Amostras / Arquivos Capturados\n")
                for f in sess["files_downloaded"]:
                    out.write(f"- **SHA-256:** `{f['sha256']}` ({f['url']})\n")
                out.write("\n")

            out.write("---\n\n")


def generate_text_log(sessions, output_file):
    with open(output_file, "w", encoding="utf-8") as out:
        out.write("=" * 80 + "\n")
        out.write("   LOG LEGÍVEL DE ATIVIDADES MALICIOSAS - HONEYPOT COWRIE\n")
        out.write("=" * 80 + "\n\n")

        for sid, sess in sessions.items():
            ip = sess["ip"] or "Desconhecido"
            start = sess["start_time"]
            client = sess["client_version"] or "N/A"
            
            out.write(f"[{start}] [NOVA CONEXAO] IP: {ip} | Sessao: {sid} | Cliente: {client}\n")
            
            for log in sess["logins"]:
                out.write(f"[{log['time']}] [AUTENTICACAO] IP: {ip} | User: '{log['user']}' | Pass: '{log['password']}' | Status: {log['status']}\n")

            for cmd in sess["commands"]:
                out.write(f"[{cmd['time']}] [COMANDO DIGITADO] IP: {ip} | User: root | $ {cmd['cmd']}\n")

            for f in sess["files_downloaded"]:
                out.write(f"[{start}] [ARQUIVO CAPTURADO] IP: {ip} | SHA256: {f['sha256']}\n")

            if sess["duration_ms"]:
                out.write(f"[{sess['end_time']}] [DESCONEXAO] IP: {ip} | Duracao: {sess['duration_ms']}ms\n")

            out.write("-" * 80 + "\n")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "logs_salvos/year=2026/month=09/day=29/cowrie_20260929_204501.json"
    sessions = parse_cowrie_file(target)
    
    md_output = target.replace(".json", "_LEGIVEL.md")
    txt_output = target.replace(".json", "_LEGIVEL.txt")

    generate_markdown_report(sessions, target, md_output)
    generate_text_log(sessions, txt_output)

    print(f"[+] Arquivo legível Markdown gerado em: {md_output}")
    print(f"[+] Arquivo legível Syslog gerado em:   {txt_output}")
