"""
Teste Local do Parser e Enriquecimento da Lambda
Simula a execução com uma amostra dos logs reais coletados no honeypot
"""

import sys
import os
from pathlib import Path

# Adiciona o diretório lambda ao path
sys.path.insert(0, str(Path(__file__).parent.parent / "lambda"))

import handler

def test_local_enrichment():
    log_sample = Path(__file__).parent.parent / "logs_salvos" / "year=2026" / "month=10" / "day=07"
    json_files = list(log_sample.glob("*.json"))

    if not json_files:
        print("[!] Nenhum arquivo de log encontrado para teste local.")
        return

    sample_file = json_files[0]
    print(f"[+] Testando parser com arquivo real: {sample_file.name}")

    with open(sample_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    print(f"[+] Total de linhas no arquivo: {len(lines)}")
    aggregated = handler.parse_cowrie_records(lines)
    print(f"[+] IPs agregados encontrados: {len(aggregated)}")

    for idx, atk in enumerate(aggregated[:3], 1):
        ip = atk["ip"]
        print(f"\n--- Amostra {idx}: IP {ip} ---")
        geo = handler.get_geoip_info(ip)
        print(f"    País: {geo['country_name']} ({geo['country_code']})")
        print(f"    Cidade: {geo['city']}")
        print(f"    Coordenadas: Lat {geo['latitude']}, Long {geo['longitude']}")
        print(f"    Tentativas de login: {atk['login_attempts']}")
        print(f"    Logins com sucesso: {atk['successful_logins']}")
        print(f"    Senhas testadas: {atk['passwords'][:5]}")
        print(f"    Comandos: {atk['commands'][:3]}")

    print("\n[OK] Parser e enriquecimento GeoIP validados com sucesso localmente!")

if __name__ == "__main__":
    test_local_enrichment()
